// Copyright 2022 The SiliFuzz Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// TODO(ksteuck): [cleanup] Rename to reflect the actual contents of the file.
// Unfortunately, snapshot_types.h is already taken but maybe we can reconcile
// the two.
#ifndef THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_ENUMS_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_ENUMS_H_
// Defines enums used by Snapshot and its components so that we can use
// the enums in a nolibc environment. When built with full libc, we should
// include snapshot.h instead of using this directly.

#include <cstdint>
#include <limits>
#include <optional>

#include "absl/time/time.h"
#include "./util/itoa.h"
#include "./util/ucontext/signal.h"

namespace silifuzz {
namespace snapshot_types {
// TODO(ksteuck): [cleanup] Pull more reusable classes/structs/types from
// Snapshot and others to here.

// Type for a memory address (instructions or data inside a snapshot).
using Address = uint64_t;
inline constexpr Address kMinAddress = std::numeric_limits<Address>::min();
inline constexpr Address kMaxAddress = std::numeric_limits<Address>::max();

// Type for a size (a non-negative difference between two `Address`es).
using ByteSize = uint64_t;

// Supported architectures of snapshots.
// Note that enum values here match those in snapshot.proto;
// snapshot_proto.cc makes sure it's the case.
enum class Architecture {
  kUnsupported = 0,
  kX86_64 = 1,
  kAArch64 = 2,
};

// Type of an endpoint.
enum class EndpointType {
  kInstruction = 0,  // reaching of an instruction address
  kSignal,           // occurrence of a signal
};

// Supported signals that could be an endpoint.
// Note that enum values here match those in snapshot.proto;
// snapshot_proto.cc makes sure it's the case.
enum class SigNum : int {
  kSigSegv = 1,  // SIGSEGV
  kSigTrap = 2,  // SIGTRAP
  kSigFPE = 3,   // SIGFPE
  kSigIll = 4,   // SIGILL
  kSigBus = 5,   // SIGBUS
};

// A more specific cause of the signal.
// Note that enum values here match those in snapshot.proto;
// snapshot_proto.cc makes sure it's the case.
enum class SigCause : int {
  kGenericSigCause = 1,        // for kSigTrap, kSigFPE, kSigIll, or kSigBus
  kSegvCantExec = 2,           // for kSigSegv
  kSegvCantWrite = 3,          // for kSigSegv
  kSegvCantRead = 4,           // for kSigSegv
  kSegvOverflow = 5,           // for kSigSegv
  kSegvGeneralProtection = 6,  // for kSigSegv
};

// Describes an execution endpoint of a snapshot.
class Endpoint final {
 public:
  // EndpointType, SigNum and SigCause are definited in above. Here we just pass
  // through the enum values for compatibility with the existing code because
  // there is no other way to "import" the enum values into a class scope.
  // Refer to the corresponding type declarations for details.
  // TODO(ksteuck): [cleanup] Cleanup the usage of Endpoint::kSignal and others
  // so that we don't need to alias the enum values here.
  using Type = snapshot_types::EndpointType;
  using enum snapshot_types::EndpointType;

  using SigNum = snapshot_types::SigNum;
  using enum snapshot_types::SigNum;

  using SigCause = snapshot_types::SigCause;
  using enum snapshot_types::SigCause;

  // Enpoint that is the first occurrence of reaching the instruction_address.
  // I.e. type() == kInstruction.
  explicit Endpoint(Address instruction_address);

  // Endpoint that is the first occurrence of the given signal with the given
  // sig_cause, sig_address, and sig_instruction_address values.
  // I.e. type() == kSignal.
  Endpoint(SigNum sig_num, SigCause sig_cause, Address sig_address,
           Address sig_instruction_address);
  Endpoint(SigNum sig_num, Address sig_address, Address sig_instruction_address)
      : Endpoint(sig_num, kGenericSigCause, sig_address,
                 sig_instruction_address) {}

  // Intentionally movable and copyable.

  bool operator==(const Endpoint& y) const;
  bool operator!=(const Endpoint& y) const { return !(*this == y); }

  Type type() const { return type_; }

  // REQUIRES: type() == kInstruction.
  Address instruction_address() const;

  // REQUIRES: type() == kSignal (For all sig_*() functions.)
  SigNum sig_num() const;
  SigCause sig_cause() const;
  Address sig_address() const;
  Address sig_instruction_address() const;

 private:
  Type type_;

  // See 2nd c-tor.
  SigNum sig_num_;
  SigCause sig_cause_;
  Address sig_address_;

  // See either c-tor (holds sig_instruction_address() for kSignal).
  Address instruction_address_;
};

// Snapshot playback outcome code.
// Ordered from best to worst matching:
// We match endpoint(), registers(), and memory_bytes() in Snapshot::EndState
// in that order stopping on first mismatch at each of those three points.
enum PlaybackOutcome {
  // Playback matched one of Snapshot::expected_end_states() fully.
  // Or in the case of Snapshot::kUndefinedEndState snapshots,
  // this is set instead of kRegisterStateMismatch because there are
  // no expected Snapshot::EndState::registers() and no expected
  // Snapshot::EndState::memory_bytes().
  kAsExpected = 0,

  // Like kAsExpected except the current PlatformId is not among the ones
  // set in the end-state.
  kPlatformMismatch,

  // Playback matched one of Snapshot::expected_end_states()[i].endpoint()
  // and Snapshot::expected_end_states()[i].registers(),
  // but Snapshot::EndState::memory_bytes() in that end-state did not match.
  kMemoryMismatch,

  // Playback matched one of Snapshot::expected_end_states()[i].endpoint(),
  // but Snapshot::EndState::registers() in that end-state did not match.
  // In this case we do not bother to check Snapshot::EndState::memory_bytes()
  // matching, but Result::actual_end_state below will describe the actual
  // state of the memory.
  kRegisterStateMismatch,

  // Playback stopped but matched none of
  // Snapshot::expected_end_states()[i].endpoint().
  kEndpointMismatch,

  // Playback was a run-away (ran longer that the allotted budget).
  kExecutionRunaway,

  // Playback did not behave according to Snapshot's description.
  // E.g. snapshot execution touched memory outside of its
  // Snapshot::memory_mappings() or corrupted the harness.
  // No guarantee that we can always detect this scenario - a snapshot
  // preparation stage should normally ensure that this outcome never happens
  // by using silifuzz/transform/playback_verifier.h.
  kExecutionMisbehave,
};

// Snapshot playback result. EndStateT is the type of the EndState contained in
// this struct. In all cases this must be Snapshot::EndState. Unfortunately, due
// to the need to make this file nolibc-compatible we cannot specify the type
// directly.
template <typename EndStateT>
struct PlaybackResult {
  PlaybackOutcome outcome;

  // Index of the (partially) matched element of
  // Snapshot::expected_end_states().
  // Missing only for kEndpointMismatch, kExecutionRunaway,
  // or kExecutionMisbehave.
  std::optional<int> end_state_index;

  // Actual end-state reached.
  // Missing only for kAsExpected or kPlatformMismatch (and only for
  // Snapshot::kNormal snapshots)
  // -- because Snapshot::expected_end_states()[end_state_index] can be used
  // in that case.
  // Might be missing for kExecutionMisbehave.
  // For kExecutionRunaway this is just the arbitrary moment where we've
  // stopped the runaway execution.
  std::optional<EndStateT> actual_end_state;

  // CPU used playing the snapshot overestimated by the unavoidable
  // overheads like RestoreUContext() that we can't directly exclude from
  // the measurements.
  // Raw measurement gets corrected by PlayOptions::cpu_usage_baseline
  // given to Play().
  // Note that this can be negative if cpu_usage_baseline is inaccurate.
  absl::Duration cpu_usage;

  // Only present for kEndpointMismatch and kExecutionMisbehave when
  // actual_end_state.endpoint().type() == kSignal.
  std::optional<SignalRegSet> raw_signal_info;

  // CPU number where the snapshot ran.
  // See ExpectedExecutionResult in player_command_result.h for details
  int64_t cpu_id;
};

// The reason Make() stopped growing the snapshot.
enum class MakerStopReason {
  // Snapshot has reached an existing endpoint.
  kEndpoint = 0,

  // Snapshot cannot add new memory during because it has reached the
  // corresponding MakerOptions page limit or has no permission to add memory.
  kCannotAddMemory,

  // Snapshot has reached the specified PlayOptions::run_time_budget.
  kTimeBudget,

  // Snapshot has encountered a SIGSEGV that can't be fixed by adding
  // pages from SnapshotSource.
  kHardSigSegv,

  // Snapshot caused a general protection fault (X86Exceptions::X86_TRAP_GP)
  kGeneralProtectionSigSegv,

  // Snapshot caused a SIGTRAP.
  kSigTrap,

  // Other members of X86Exceptions:: are not listed here. They don't happen
  // often enough to special-case them and we let kSignal catch them.

  // Snapshot caused a signal that didn't fall into any of the more specific
  // buckets above (e.g. a SIGSEGV X86Exceptions::X86_TRAP_OF).
  kSignal,
};

}  // namespace snapshot_types

template <>
inline constexpr const char* EnumNameMap<snapshot_types::EndpointType>[2] = {
    "Instruction",
    "Signal",
};

template <>
inline constexpr const char* EnumNameMap<snapshot_types::SigNum>[6] = {
    "UNDEFINED_SIG_NUM",  //
    "SIG_SEGV",           //
    "SIG_TRAP",           //
    "SIG_FPE",            //
    "SIG_ILL",            //
    "SIG_BUS",            //
};

template <>
inline constexpr const char* EnumNameMap<snapshot_types::SigCause>[7] = {
    "UNDEFINED_SIG_CAUSE",      //
    "GENERIC_SIG_CAUSE",        //
    "SEGV_CANT_EXEC",           //
    "SEGV_CANT_WRITE",          //
    "SEGV_CANT_READ",           //
    "SEGV_OVERFLOW",            //
    "SEGV_GENERAL_PROTECTION",  //
};

template <>
inline constexpr const char* EnumNameMap<snapshot_types::MakerStopReason>[7] = {
    "Endpoint",                  //
    "CannotAddMemory",           //
    "TimeBudget",                //
    "HardSigSegv",               //
    "GeneralProtectionSigSegv",  //
    "SigTrap",                   //
    "Signal",                    //
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_ENUMS_H_
