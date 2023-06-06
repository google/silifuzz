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

#include "./common/snapshot.h"

#include <stddef.h>

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/mapped_memory_map.h"
#include "./util/checks.h"
#include "./util/platform.h"
#include "./util/ucontext/serialize.h"

namespace silifuzz {

template <>
ABSL_CONST_INIT const char* EnumNameMap<Snapshot::Metadata::Origin>[14] = {
    "kUndefined",  "UNKNOWN(1)",  "kIfuzz",      "kUnicorn",   "UNKNOWN(4)",
    "kBochs",      "kXed",        "kGem5",       "UNKNOWN(8)", "UNKNOWN(9)",
    "UNKNOWN(10)", "UNKNOWN(11)", "UNKNOWN(12)", "kUseString",
};

// Descriptor for an architecture for which we support snapshot data.
//
// Use silifuzz/tools/arch_info.cc to dump these values for the given
// architecture.
struct Snapshot::ArchitectureDescr {
  // Id of the architecture.
  Architecture id;

  // Descriptive and unique name of the architecture.
  const char* name;

  // getpagesize() - size of pages in the address space.
  int page_size;

  // See Snapshot::required_stack_size().
  int required_stack_size;

  // TODO(ksteuck): [as-needed]: Add a flag to indicate the direction of
  // stack growth.
};

// static
ABSL_CONST_INIT const Snapshot::ArchitectureDescr
    Snapshot::kSupportedArchitectures[] = {
        {
            .id = Snapshot::Architecture::kX86_64,
            .name = "x86_64",
            .page_size = 4096,
            // RestoreUContext() needs to push two registers onto the stack
            .required_stack_size = 8 * 2,
        },
        {
            .id = Snapshot::Architecture::kAArch64,
            .name = "aarch64",
            .page_size = 4096,
            // RestoreUContext() has a 32-byte stack frame
            .required_stack_size = 32,
        },
};

const Snapshot::Id& Snapshot::UnsetId() {
  static Id& unset_id = *(new std::string("has_not_been_set"));
  return unset_id;
}

absl::Status Snapshot::IsValidId(const Snapshot::Id& id) {
  if (id == Snapshot::UnsetId()) {
    return absl::OkStatus();
  }
  if (id.empty()) {
    return absl::InvalidArgumentError("Snapshot.id cannot be empty");
  }
  for (char c : id) {
    if (!absl::ascii_isalnum(c) && c != '_' && c != '-') {
      return absl::InvalidArgumentError(absl::StrCat(
          "[0x", absl::Hex(c), "] is not a valid Snapshot.id character"));
    }
  }
  return absl::OkStatus();
}

// static
Snapshot::Architecture Snapshot::CurrentArchitecture() {
  // TODO(ksteuck): [as-needed] Evolve as we add more architectures.
#if defined(__x86_64__)
  return Architecture::kX86_64;
#elif defined(__aarch64__)
  return Architecture::kAArch64;
#else
  return Architecture::kUnsupported;
#endif
}

absl::StatusOr<bool> Snapshot::IsExecutable(Address addr, ByteSize size) const {
  RETURN_IF_NOT_OK(MemoryMapping::CanMakeSized(addr, size));
  return mapped_memory_map_.Perms(addr, addr + size, MemoryPerms::kAnd)
      .Has(MemoryPerms::kExecutable);
}

// ----------------------------------------------------------------------- //

Snapshot::Snapshot(Architecture arch, const Id& id)
    : id_(id),
      architecture_(arch),
      architecture_descr_(nullptr),
      mapped_memory_map_(),
      negative_mapped_memory_map_(),
      written_memory_set_(),
      memory_mappings_(),
      negative_memory_mappings_(),
      memory_bytes_(),
      registers_(nullptr),
      expected_end_states_(),
      metadata_(new Metadata()),
      trace_metadata_() {
  DCHECK_STATUS(IsValidId(id_));
  for (const auto& arch : kSupportedArchitectures) {
    if (arch.id == architecture_) {
      architecture_descr_ = &arch;
      break;
    }
  }
  if (architecture_ == Architecture::kUnsupported ||
      architecture_descr_ == nullptr) {
    LOG_FATAL("Unsupported architecture: ", architecture_);
  }
}

// Quick O(n*m) comparison of two vectors as sets.
template <typename T>
bool VectorsEqualAsSet(const std::vector<T>& a, const std::vector<T>& b) {
  return a.size() == b.size() &&
         std::all_of(a.begin(), a.end(), [&b](const T& x) {
           return absl::c_find(b, x) != b.end();
         });
}

bool Snapshot::operator==(const Snapshot& y) const {
  bool expected_end_states_eq =
      VectorsEqualAsSet(expected_end_states_, y.expected_end_states_);
  bool metadata_eq = (metadata_ == nullptr && y.metadata_ == nullptr) ||
                     (metadata_ != nullptr && y.metadata_ != nullptr &&
                      *metadata_ == *y.metadata_);
  bool trace_metadata_eq =
      VectorsEqualAsSet(trace_metadata_, y.trace_metadata_);
  return EqualsButEndStates(y) &&
         negative_mapped_memory_map_ ==
             y.negative_mapped_memory_map_ &&  // covers
                                               // negative_memory_mappings_
         expected_end_states_eq &&
         metadata_eq && trace_metadata_eq;
}

bool Snapshot::EqualsButEndStates(const Snapshot& y) const {
  return id_ == y.id_ && architecture_ == y.architecture_ &&
         mapped_memory_map_ ==
             y.mapped_memory_map_ &&  // covers memory_mappings_
         MemoryBytesListEq(memory_bytes_,
                           y.memory_bytes_) &&  // covers written_memory_set_
         (registers_ == nullptr ? y.registers_ == nullptr
                                : *registers_ == *y.registers_);
}

Snapshot Snapshot::Copy() const {
  Snapshot r(architecture_, id_);
  r.mapped_memory_map_ = mapped_memory_map_.Copy();
  r.negative_mapped_memory_map_ = negative_mapped_memory_map_.Copy();
  r.written_memory_set_ = written_memory_set_;
  r.memory_mappings_ = memory_mappings_;
  r.negative_memory_mappings_ = negative_memory_mappings_;
  r.memory_bytes_ = memory_bytes_;
  if (registers_) {
    r.registers_.reset(new RegisterState(*registers_));
  }
  r.expected_end_states_ = expected_end_states_;
  r.metadata_.reset(new Metadata(*metadata_));
  r.trace_metadata_ = trace_metadata_;
  return r;
}

void Snapshot::Clear() { *this = Snapshot(architecture_); }

absl::Status Snapshot::IsComplete(State state) const {
  if (memory_mappings_.empty()) {
    return absl::InvalidArgumentError("No memory_mappings");
  }
  auto needs_negative_mapping_fn = [](const EndState& e) {
    const Endpoint& ep = e.endpoint();
    bool r = ep.type() == Endpoint::kSignal &&
             ep.sig_num() == Endpoint::kSigSegv &&
             (ep.sig_cause() == Endpoint::kSegvCantRead ||
              ep.sig_cause() == Endpoint::kSegvCantWrite ||
              ep.sig_cause() == Endpoint::kSegvCantExec);
    return r;
  };
  bool needs_negative_mapping =
      std::any_of(expected_end_states_.begin(), expected_end_states_.end(),
                  needs_negative_mapping_fn);
  bool has_negative_mappings = !negative_memory_mappings_.empty();
  if (needs_negative_mapping && !has_negative_mappings) {
    return absl::InvalidArgumentError(
        absl::StrCat("Missing negative_memory_mappings"));
  }
  if (!needs_negative_mapping && has_negative_mappings) {
    std::string details = "Unnecessary negative_memory_mappings";
    if (DEBUG_MODE) {
      absl::StrAppend(&details, ": ",
                      negative_mapped_memory_map().DebugString());
    }
    return absl::InvalidArgumentError(details);
  }
  if (memory_bytes_.empty()) {
    return absl::InvalidArgumentError("No memory_bytes");
  }
  if (!has_registers()) {
    return absl::InvalidArgumentError("No registers");
  }
  if (expected_end_states_.empty() && state == kNormalState) {
    return absl::InvalidArgumentError("No expected_end_states");
  }
  for (int i = 0; i < expected_end_states_.size(); ++i) {
    const auto& s = expected_end_states_[i];
    RETURN_IF_NOT_OK_PLUS(s.IsComplete(state),
                          absl::StrCat("In end-state ", i, ": "));
    if (state != kMakingState) {
      // Verify that we do have the memory mapped for all endpoints
      // (caller of public Snapshot API can supply true for unmapped_endpoint_ok
      // when adding an end-state):
      RETURN_IF_NOT_OK_PLUS(
          can_add_expected_end_state(s, false /* unmapped_endpoint_ok */,
                                     true /* duplicate_ok */),
          absl::StrCat("In end-state ", i, ": "));
    }
  }
  return absl::OkStatus();
}

absl::Status Snapshot::IsCompleteSomeState() const {
  if (IsComplete(kNormalState).ok()) return absl::OkStatus();
  if (IsComplete(kUndefinedEndState).ok()) return absl::OkStatus();
  return IsComplete(kMakingState);
}

absl::string_view Snapshot::architecture_name() const {
  return architecture_descr_->name;
}

Snapshot::ByteSize Snapshot::page_size() const {
  return architecture_descr_->page_size;
}

Snapshot::ByteSize Snapshot::required_stack_size() const {
  return architecture_descr_->required_stack_size;
}

// ----------------------------------------------------------------------- //

const Snapshot::MemoryMappingList& Snapshot::memory_mappings() const {
  return memory_mappings_;
}

absl::Status Snapshot::can_add_memory_mapping(const MemoryMapping& x) const {
  if (x.perms().IsEmpty()) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "Has empty perms");
  }
  if (x.start_address() == x.limit_address()) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "Is empty");
  }
  if (x.start_address() % page_size() != 0 ||
      x.limit_address() % page_size() != 0) {
    return absl::InvalidArgumentError(
        absl::StrCat("Is not page-aligned: ", HexStr(x.start_address()), "..",
                     HexStr(x.limit_address())));
  }
  if (mapped_memory_map_.Overlaps(x.start_address(), x.limit_address())) {
    return absl::InvalidArgumentError("Overlaps with existing memory_mappings");
  }
  if (x.perms().HasSomeOf(negative_mapped_memory_map_.Perms(
          x.start_address(), x.limit_address(), MemoryPerms::kOr))) {
    return absl::InvalidArgumentError(
        "Conflicts with existing negative_memory_mappings");
  }
  return absl::OkStatus();
}

void Snapshot::add_memory_mapping(const MemoryMapping& x) {
  DCHECK_STATUS(can_add_memory_mapping(x));
  mapped_memory_map_.AddNew(x.start_address(), x.limit_address(), x.perms());
  memory_mappings_.push_back(x);
}

void Snapshot::set_memory_mapping_perms(const MemoryMapping& x,
                                        int memory_mappings_index) {
  DCHECK(!x.perms().IsEmpty());
  DCHECK(0 <= memory_mappings_index &&
         memory_mappings_index < memory_mappings_.size());
  auto& m = memory_mappings_[memory_mappings_index];
  DCHECK(m.start_address() == x.start_address() &&
         m.limit_address() == x.limit_address());
  m = x;
  mapped_memory_map_.Set(x.start_address(), x.limit_address(), x.perms());
}

absl::Status Snapshot::can_set_memory_mappings(
    const MemoryMappingList& x) const {
  // Check that we can rebuild the snapshot with `x`
  // instead of memory_mappings():
  Snapshot copy(architecture(), id());
  for (const auto& m : x) {
    RETURN_IF_NOT_OK(copy.can_add_memory_mapping(m));
    copy.add_memory_mapping(m);
  }
  for (const auto& m : negative_memory_mappings()) {
    RETURN_IF_NOT_OK(copy.can_add_negative_memory_mapping(m));
    copy.add_negative_memory_mapping(m);
  }
  for (const auto& b : memory_bytes()) {
    RETURN_IF_NOT_OK(copy.can_add_memory_bytes(b));
    copy.add_memory_bytes(b);
  }
  if (has_registers()) {
    RETURN_IF_NOT_OK(copy.can_set_registers(registers()));
    copy.set_registers(registers());
  }
  for (const auto& e : expected_end_states()) {
    RETURN_IF_NOT_OK(copy.can_add_expected_end_state(e));
    copy.add_expected_end_state(e);
  }
  return absl::OkStatus();
}

void Snapshot::set_memory_mappings(const MemoryMappingList& x) {
  DCHECK_STATUS(can_set_memory_mappings(x));
  mapped_memory_map_.Clear();
  for (const auto& m : x) {
    mapped_memory_map_.AddNew(m.start_address(), m.limit_address(), m.perms());
  }
  memory_mappings_ = x;
}

const std::vector<Snapshot::MemoryMapping>& Snapshot::negative_memory_mappings()
    const {
  return negative_memory_mappings_;
}

absl::Status Snapshot::can_add_negative_memory_mapping(
    const MemoryMapping& x) const {
  return can_add_negative_memory_mapping(x, false);
}

absl::Status Snapshot::can_add_negative_memory_mapping(const MemoryMapping& x,
                                                       bool overlap_ok) const {
  if (x.perms().IsEmpty()) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "Has empty perms");
  }
  if (x.start_address() == x.limit_address()) {
    return absl::Status(absl::StatusCode::kInvalidArgument, "Is empty");
  }
  if (x.start_address() % page_size() != 0 ||
      (x.limit_address() % page_size() != 0 &&
       // Special-case when the very last page is negatively mapped:
       x.limit_address() != kMaxAddress)) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Negative is not page-aligned: ", HexStr(x.start_address()), "..",
        HexStr(x.limit_address())));
  }
  if (!overlap_ok && negative_mapped_memory_map_.Overlaps(x.start_address(),
                                                          x.limit_address())) {
    return absl::InvalidArgumentError(
        "Overlaps with existing negative_memory_mappings");
  }
  if (x.perms().HasSomeOf(mapped_memory_map_.Perms(
          x.start_address(), x.limit_address(), MemoryPerms::kOr))) {
    return absl::InvalidArgumentError(
        "Conflicts with existing memory_mappings");
  }
  return absl::OkStatus();
}

void Snapshot::add_negative_memory_mapping(const MemoryMapping& x) {
  DCHECK_STATUS(can_add_negative_memory_mapping(x));
  negative_mapped_memory_map_.AddNew(x.start_address(), x.limit_address(),
                                     x.perms());
  negative_memory_mappings_.push_back(x);
}

void Snapshot::add_negative_memory_mapping_overlap_ok(const MemoryMapping& x) {
  DCHECK_STATUS(can_add_negative_memory_mapping(x, true));
  if (negative_mapped_memory_map_.Overlaps(x.start_address(),
                                           x.limit_address())) {
    negative_mapped_memory_map_.Add(x.start_address(), x.limit_address(),
                                    x.perms());
    negative_memory_mappings_.clear();
    negative_mapped_memory_map_.Iterate(
        [&](Address start, Address limit, MemoryPerms perms) {
          negative_memory_mappings_.emplace_back(
              MemoryMapping::MakeRanged(start, limit, perms));
        });
  } else {
    // This clause is just an optimization wrt the other more general one.
    negative_mapped_memory_map_.AddNew(x.start_address(), x.limit_address(),
                                       x.perms());
    negative_memory_mappings_.push_back(x);
  }
}

void Snapshot::set_negative_memory_mappings(const MemoryMappingList& xs) {
  negative_mapped_memory_map_.Clear();
  negative_memory_mappings_.clear();
  for (auto& x : xs) {
    add_negative_memory_mapping(x);
  }
}

absl::Status Snapshot::AddNegativeMemoryMappingsFor(const EndState& x) {
  const auto& endpoint = x.endpoint();
  if (endpoint.type() == Endpoint::kSignal &&
      endpoint.sig_num() == Endpoint::kSigSegv) {
    MemoryPerms negative_perms;
    switch (endpoint.sig_cause()) {
      case Endpoint::kSegvGeneralProtection:
      case Endpoint::kSegvOverflow:
        return absl::OkStatus();
      case Endpoint::kSegvCantExec:
        negative_perms.Add(MemoryPerms::kExecutable);
        break;
      case Endpoint::kSegvCantWrite:
        negative_perms.Add(MemoryPerms::kWritable);
        break;
      case Endpoint::kSegvCantRead:
        negative_perms.Add(MemoryPerms::kReadable);
        break;
      case Endpoint::kGenericSigCause:
        LOG_FATAL("unreachable");
    }
    switch (architecture()) {
      case Architecture::kAArch64:
        // Default to X86_64 behavior - it may not be necessary, but it should
        // be safe.
        // TODO(ncbray): should we be more precise with aarch64?
      case Architecture::kX86_64:
        if (endpoint.sig_cause() == Endpoint::kSegvCantRead) {
          // On x86_64 PROT_EXEC and PROT_WRITE each imply PROT_READ
          // (see silifuzz/tools/mem_perms_testing.cc),
          // hence we disable them too (negative_perms will go into
          // negative_memory_mappings_ below:
          negative_perms.Add(MemoryPerms::kExecutable);
          negative_perms.Add(MemoryPerms::kWritable);
        }
        break;
      default:
        LOG_FATAL("Implement proper fixups if any");
        // after doing silifuzz/tools/mem_perms_testing.cc for the architecture
    }
    // When the very last page needs to be negatively mapped, we special case it
    // by excluding kMaxAddress itself, so that we don't need to complicate
    // things in MappedMemoryMap and represent limit range values that equal to
    // kMaxAddress+1, which is not directly representable by the Address type.
    // We are not going to need to put the last page into the positive
    // memory_mappings_.
    bool is_last_page = endpoint.sig_address() >= kMaxAddress - page_size() + 1;
    Address page = endpoint.sig_address() / page_size();
    Address start = page * page_size();
    ByteSize size = is_last_page ? (page_size() - 1) : page_size();
    RETURN_IF_NOT_OK(MemoryMapping::CanMakeSized(start, size));
    auto m = MemoryMapping::MakeSized(start, size, negative_perms);
    RETURN_IF_NOT_OK(can_add_negative_memory_mapping(m, true /* overlap_ok */));
    add_negative_memory_mapping_overlap_ok(m);
  }
  return absl::OkStatus();
}

const std::vector<Snapshot::MemoryBytes>& Snapshot::memory_bytes() const {
  return memory_bytes_;
}

absl::Status Snapshot::can_add_memory_bytes(const MemoryBytes& x) const {
  if (!mapped_memory_map_.Contains(x.start_address(), x.limit_address())) {
    return absl::InvalidArgumentError(
        "Not fully contained in existing memory_mappings");
  }
  if (!written_memory_set_.IsDisjoint(x.start_address(), x.limit_address())) {
    return absl::InvalidArgumentError("Overlaps with existing memory_bytes");
  }
  return absl::OkStatus();
}

void Snapshot::add_memory_bytes(const MemoryBytes& x) {
  MemoryBytes copy(x);
  add_memory_bytes(std::move(copy));
}

void Snapshot::add_memory_bytes(MemoryBytes&& x) {
  DCHECK_STATUS(can_add_memory_bytes(x));
  written_memory_set_.Add(x.start_address(), x.limit_address());
  memory_bytes_.emplace_back(std::move(x));
}

absl::Status Snapshot::ReplaceMemoryBytes(MemoryBytesList&& xs) {
  written_memory_set_.clear();
  memory_bytes_.clear();
  for (auto&& x : xs) {
    RETURN_IF_NOT_OK(can_add_memory_bytes(x));
    add_memory_bytes(x);
  }
  return absl::OkStatus();
}

bool Snapshot::MappedMemoryIsDefined() const {
  auto copy = mapped_memory_map_.Copy();
  for (const auto& b : memory_bytes_) {
    copy.Remove(b.start_address(), b.limit_address());
  }
  return copy.IsEmpty();
}

bool Snapshot::has_registers() const { return registers_ != nullptr; }

void Snapshot::set_id(const Id& id) {
  DCHECK_STATUS(IsValidId(id));
  id_ = id;
}

const Snapshot::RegisterState& Snapshot::registers() const {
  DCHECK(has_registers());
  return *registers_;
}

template <typename Arch>
absl::Status Snapshot::can_set_registers_impl(const Snapshot::RegisterState& x,
                                              bool is_end_state) const {
  GRegSet<Arch> gregs;
  FPRegSet<Arch> fpregs;
  // It would be cleaner to use ConvertRegsFromSnapshot, but this would cause
  // a cycle in the dependency graph. Instead, we inline.
  // TODO(ncbray) relayer the snapshot libraries.
  if (!DeserializeGRegs(x.gregs(), &gregs)) {
    return absl::InvalidArgumentError("Failed to deserialize gregs");
  }
  if (!DeserializeFPRegs(x.fpregs(), &fpregs)) {
    return absl::InvalidArgumentError("Failed to deserialize fpregs");
  }

  // For EndState rsp and rip can be anything: their values going outside of the
  // mapped memory might be the reason for the SIGSEGV that is the end-state.
  if (is_end_state) return absl::OkStatus();
  Address instruction_pointer = gregs.GetInstructionPointer();
  absl::StatusOr<bool> s = IsExecutable(instruction_pointer, 1);
  RETURN_IF_NOT_OK(s.status());
  if (!*s) {
    return absl::InvalidArgumentError(
        absl::StrCat("instruction pointer (0x", absl::Hex(instruction_pointer),
                     ") is not in an existing executable MemoryMapping"));
  }
  Address stack_pointer = gregs.GetStackPointer();
  auto stack_bytes = required_stack_size();
  if (stack_pointer < stack_bytes ||
      mapped_memory_map_
          .Perms(stack_pointer - stack_bytes, stack_pointer, MemoryPerms::kAnd)
          .HasNo(MemoryPerms::kWritable)) {
    return absl::InvalidArgumentError(absl::StrCat(
        "stack pointer (0x", absl::Hex(stack_pointer), ") and ", stack_bytes,
        " bytes before it must be within a writable MemoryMapping"));
  }
  return absl::OkStatus();
}

absl::Status Snapshot::can_set_registers(const RegisterState& x,
                                         bool is_end_state) const {
  return ARCH_DISPATCH(can_set_registers_impl, architecture_id(), x,
                       is_end_state);
}

template <typename Arch>
bool Snapshot::registers_match_arch_impl(
    const Snapshot::RegisterState& x) const {
  return MayBeSerializedGRegs<Arch>(x.gregs()) &&
         MayBeSerializedFPRegs<Arch>(x.fpregs());
}

// Check that the RegisterState matches the architecture of the Snapshot.
bool Snapshot::registers_match_arch(const Snapshot::RegisterState& x) const {
  return ARCH_DISPATCH(registers_match_arch_impl, architecture_id(), x);
}

void Snapshot::set_registers(const RegisterState& x) {
  // registers_match_arch should always be true if can_set_registers is true,
  // but it's lighter weight so we can run it all the time.
  CHECK(registers_match_arch(x));
  DCHECK_STATUS(can_set_registers(x, false /* is_end_state */));
  registers_.reset(new RegisterState(x));
}

const std::vector<Snapshot::EndState>& Snapshot::expected_end_states() const {
  return expected_end_states_;
}

absl::Status Snapshot::can_add_expected_end_state(
    const EndState& x, bool unmapped_endpoint_ok) const {
  return can_add_expected_end_state(x, unmapped_endpoint_ok,
                                    false /* duplicate_ok */);
}

absl::Status Snapshot::can_add_expected_end_state(const EndState& x,
                                                  bool unmapped_endpoint_ok,
                                                  bool duplicate_ok) const {
  switch (x.endpoint().type()) {
    case Endpoint::kInstruction: {
      // Make sure there is at least some executable memory after the endpoint.
      // Note this is a weak check because it doesn't guarentee we can add a
      // full exit sequence.
      auto s = IsExecutable(x.endpoint().instruction_address(), 1);
      RETURN_IF_NOT_OK(s.status());
      if (!unmapped_endpoint_ok && !*s) {
        return absl::InvalidArgumentError(
            absl::StrCat("endpoint instruction_address 0x",
                         absl::Hex(x.endpoint().instruction_address()),
                         " is not in an existing executable MemoryMapping"));
      }
      break;
    }
    case Endpoint::kSignal:
      bool is_segv = x.endpoint().sig_num() == Endpoint::kSigSegv;
      // The mappings for sig_address and sig_instruction_address might have
      // empty permissions, but they need to exist. For SEGV we check both
      // mapped_memory_map_ and negative_mapped_memory_map_.
      if (Address sig_address = x.endpoint().sig_address(); sig_address != 0) {
        bool has_mapping = mapped_memory_map_.Contains(sig_address);
        bool has_negative_mapping =
            is_segv &&
            (negative_mapped_memory_map_.Contains(sig_address)
             // Special-case to support kMaxAddress values -- see comments
             // for negative_memory_mappings() and inside of
             // AddNegativeMemoryMappingsFor().
             || (sig_address == kMaxAddress &&
                 negative_mapped_memory_map_.Contains(kMaxAddress - 1)));
        if (!has_mapping && !has_negative_mapping) {
          return absl::InvalidArgumentError(
              absl::StrCat("sig_address 0x", absl::Hex(sig_address),
                           " is not in an existing MemoryMapping"));
        }
      }
      Address sig_instruction_address = x.endpoint().sig_instruction_address();
      bool has_mapping = mapped_memory_map_.Contains(sig_instruction_address);
      bool has_negative_mapping =
          is_segv &&
          (negative_mapped_memory_map_.Contains(sig_instruction_address)
           // Special-case to support kMaxAddress values -- same as above.
           || (sig_instruction_address == kMaxAddress &&
               negative_mapped_memory_map_.Contains(kMaxAddress - 1)));
      if (!unmapped_endpoint_ok && !has_mapping && !has_negative_mapping) {
        return absl::InvalidArgumentError(absl::StrCat(
            "signal instruction address 0x", absl::Hex(sig_instruction_address),
            " is not in an existing MemoryMapping"));
      }
      break;
  }
  if (x.registers().gregs().empty() && x.registers().fpregs().empty()) {
    // Special case of EndState being undetermined yet.
    if (!x.memory_bytes().empty()) {
      return absl::InvalidArgumentError(
          "memory_bytes must be empty if registers are");
    }
  } else {
    RETURN_IF_NOT_OK_PLUS(
        can_set_registers(x.registers(), true /* is_end_state */),
        "Bad RegisterState: ");
  }
  for (const auto& r : x.memory_bytes()) {
    if (mapped_memory_map_
            .Perms(r.start_address(), r.limit_address(), MemoryPerms::kAnd)
            .HasNo(MemoryPerms::kWritable)) {
      return absl::InvalidArgumentError(
          absl::StrCat("memory_bytes at [", HexStr(r.start_address()), "; ",
                       HexStr(r.limit_address()),
                       ") is not in an existing writable MemoryMapping"));
    }
  }
  // TODO(dougkwan): verify register checksum is okay.
  if (!duplicate_ok) {
    for (int i = 0; i < expected_end_states_.size(); ++i) {
      if (x.DataEquals(expected_end_states_[i])) {
        return absl::InvalidArgumentError(
            absl::StrCat("Is a dup of ", i, "-th existing EndState"));
      }
    }
  }
  return absl::OkStatus();
}

void Snapshot::add_expected_end_state(const EndState& x,
                                      bool unmapped_endpoint_ok) {
  DCHECK_STATUS(can_add_expected_end_state(x, unmapped_endpoint_ok));
  EndState copy(x);
  expected_end_states_.emplace_back(std::move(copy));
}

void Snapshot::add_platform_to_expected_end_state(int i, PlatformId platform) {
  expected_end_states_[i].add_platform(platform);
}

void Snapshot::add_platforms_to_expected_end_state(int i, const EndState& x) {
  auto& s = expected_end_states_[i];
  DCHECK(s.DataEquals(x));
  for (int p = 0; p < s.platforms_.size(); ++p) {
    if (x.platforms_[p]) s.platforms_[p] = true;
  }
}

void Snapshot::set_expected_end_states(const EndStateList& xs) {
  expected_end_states_.clear();
  for (auto& x : xs) {
    add_expected_end_state(x);
  }
}

void Snapshot::remove_expected_end_state(const EndState* x) {
  for (auto it = expected_end_states_.begin(); it != expected_end_states_.end();
       ++it) {
    if (&(*it) == x) {
      expected_end_states_.erase(it);
      return;
    }
  }
  LOG_DFATAL("Given EndState not present");
}

// ----------------------------------------------------------------------- //

// static
Snapshot::MemoryMappingList Snapshot::SortedMemoryMappingList(
    const MappedMemoryMap& memory_map) {
  MemoryMappingList memory_mappings;
  memory_map.Iterate([&memory_mappings](Address start, Address limit,
                                        MemoryPerms perms) {
    memory_mappings.push_back(MemoryMapping::MakeRanged(start, limit, perms));
  });
  return memory_mappings;
}

void Snapshot::NormalizeMemoryMappings() {
  memory_mappings_ = SortedMemoryMappingList(mapped_memory_map_);
  negative_memory_mappings_ =
      SortedMemoryMappingList(negative_mapped_memory_map_);
}

void Snapshot::NormalizeMemoryBytes() {
  NormalizeMemoryBytes(mapped_memory_map_, &memory_bytes_);
  for (auto& es : expected_end_states_) {
    NormalizeMemoryBytes(mapped_memory_map_, &es.memory_bytes_);
  }
}

// static
void Snapshot::NormalizeMemoryBytes(const MappedMemoryMap& memory_map,
                                    MemoryBytesList* memory_bytes) {
  MemoryBytesList old_memory_bytes;
  old_memory_bytes.swap(*memory_bytes);
  sort(old_memory_bytes.begin(), old_memory_bytes.end());

  // If allow_mixed_permission is false, we need to break up existing
  // memory bytes at permissions boundaries. We do this with nested loops.
  // The outer loop iterates over the sorted MemoryBytes. The inner loop
  // iterates overs all memory mappings that overlap with a MemoryBytes,
  // breaking up the MemoryBytes at permissions boundaries. This is done
  // so that all bytes in a MemoryBytes have identical memory permissions.
  // The adjacent MemoryBytes are then merged depending on their permissions
  // and whether mixed permissions are allowed, which is now allowed in Snap.
  // Memory permissions are stored in Snap::MemoryBytes directly, thus
  // the breaking at permissions boundary.
  MemoryPerms perms;  // perms of memory_bytes.back().
  for (auto& b : old_memory_bytes) {
    // As an optimization, memory bytes not split are simply moved to
    // the new memory byte list. Wrap it with a std::optional as it may
    // be erased by moving.
    std::optional<MemoryBytes> old_memory_bytes = std::move(b);

    // old_memory_bytes may be erased by std::move(). Copy these addresses for
    // later use.
    const Address old_memory_bytes_start = old_memory_bytes->start_address();
    const Address old_memory_bytes_limit = old_memory_bytes->limit_address();

    // memory bytes may span across multiple memory mappings. Iterate over
    // mappings in the address range of memory bytes and split memory bytes
    // if necessary.
    Address current_chunk_start = old_memory_bytes_start;
    while (current_chunk_start < old_memory_bytes_limit) {
      std::optional<MemoryMapping> memory_mapping =
          memory_map.MappingAt(current_chunk_start);
      CHECK(memory_mapping.has_value());
      const Address current_chunk_limit =
          std::min(old_memory_bytes_limit, memory_mapping->limit_address());

      // If we reach the end of old memory bytes, just do a move.
      MemoryBytes current_chunk =
          (current_chunk_start == old_memory_bytes_start &&
           current_chunk_limit == old_memory_bytes_limit)
              ? std::move(old_memory_bytes.value())
              : old_memory_bytes->Range(current_chunk_start,
                                        current_chunk_limit);

      // Merge chunk if mixed permissions setting allows us.
      if (!memory_bytes->empty() &&
          current_chunk.start_address() ==
              memory_bytes->back().limit_address() &&
          memory_mapping->perms() == perms) {
        memory_bytes->back().mutable_byte_values()->append(
            current_chunk.byte_values());
      } else {
        perms = memory_mapping->perms();
        memory_bytes->emplace_back(std::move(current_chunk));
      }

      // Advance chunk start.
      current_chunk_start = current_chunk_limit;
    }
  }
}

void Snapshot::NormalizeAll() {
  NormalizeMemoryMappings();
  NormalizeMemoryBytes();
}

bool Snapshot::TryRemoveUndefinedEndStates() {
  auto& states = expected_end_states_;
  auto before_size = states.size();
  if (std::find_if(states.begin(), states.end(), [](const EndState& x) {
        return x.IsComplete(Snapshot::kNormalState).ok();
      }) != states.end()) {
    states.erase(
        std::remove_if(states.begin(), states.end(),
                       [](const EndState& x) {
                         return x.IsComplete(Snapshot::kUndefinedEndState).ok();
                       }),
        states.end());
  }
  return before_size != states.size();
}

// ----------------------------------------------------------------------- //

template <typename Arch>
Snapshot::Address Snapshot::ExtractRipImpl(const RegisterState& x) const {
  if (x.gregs().empty()) {
    return kUnsetRegisterValue;
  }
  GRegSet<Arch> gregs;
  CHECK(DeserializeGRegs(x.gregs(), &gregs));
  return gregs.GetInstructionPointer();
}

Snapshot::Address Snapshot::ExtractRip(const RegisterState& x) const {
  return ARCH_DISPATCH(ExtractRipImpl, architecture_id(), x);
}

template <typename Arch>
Snapshot::Address Snapshot::ExtractRspImpl(const RegisterState& x) const {
  if (x.gregs().empty()) {
    return kUnsetRegisterValue;
  }
  GRegSet<Arch> gregs;
  CHECK(DeserializeGRegs(x.gregs(), &gregs));
  return gregs.GetStackPointer();
}

Snapshot::Address Snapshot::ExtractRsp(const RegisterState& x) const {
  return ARCH_DISPATCH(ExtractRspImpl, architecture_id(), x);
}

int Snapshot::num_pages() const {
  int r = 0;
  for (const auto& m : memory_mappings_) {
    r += m.num_bytes();
  }
  DCHECK_EQ(r % page_size(), 0);
  return r / page_size();
}

const MappedMemoryMap& Snapshot::mapped_memory_map() const {
  return mapped_memory_map_;
}

const MappedMemoryMap& Snapshot::negative_mapped_memory_map() const {
  return negative_mapped_memory_map_;
}

bool Snapshot::some_has_platform(PlatformId platform) const {
  return std::any_of(
      expected_end_states_.begin(), expected_end_states_.end(),
      [platform](const EndState& x) { return x.has_platform(platform); });
}

const Snapshot::MemoryBytesSet& Snapshot::written_memory_set() const {
  return written_memory_set_;
}

MemoryPerms Snapshot::PermsAt(Address address) const {
  return mapped_memory_map_.PermsAt(address);
}

MemoryPerms Snapshot::Perms(Address start_address, Address limit_address,
                            MemoryPerms::JoinMode mode) const {
  return mapped_memory_map_.Perms(start_address, limit_address, mode);
}

// static
bool Snapshot::MemoryBytesListEq(const MemoryBytesList& x,
                                 const MemoryBytesList& y) {
  if (x.size() != y.size()) return false;
  std::vector<const MemoryBytes*> xs;
  std::vector<const MemoryBytes*> ys;
  for (const auto& e : x) xs.push_back(&e);
  for (const auto& e : y) ys.push_back(&e);
  auto less = [](const MemoryBytes* a, const MemoryBytes* b) {
    return *a < *b;
  };
  sort(xs.begin(), xs.end(), less);
  sort(ys.begin(), ys.end(), less);
  for (int i = 0; i < xs.size(); ++i) {
    if (*xs[i] != *ys[i]) return false;
  }
  return true;
}

// ========================================================================= //

// static
absl::Status Snapshot::MemoryBytes::CanConstruct(Address start_address,
                                                 const ByteData& byte_values) {
  if (byte_values.empty()) {
    return absl::InvalidArgumentError("Empty byte_values");
  }
  if (kMaxAddress - byte_values.size() < start_address) {
    return absl::InvalidArgumentError(
        "start_address + byte_values.size is too large");
  }
  return absl::OkStatus();
}

Snapshot::MemoryBytes::MemoryBytes(Address start_address,
                                   const ByteData& byte_values)
    : start_address_(start_address), byte_values_(byte_values) {
  DCHECK_STATUS(CanConstruct(start_address_, byte_values_));
}

Snapshot::MemoryBytes::MemoryBytes(Address start_address,
                                   ByteData&& byte_values)
    : start_address_(start_address), byte_values_(std::move(byte_values)) {
  DCHECK_STATUS(CanConstruct(start_address_, byte_values_));
}

bool Snapshot::MemoryBytes::operator==(const MemoryBytes& y) const {
  return start_address_ == y.start_address_ && byte_values_ == y.byte_values_;
}

bool Snapshot::MemoryBytes::operator<(const MemoryBytes& y) const {
  return start_address_ < y.start_address_ ||
         (start_address_ == y.start_address_ &&
          limit_address() < y.limit_address());
}

Snapshot::MemoryBytes Snapshot::MemoryBytes::Range(Address start,
                                                   Address limit) {
  CHECK_GE(start, start_address_);
  CHECK_LE(limit, limit_address());
  const size_t offset = start - start_address_;
  const size_t length = limit - start;
  return MemoryBytes(start, byte_values_.substr(offset, length));
}

std::string Snapshot::MemoryBytes::DebugString() const {
  return absl::StrCat(HexStr(start_address()), "..", HexStr(limit_address()),
                      " : ", absl::CHexEscape(byte_values()));
}

// ========================================================================= //

Snapshot::RegisterState::RegisterState(const ByteData& gregs,
                                       const ByteData& fpregs)
    : gregs_(gregs), fpregs_(fpregs) {}

bool Snapshot::RegisterState::operator==(const RegisterState& y) const {
  return gregs_ == y.gregs_ && fpregs_ == y.fpregs_;
}

// ========================================================================= //

Snapshot::EndState::EndState(const Endpoint& endpoint,
                             const RegisterState& registers)
    : changed_memory_set_(),
      endpoint_(endpoint),
      registers_(registers),
      memory_bytes_(),
      platforms_(ToInt(kMaxPlatformId) + 1, false),
      register_checksum_() {}

bool Snapshot::EndState::operator==(const EndState& y) const {
  return DataEquals(y) && platforms_ == y.platforms_;
}

bool Snapshot::EndState::DataEquals(const EndState& y) const {
  return endpoint_ == y.endpoint_ && registers_ == y.registers_ &&
         register_checksum_ == y.register_checksum_ &&
         MemoryBytesListEq(memory_bytes_,
                           y.memory_bytes_);  // covers changed_memory_set_
}

absl::Status Snapshot::EndState::IsComplete(State state) const {
  switch (state) {
    case kUndefinedEndState:
    case kMakingState:
      if (!registers().gregs().empty() || !registers().fpregs().empty()) {
        return absl::InvalidArgumentError("Non empty registers in EndState");
      }
      if (!memory_bytes().empty()) {
        return absl::InvalidArgumentError("Non empty memory_bytes in EndState");
      }
      if (!empty_platforms()) {
        return absl::InvalidArgumentError("Non empty platforms in an EndState");
      }
      break;
    case kNormalState:
      if (registers().gregs().empty() || registers().fpregs().empty()) {
        return absl::InvalidArgumentError("Empty registers in an EndState");
      }
      if (empty_platforms()) {
        return absl::InvalidArgumentError("Empty platforms in an EndState");
      }
      break;
  }
  return absl::OkStatus();
}

const Snapshot::MemoryBytesSet& Snapshot::EndState::changed_memory_set() const {
  return changed_memory_set_;
}

absl::Status Snapshot::EndState::can_add_memory_bytes(
    const MemoryBytes& x) const {
  if (!changed_memory_set_.IsDisjoint(x.start_address(), x.limit_address())) {
    return absl::InvalidArgumentError("Overlaps with existing memory_bytes");
  }
  return absl::OkStatus();
}

void Snapshot::EndState::add_memory_bytes(const MemoryBytes& x) {
  MemoryBytes copy(x);
  add_memory_bytes(std::move(copy));
}

void Snapshot::EndState::add_memory_bytes(MemoryBytes&& x) {
  DCHECK_STATUS(can_add_memory_bytes(x));
  changed_memory_set_.Add(x.start_address(), x.limit_address());
  memory_bytes_.emplace_back(std::move(x));
}

void Snapshot::EndState::add_memory_bytes(const MemoryBytesList& xs) {
  for (const MemoryBytes& x : xs) {
    add_memory_bytes(x);
  }
}

void Snapshot::EndState::add_memory_bytes(MemoryBytesList&& xs) {
  for (MemoryBytes& x : xs) {
    add_memory_bytes(std::move(x));
  }
}

absl::Status Snapshot::EndState::ReplaceMemoryBytes(MemoryBytesList&& xs) {
  changed_memory_set_.clear();
  memory_bytes_.clear();
  for (auto&& x : xs) {
    RETURN_IF_NOT_OK(can_add_memory_bytes(x));
    add_memory_bytes(x);
  }
  return absl::OkStatus();
}

bool Snapshot::EndState::has_platform(PlatformId platform) const {
  return platforms_[ToInt(platform)];
}

bool Snapshot::EndState::empty_platforms() const {
  return std::none_of(platforms_.begin(), platforms_.end(),
                      [](bool x) { return x; });
}

void Snapshot::EndState::add_platform(PlatformId platform) {
  platforms_[ToInt(platform)] = true;
}

std::vector<PlatformId> Snapshot::EndState::platforms() const {
  std::vector<PlatformId> r;
  for (int p = 0; p < platforms_.size(); ++p) {
    if (platforms_[p]) {
      r.push_back(static_cast<PlatformId>(p));
    }
  }
  return r;
}

void Snapshot::EndState::set_platforms(
    const std::vector<PlatformId>& platforms) {
  platforms_ = std::vector<bool>(ToInt(kMaxPlatformId) + 1, false);
  for (auto p : platforms) {
    int i = ToInt(p);
    CHECK_LT(i, ToInt(kMaxPlatformId));
    platforms_[i] = true;
  }
}

// ========================================================================= //

const Snapshot::Metadata& Snapshot::metadata() const {
  CHECK(metadata_ != nullptr);
  return *metadata_;
}

void Snapshot::set_metadata(const Metadata& metadata) {
  metadata_.reset(new Metadata(metadata));
}

// ========================================================================= //

void Snapshot::set_trace_data(const std::vector<TraceData>& trace_data) {
  trace_metadata_ = trace_data;
}

const std::vector<Snapshot::TraceData>& Snapshot::trace_data() const {
  return trace_metadata_;
}

void Snapshot::TraceData::add_platform(PlatformId platform) {
  DCHECK(platform != PlatformId::kUndefined && platform < PlatformId::kAny);
  auto pos = absl::c_lower_bound(platforms_, platform);
  if (pos == platforms_.end() || *pos != platform) {
    platforms_.insert(pos, platform);
  }
}
}  // namespace silifuzz
