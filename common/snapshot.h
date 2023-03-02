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

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_H_

// This file defines the C++ classes representing snapshot data.
// This is the same data as in silifuzz/proto/snapshot.proto.
// IMPORTANT: All code except for ./snapshot_proto.h lib should deal with these
// classes, never with the protos directly.
//
// Note that this library does not depend on snapshot.proto, only the
// snapshot_proto.h lib does.
// This way we could easily change the externalization format if needed.

#include <string>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "./common/mapped_memory_map.h"
#include "./common/memory_bytes_set.h"
#include "./common/memory_mapping.h"
#include "./common/memory_perms.h"
#include "./common/snapshot_enums.h"
#include "./util/arch.h"
#include "./util/itoa.h"
#include "./util/misc_util.h"
#include "./util/platform.h"

namespace silifuzz {

// Snapshot is the data representation for a snapshot: instructions
// and the necessary data for execution of some relatively short snippet
// of binary code, target architechture and snapshot id.
//
// See proto.Snapshot in silifuzz/proto/snapshot.proto for more info.
//
// Note that (in the future) a process manipulating a `Snapshot` (or its
// proto equivalent) might be for a different architecture than the
// architecture in which the snapshot is meant to execute.
// We write the code with this assumption in mind.
//
// This class is thread-compatible (so are all its nested classes).
class Snapshot final {
 public:
  // Type for a memory address (instructions or data inside a snapshot).
  using Address = snapshot_types::Address;
  static constexpr Address kMinAddress = snapshot_types::kMinAddress;
  static constexpr Address kMaxAddress = snapshot_types::kMaxAddress;

  // Type for a Snapshot identifier. Refer to Snapshot.id proto field for
  // details.
  using Id = std::string;

  // Default register value when a value is missing.
  static constexpr uint64_t kUnsetRegisterValue = 0x0;

  // Type for a size (a non-negative difference between two `Address`es).
  using ByteSize = snapshot_types::ByteSize;

  // Type for a sequence of byte data.
  using ByteData = std::string;

  // Type for one byte of data.
  using Byte = ByteData::value_type;  // char

  // Describes a single contiguous page-aligned memory mapping.
  using MemoryMapping = silifuzz::MemoryMapping;

  // All these component-of-snapshot types are defined below.
  // Each T corresponds to a proto::T from silifuzz/proto/snapshot.proto.
  class MemoryBytes;
  class RegisterState;
  using Endpoint = snapshot_types::Endpoint;
  class EndState;
  class Metadata;

  // Supported architectures of snapshots.
  // Note that enum values here match those in snapshot.proto;
  // snapshot_proto.cc makes sure it's the case.
  // See snapshot_enums_noblic.h for the values used.
  using Architecture = snapshot_types::Architecture;

  // Possible types of good states for Snapshot -- see IsComplete().
  enum State {
    // registers() and memory_bytes() in expected_end_states() must be empty.
    kUndefinedEndState,

    // registers() in expected_end_states() must be set.
    kNormalState,

    // Same as kUndefinedEndState plus the expected_end_states() can
    // have unmapped endpoint instruction addresses.
    kMakingState,
  };

  // Returns the value of "unset" snapshot id. The id must be set using
  // set_id() prior to proto conversion.
  static const Id& UnsetId();

  // Validates snapshot id.
  // Refer to snapshot.proto/Snapshot.id for details on what a valid ID is.
  static absl::Status IsValidId(const Id& id) ABSL_MUST_USE_RESULT;

  // Returns the Architecture of the process executing this code,
  // i.e. the current host architecture.
  static Architecture CurrentArchitecture();

  template <typename Arch>
  static Architecture ArchitectureTypeToEnum() {
    return static_cast<Architecture>(Arch::architecture_id);
  }

  // Constructs empty Snapshot with the given id for the given Architecture
  // (must be a supported one).
  Snapshot(Architecture arch, const Id& id = UnsetId());

  ~Snapshot();

  // Movable, but not copyable (can be large and expensive to copy by accident).
  Snapshot(const Snapshot&) = delete;
  Snapshot(Snapshot&&) = default;
  Snapshot& operator=(const Snapshot&) = delete;
  Snapshot& operator=(Snapshot&&) = default;

  // Returns a copy of *this - for when we actually need to copy.
  Snapshot Copy() const;

  bool operator==(const Snapshot& y) const;
  bool operator!=(const Snapshot& y) const { return !(*this == y); }

  // Equality that disregards expected_end_states() and
  // negative_memory_mappings() (derived from expected_end_states()).
  // NOTE: both *this and y should be normalized according to NormalizeAll()
  // for this function to return correct result.
  bool EqualsButEndStates(const Snapshot& y) const;

  // Resets *this to post-construction state.
  void Clear();

  // Returns ok status iff this snapshot contains the minimally required
  // contents for the given `state`:
  // some memory_mappings(), some memory_bytes(), some expected_end_states(),
  // and registers() are present; otherwise encodes the error into the result.
  absl::Status IsComplete(State state = kNormalState) const
      ABSL_MUST_USE_RESULT;

  // Succeeds if IsComplete() succeeds for some `State`.
  absl::Status IsCompleteSomeState() const ABSL_MUST_USE_RESULT;

  // Identifier for this snapshot.
  const Id& id() const { return id_; }

  // Architecture this snapshot is meant for, i.e. its target architecture.
  Architecture architecture() const { return architecture_; }
  ArchitectureId architecture_id() const {
    return static_cast<ArchitectureId>(architecture_);
  }

  // Human-readable name of architecture().
  absl::string_view architecture_name() const;

  // Size of OS pages in the address space for architecture().
  ByteSize page_size() const;

  // Number of bytes below rsp register that must exist (and be writable)
  // for snapshot playback to function.
  ByteSize required_stack_size() const;

  // ----------------------------------------------------------------------- //
  // Basic contents.

  // All the memory mappings that exist at the start of the snapshot.
  // Guaranteed to be disjoint.
  using MemoryMappingList = std::vector<MemoryMapping>;
  const MemoryMappingList& memory_mappings() const;

  // Tells if the x can be added; encodes the error if not.
  absl::Status can_add_memory_mapping(const MemoryMapping& x) const
      ABSL_MUST_USE_RESULT;

  // Adds one more MemoryMapping to snapshot.
  // REQUIRES: can_add_memory_mapping(x)
  // PROVIDES: x is *memory_mappings().back()
  void add_memory_mapping(const MemoryMapping& x);

  // Updates perms for an existing memory mapping.
  // REQUIRES: x must be in memory_mappings(), but possibly with a different
  //           MemoryPerms value.
  //           memory_mappings_index must be the index of the entry in
  //           memory_mappings() matching `x`.
  //           (This is so that this can be O(1) for memory_mappings()).
  void set_memory_mapping_perms(const MemoryMapping& x,
                                int memory_mappings_index);

  // Tells if `x` can replace memory_mappings(); encodes the error if not.
  absl::Status can_set_memory_mappings(const MemoryMappingList& x) const
      ABSL_MUST_USE_RESULT;

  // Replaces existing memory_mappings() by `x`.
  // REQUIRES: can_set_memory_mappings(x)
  void set_memory_mappings(const MemoryMappingList& x);

  // All the negative memory mappings that must not exist during playback
  // of the snapshot.
  // Negative mapping are used to ensure that a SIGSEGV Endpoint reliably
  // reoccurs during snapshot playback -- see AddNegativeMemoryMappingsFor()
  // below.
  // Guaranteed to be disjoint and not conflict with memory_mappings().
  // CAVEAT: Sometimes we need to have a MemoryMapping in this list that
  // represents the very last page in the address space. This can't be done
  // directly: MemoryMapping::limit_address() is not representable as Address.
  // Instead we add that last page excluding its very last byte and then
  // special-case the code dealing with negative MemoryMapping-s to account
  // for this. We could clean this up if we extended Address to be able to
  // represent kMaxAddress + 1.
  const MemoryMappingList& negative_memory_mappings() const;

  // Tells if the x can be added; encodes the error if not.
  absl::Status can_add_negative_memory_mapping(const MemoryMapping& x) const
      ABSL_MUST_USE_RESULT;

  // Adds one more negative MemoryMapping to snapshot.
  // Prefer to use AddNegativeMemoryMappingsFor() below.
  // REQUIRES: can_add_negative_memory_mapping(x)
  // PROVIDES: x is *negative_memory_mappings().back()
  void add_negative_memory_mapping(const MemoryMapping& x);

  // Sets negative_memory_mappings() to the given value.
  // REQUIRES: can_add_negative_memory_mapping(x) for every x in xs
  //           starting from empty negative_memory_mappings() state.
  void set_negative_memory_mappings(const MemoryMappingList& xs);

  // Adds the necessary negative_memory_mappings() for an EndState if any
  // or returns the error if can't do that.
  //
  // For EndState-s with SIGSEGV (kSigSegv) in them this is essential to be
  // done to make an IsComplete() snapshot that plays correctly when we
  // reuse the harness subprocess.
  absl::Status AddNegativeMemoryMappingsFor(const EndState& x)
      ABSL_MUST_USE_RESULT;

  // All the memory state that exists at the start of the snapshot.
  // Guaranteed to be disjoint and inside memory_mappings().
  // IMPORTANT: See comments on proto.Snapshot.memory_bytes for a non-trivial
  // conditions on memory_bytes() that snapshots from which we want predictable
  // outcomes must satisfy. See also MappedMemoryIsDefined().
  using MemoryBytesList = std::vector<MemoryBytes>;
  const MemoryBytesList& memory_bytes() const;

  // Tells if the x can be added; encodes the error if not.
  absl::Status can_add_memory_bytes(const MemoryBytes& x) const
      ABSL_MUST_USE_RESULT;

  // Adds one more MemoryBytes to snapshot.
  // REQUIRES: can_add_memory_bytes(x)
  // PROVIDES: x is *memory_bytes().back()
  void add_memory_bytes(const MemoryBytes& x);
  void add_memory_bytes(MemoryBytes&& x);

  // Replaces all MemoryBytes of the snapshot with items from the list.
  // REQUIRES: can_add_memory_bytes(x) for all x <- xs.
  // Returns a status if the precondition was not satisfied. When a status
  // is returned leaves *this in an undefined state.
  absl::Status ReplaceMemoryBytes(MemoryBytesList&& xs);

  // Tells iff memory_bytes() covers all of memory_mappings().
  bool MappedMemoryIsDefined() const;

  // Tells if RegisterState is present in the snapshot.
  bool has_registers() const;

  // Sets snapshot id.
  // REQUIRES: IsValidId(id)
  void set_id(const Id& id);

  // The state of the registers at the start of the snapshot.
  // REQUIRES: has_registers().
  const RegisterState& registers() const;

  // Tells if the x can be set; encodes the error if not.
  // is_end_state tells if this is for EndState or Snapshot.
  absl::Status can_set_registers(const RegisterState& x,
                                 bool is_end_state = false) const
      ABSL_MUST_USE_RESULT;

  // Sets (replaces) RegisterState in the snapshot to `x`.
  // REQUIRES: can_set_registers(x)
  void set_registers(const RegisterState& x);

  // The possible expected end-states of executing the snapshot.
  using EndStateList = std::vector<EndState>;
  const EndStateList& expected_end_states() const;

  // Metadata associated with this snapshot.
  const Metadata& metadata() const;
  void set_metadata(const Metadata& metadata);

  // Tells if the x can be added; encodes the error if not.
  // Setting unmapped_endpoint_ok allows to add an end-state with
  // Endpoint::kInstruction that is not yet in memory_mappings().
  // Note that IsComplete(state) will still require this to be fixed-up for
  // any `state` but kMakingState.
  absl::Status can_add_expected_end_state(
      const EndState& x,
      bool unmapped_endpoint_ok = false) const ABSL_MUST_USE_RESULT;

  // Adds one more EndState to snapshot.
  // You probably also want to call AddNegativeMemoryMappingsFor(x) above.
  // REQUIRES: can_add_expected_end_state(x)
  // PROVIDES: x is *expected_end_states().back()
  void add_expected_end_state(const EndState& x,
                              bool unmapped_endpoint_ok = false);

  // Does add_platform(platform) on expected_end_states()[i].
  // REQUIRES: i must be in-range
  void add_platform_to_expected_end_state(int i, PlatformId platform);

  // Same as add_platform_to_expected_end_state(),
  // but adds all platforms from `x` (which must be DataEquals()).
  void add_platforms_to_expected_end_state(int i, const EndState& x);

  // Sets expected_end_states() to the given value.
  // REQUIRES: can_add_expected_end_state(x) for every x in xs
  void set_expected_end_states(const EndStateList& xs);

  // Removes *x from snapshot, thus invalidating `x`.
  // REQUIRES: x must refer to one of expected_end_states()
  void remove_expected_end_state(const EndState* x);

  // ----------------------------------------------------------------------- //
  // Simple whole-snapshot manipulation.

  // Merges adjacent memory_mappings() if possible and orders them
  // by Address values. Same for negative_memory_mappings().
  void NormalizeMemoryMappings();

  // Ensures that memory_bytes() has the minimum number of elements sorted by
  // start addresses. Adjacent MemoryBytes are broken into parts at permission
  // boundaries and are only merged if their permissions are identical.
  void NormalizeMemoryBytes();

  // Merges adjacent *memory_bytes entries and orders them by Address values.
  // This only merges adjacent memory bytes with identical permissions.
  // `memory_map` describes memory mappings of the *`memory_bytes` REQUIRES: all
  // memory bytes must resides in mapped regions in memory_map.
  static void NormalizeMemoryBytes(const MappedMemoryMap& memory_map,
                                   MemoryBytesList* memory_bytes);
  // Does all Normalize*()s above.
  // One might want to do this after heavy processing of this snapshot
  // before saving it into some long-term storage.
  void NormalizeAll();

  // Removes IsComplete(kUndefinedEndState) expected_end_states() if have
  // a kNormalState entry there. Returns whether it has changed the snapshot.
  // One might want to do this after applying EndStateRecorder if one did
  // not trust the accuracy of kUndefinedEndState-s that existed before that.
  bool TryRemoveUndefinedEndStates();

  // ----------------------------------------------------------------------- //
  // Content querying.

  // Extracts value of rip from a RegisterState per architecture().
  Address ExtractRip(const RegisterState& x) const;

  // Extracts value of rsp from a RegisterState per architecture().
  Address ExtractRsp(const RegisterState& x) const;

  // Size of memory_mappings() in page_size().
  int num_pages() const;

  // memory_mappings() as a MappedMemoryMap.
  // Does not include MemoryPerms::kMapped as it only contains entries
  // with non-empty perms.
  const MappedMemoryMap& mapped_memory_map() const;

  // negative_memory_mappings() as a MappedMemoryMap.
  // Does not include MemoryPerms::kMapped as it only contains entries
  // with non-empty perms.
  const MappedMemoryMap& negative_mapped_memory_map() const;

  // || of has_platform(platform) over expected_end_states().
  bool some_has_platform(PlatformId platform) const;

  // memory_bytes() as an MemoryBytesSet of Address ranges.
  using MemoryBytesSet = silifuzz::MemoryBytesSet;
  const MemoryBytesSet& written_memory_set() const;

  // Returns permissions covering the byte at `address`
  // or MemoryPerms::None() if `address` is not inside memory_mappings().
  MemoryPerms PermsAt(Address address) const;

  // Union or intersection of permissions for the given Address range.
  MemoryPerms Perms(Address start_address, Address limit_address,
                    MemoryPerms::JoinMode mode) const;

  // Equality helper.
  static bool MemoryBytesListEq(const MemoryBytesList& x,
                                const MemoryBytesList& y);

 private:
  // Defined in .cc.
  struct ArchitectureDescr;

  // All the architectures supported by snapshots.
  static const ArchitectureDescr kSupportedArchitectures[];

  // Implements the public can_add_negative_memory_mapping()
  // as well as the precondition for add_negative_memory_mapping_overlap_ok().
  absl::Status can_add_negative_memory_mapping(
      const MemoryMapping& x, bool overlap_ok) const ABSL_MUST_USE_RESULT;

  // Implements the public can_add_expected_end_state(),
  // while providing an option to ignore the case when `x` is a dup of an
  // existing end-state.
  absl::Status can_add_expected_end_state(
      const EndState& x, bool unmapped_endpoint_ok,
      bool duplicate_ok) const ABSL_MUST_USE_RESULT;

  // A variant of add_negative_memory_mapping() that allows `x` to overlap
  // pre-existing negative_memory_mappings().
  // REQUIRES: can_add_negative_memory_mapping(x, true)
  void add_negative_memory_mapping_overlap_ok(const MemoryMapping& x);

  // Returns true iff [addr, addr+size) is in a mapped executable region
  // per memory_mappings().
  // Returns non-ok status if [addr; addr+size) is not a valid memory mapping.
  absl::StatusOr<bool> IsExecutable(Address addr, ByteSize size) const;

  // Returns a list of memory mappings in memory_map in ascending address
  // order.
  static MemoryMappingList SortedMemoryMappingList(
      const MappedMemoryMap& memory_map);

  template <typename Arch>
  Snapshot::Address ExtractRipImpl(const RegisterState& x) const;

  template <typename Arch>
  Snapshot::Address ExtractRspImpl(const RegisterState& x) const;

  template <typename Arch>
  absl::Status can_set_registers_impl(const Snapshot::RegisterState& x,
                                      bool is_end_state) const;

  template <typename Arch>
  bool registers_match_arch_impl(const Snapshot::RegisterState& x) const;

  // Check that the RegisterState matches the architecture of the Snapshot.
  bool registers_match_arch(const Snapshot::RegisterState& x) const;

  // ----------------------------------------------------------------------- //

  // See id().
  Id id_;

  // See architecture().
  Architecture architecture_;

  // ArchitectureDescr corresponding to architecture_ (not null).
  const ArchitectureDescr* architecture_descr_;

  // See mapped_memory_map().
  MappedMemoryMap mapped_memory_map_;

  // See negative_mapped_memory_map().
  MappedMemoryMap negative_mapped_memory_map_;

  // See written_memory_set().
  MemoryBytesSet written_memory_set_;

  // See memory_mappings().
  MemoryMappingList memory_mappings_;

  // See negative_memory_mappings().
  MemoryMappingList negative_memory_mappings_;

  // See memory_bytes().
  MemoryBytesList memory_bytes_;

  // See registers().
  std::unique_ptr<RegisterState> registers_;

  // See expected_end_states().
  std::vector<EndState> expected_end_states_;

  // See metadata().
  std::unique_ptr<Metadata> metadata_;
};

// ========================================================================= //

// Contains metadata associated with the snapshot.
class Snapshot::Metadata {
 public:
  enum class Origin {
    kUndefined = 0,
    kIfuzz = 2,
    kUnicorn = 3,
    kBochs = 5,
    kXed = 6,
    kGem5 = 7,
    kIaca = 8,
    kLlvmMca = 9,
    kUnicornCustom = 10,
    kEmulator1 = 11,
  };

  Metadata() : origin_(Origin::kUndefined) {}
  Metadata(const Metadata& other) = default;
  Metadata(Metadata&& other) = default;
  explicit Metadata(Origin origin) : origin_(origin) {}

  Origin origin() const { return origin_; }

 private:
  Origin origin_;
};

// ========================================================================= //

// Describes a single contiguous range of byte values in memory.
class Snapshot::MemoryBytes final {
 public:
  // Returns iff constructing MemoryBytes from these is valid:
  // byte_values needs to be non-empty.
  static absl::Status CanConstruct(
      Address start_address, const ByteData& byte_values) ABSL_MUST_USE_RESULT;

  // REQUIRES: CanConstruct(start_address, byte_values)
  MemoryBytes(Address start_address, const ByteData& byte_values);
  MemoryBytes(Address start_address, ByteData&& byte_values);

  // Intentionally movable and copyable.

  bool operator==(const MemoryBytes& y) const;
  bool operator!=(const MemoryBytes& y) const { return !(*this == y); }
  bool operator<(const MemoryBytes& y) const;  // for sorting

  // Where byte_values() start and end:
  // [start_address, limit_address) address range.
  Address start_address() const { return start_address_; }
  Address limit_address() const { return start_address_ + byte_values_.size(); }

  // The bytes to exist in the [start_address, limit_address) address range.
  const ByteData& byte_values() const { return byte_values_; }
  ByteData* mutable_byte_values() { return &byte_values_; }
  ByteSize num_bytes() const { return byte_values_.size(); }

  // Returns a new MemoryBytes in of contents in range [start, limit).
  // REQUIRES: [start, limit) must be within this.
  MemoryBytes Range(Address start, Address limit);

  // For logging.
  std::string DebugString() const;

 private:
  // See start_address().
  Address start_address_;

  // See byte_values().
  ByteData byte_values_;
};

// ========================================================================= //

// Describes the state of CPU registers.
class Snapshot::RegisterState final {
 public:
  // See ./snapshot_util.h on how to convert between RegisterState and
  // the usual GRegSet plus FPRegSet in Snapshot::CurrentArchitecture().
  RegisterState(const ByteData& gregs, const ByteData& fpregs);

  // Intentionally movable and copyable.

  bool operator==(const RegisterState& y) const;
  bool operator!=(const RegisterState& y) const { return !(*this == y); }

  // Returns true if *this describes an empty, unspecified register state.
  bool IsUnset() const { return gregs_.empty() && fpregs_.empty(); }

  // Serialized bytes of the GRegSet struct.
  const ByteData& gregs() const { return gregs_; }

  // Serialized bytes of the FPRegSet struct.
  const ByteData& fpregs() const { return fpregs_; }

 private:
  // See gregs().
  ByteData gregs_;

  // See fpregs().
  ByteData fpregs_;
};

// ========================================================================= //

// Describes a specific endstate of executing a snapshot.
class Snapshot::EndState final {
 public:
  // Constructs EndState with empty memory_bytes().
  EndState(const Endpoint& endpoint, const RegisterState& registers);

  // Constructs EndState with empty registers() and memory_bytes(),
  // i.e. an IsComplete(kUndefinedEndState) one.
  explicit EndState(const Endpoint& endpoint)
      : EndState(endpoint, RegisterState("", "")) {}

  // Intentionally movable and copyable.

  bool operator==(const EndState& y) const;
  bool operator!=(const EndState& y) const { return !(*this == y); }

  // Ignores differences in has_platform().
  bool DataEquals(const EndState& y) const;

  // Returns ok status iff this EndState contains the minimally required
  // contents for the given `state`, otherwise encodes the error into
  // the result.
  absl::Status IsComplete(State state = kNormalState) const
      ABSL_MUST_USE_RESULT;

  // Expected execution endpoint that defines this EndState.
  const Endpoint& endpoint() const { return endpoint_; }

  // The expected state of the registers to exist at `endpoint()`.
  const RegisterState& registers() const { return registers_; }

  // The expected memory state to exist at `endpoint()`.
  // Only differences from the starting state need to be mentioned here.
  // Guaranteed to be disjoint and inside Snapshot::memory_mappings() when
  // part of a Snapshot.
  const MemoryBytesList& memory_bytes() const { return memory_bytes_; }

  // memory_bytes() as an IntervalSet of Address ranges.
  const MemoryBytesSet& changed_memory_set() const;

  // Tells if the x can be added; encodes the error if not.
  absl::Status can_add_memory_bytes(const MemoryBytes& x) const
      ABSL_MUST_USE_RESULT;

  // Adds one more MemoryBytes to EndState.
  // REQUIRES: can_add_memory_bytes(x)
  // PROVIDES: x is *memory_bytes().back()
  void add_memory_bytes(const MemoryBytes& x);
  void add_memory_bytes(MemoryBytes&& x);

  // Overloads for a list of MemoryBytes.
  void add_memory_bytes(const MemoryBytesList& xs);
  void add_memory_bytes(MemoryBytesList&& xs);

  // Replaces all MemoryBytes of the EndState with items from the list.
  // REQUIRES: can_add_memory_bytes(x) for all x <- xs.
  // Returns a status if the precondition was not satisfied. When a status
  // is returned leaves *this in an undefined state.
  absl::Status ReplaceMemoryBytes(MemoryBytesList&& xs);

  // Tells if this EndState is known-to-be-compatible with `platform`.
  bool has_platform(PlatformId platform) const;

  // Tells if has_platform(x) is false for all x.
  // This means that this EndState is provisional and can be removed
  // once a real one is observed.
  bool empty_platforms() const;

  // Add `platform` to the set of known-to-be-compatible for this EndState.
  void add_platform(PlatformId platform);

  // Returns a list of platforms this snapshot is compatible with.
  std::vector<PlatformId> platforms() const;

  // Sets the list of platforms this snapshot is compatible with.
  void set_platforms(const std::vector<PlatformId>& platforms);

 private:
  friend class Snapshot;  // for memory_bytes_ and platforms_.

  // See changed_memory_set().
  MemoryBytesSet changed_memory_set_;

  // See endpoint().
  Endpoint endpoint_;

  // See registers().
  RegisterState registers_;

  // See memory_bytes().
  MemoryBytesList memory_bytes_;

  // Holds bits for ToInt(PlatformId::kFoo).
  std::vector<bool> platforms_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_H_
