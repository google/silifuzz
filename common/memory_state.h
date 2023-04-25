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

#ifndef THIRD_PARTY_SILIFUZZ_MEMORY_STATE_H_
#define THIRD_PARTY_SILIFUZZ_MEMORY_STATE_H_

#include <stddef.h>

#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "./common/mapped_memory_map.h"
#include "./common/snapshot.h"
#include "./common/snapshot_types.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/range_map.h"

namespace silifuzz {

// MemoryState describes the state of memory (related to snapshot)
// in a process playing a snapshot.
// It also provides utilities for accessing and utilizing that info.
//
// This class is thread-compatible.
class MemoryState : private SnapshotTypeNames {
 public:
  // ----------------------------------------------------------------------- //
  // Types.

  // We operate on the same data as Snapshot, but initial usage will be
  // for the cases when Snapshot::CurrentArchitecture() matches architecture()
  // in the Snapshot being processed.

  // MemoryMapping with an additional action enum to tell what needs to happen
  // - see all the DeltaMemoryMapping*() functions below.
  class MemoryMappingCmd : public MemoryMapping {
   public:
    // What to do for this MemoryMapping: mmap(), mprotect(), munmap().
    enum Action { kMap = 0, kProtect, kUnmap };
    MemoryMappingCmd(const MemoryMapping& m, Action action)
        : MemoryMapping(m), action_(action) {}
    Action action() const { return action_; }

    // For logging.
    std::string DebugString() const;

   private:
    Action action_;
  };

  using MemoryMappingCmdList = std::vector<MemoryMappingCmd>;

  // A bool (conceptually) specifying whether ZeroMappedMemoryBytes()
  // should be happening or not for all the relevant mapped regions.
  enum MappedZeroing { kZeroMappedBytes, kIgnoreMappedBytes };

  // ----------------------------------------------------------------------- //
  // Factories.

  // Returns state corresponding to the initial snapshot state.
  // See also SetInitialState().
  static MemoryState MakeInitial(const Snapshot& snapshot,
                                 MappedZeroing mapped_zeroing);

  // Returns state corresponding to the given endstate in `snapshot`.
  // REQUIRES: end_state_index is in [0, snapshot.expected_end_states().size())
  static MemoryState MakeEnd(const Snapshot& snapshot, int end_state_index,
                             MappedZeroing mapped_zeroing);

  // ----------------------------------------------------------------------- //
  // Construction, etc.

  // Creates an empty MemoryState.
  // PROVIDES: IsEmpty()
  MemoryState();
  ~MemoryState();

  // Movable, but not copyable (can be large and expensive to copy by accident).
  MemoryState(const MemoryState&) = delete;
  MemoryState(MemoryState&&) = default;
  MemoryState& operator=(const MemoryState&) = delete;
  MemoryState& operator=(MemoryState&&) = default;

  // Returns a copy of *this - for when we actually need to copy.
  MemoryState Copy() const;

  bool operator==(const MemoryState& y) const;
  bool operator!=(const MemoryState& y) const { return !(*this == y); }

  // Equality constrained to all the data behind memory_bytes().
  // Note that mapped_memory() can be compared directly.
  bool MemoryBytesEq(const MemoryState& y) const;

  // Whether *this has no data.
  bool IsEmpty() const;

  // Returns *this to empty state.
  // PROVIDES: IsEmpty()
  void Clear() { *this = MemoryState(); }

  // ----------------------------------------------------------------------- //
  // Mutators.
  // "Set" in the names here means "add-or-update supplied state",
  // not "assign replacing whole existing state".
  // TODO(ksteuck): [cleanup] Consider Set->Upsert to remove ambiguity.

  // Adds a MemoryMapping to *this (must be disjoint from mapped_memory()).
  // REQUIRES: mapping.perms() is non-empty
  void AddNewMemoryMapping(const MemoryMapping& mapping);
  void AddNewMemoryMappings(const MemoryMappingList& mappings) {
    for (const auto& m : mappings) AddNewMemoryMapping(m);
  }

  // Same as AddNewMemoryMapping(), but does not require `mapping`
  // to be disjoint from mapped_memory() -- replaces the perms
  // in the range of `mapping`.
  void SetMemoryMapping(const MemoryMapping& mapping);

  // Same as SetMemoryMapping(), but allows empty mapping.perms().
  void SetMemoryMappingEmptyPermsOk(const MemoryMapping& mapping);

  // Remove the given range from mapped_memory().
  void RemoveMemoryMapping(Address start_address, Address limit_address);

  // Remove all ranges from mapped_memory() that are not in
  // snapshot.memory_mappings().
  void RemoveMemoryMappingsNotIn(const Snapshot& snapshot);

  // Like RemoveMemoryMappingsNotIn(), but instead of removing all knowledge
  // of the memory ranges, only clears rwx perms on them.
  void ClearMemoryMappingsPermsNotIn(const Snapshot& snapshot);

  // Remembers that given bytes have given values: adds or updates the info
  // about byte values in *this as needed.
  // REQUIRES: MemoryBytes is within mapped_memory().
  void SetMemoryBytes(const MemoryBytes& bytes);
  void SetMemoryBytes(const MemoryBytesList& bytes) {
    for (const auto& b : bytes) SetMemoryBytes(b);
  }

  // Remove any existing record of previous SetMemoryBytes() for the
  // [start_address, limit_address) range.
  // This is necessary to do for performance reasons before updating
  // previously-known MemoryBytes via a long sequence of SetMemoryBytes()
  // chunks. Without such pre-removal the iterative overwriting results in
  // a bad n^2 performace as the ByteData blob for the overall range gets
  // repeatedly split-up into three parts, middle chunk overwrittend, and
  // then the three parts merged back. Whereas with the pre-removal the added
  // chunks are appended to a growing ByteData blob.
  void ForgetMemoryBytes(Address start_address, Address limit_address);

  // SetMemoryBytes() for all snapshot.memory_bytes()
  void SetMemoryBytes(const Snapshot& snapshot);

  // Convenience overload:
  void SetMemoryBytes(const EndState& end_state) {
    SetMemoryBytes(end_state.memory_bytes());
  }

  // Like SetMemoryBytes(), but sets all mapped memory bytes to 0.
  // This models the MAP_ANONYMOUS mmap() behavior happening in the harness.
  void ZeroMappedMemoryBytes(const MemoryMapping& mapping);
  void ZeroMappedMemoryBytes(const MemoryMappingList& mappings) {
    for (const auto& m : mappings) ZeroMappedMemoryBytes(m);
  }
  void ZeroMappedMemoryBytes(const Snapshot& snapshot) {
    ZeroMappedMemoryBytes(snapshot.memory_mappings());
  }

  // Modifies *this to have the starting `snapshot` state in it (while leaving
  // anything pre-existing outside `snapshot` memory regions as is).
  void SetInitialState(const Snapshot& snapshot, MappedZeroing mapped_zeroing);

  // ----------------------------------------------------------------------- //
  // Accessors.

  // The state of mapped memory: what is mapped with what permissions.
  // Always includes MemoryPerms::kMapped, so that it can represent memory
  // mapped with empty perms.
  const MappedMemoryMap& mapped_memory() const;

  // The set of known (written) memory.
  const MemoryBytesSet& written_memory() const;

  // Number of bytes covered by written_memory().
  ByteSize num_written_bytes() const;

  // The value of the memory byte at `address`.
  // REQUIRES: `address` is inside written_memory().
  char memory_byte(Address address) const;

  // The values of the memory bytes at [start_address, start_address+num_bytes).
  // REQUIRES: the byte range requested is fully within written_memory().
  ByteData memory_bytes(Address start_address, ByteSize num_bytes) const;

  // Convenience helper reading and returning memory_bytes() for the ranges
  // of addresses in a MemoryBytesSet as MemoryBytesList.
  MemoryBytesList memory_bytes_list(const MemoryBytesSet& bytes) const;

  // ----------------------------------------------------------------------- //
  // Non-trivial readers (data users).

  // Returns minimized value x of `mapping` such that applying the commands
  // of x has the same effect on *this as SetMemoryMappings(y), where y is
  // `mapping` with added_perms added to it.
  // The returned MemoryMappingCmd values are disjoint.
  // If one has known-to-be-disjoint set of MemoryMapping,
  // this helper can be trivially generalized to it.
  MemoryMappingCmdList DeltaMemoryMapping(const MemoryMapping& mapping,
                                          MemoryPerms added_perms) const;

  // DeltaMemoryMapping() generalized to snapshot.memory_mappings().
  // The returned MemoryMappingCmd values are disjoint.
  MemoryMappingCmdList DeltaMemoryMappings(const Snapshot& snapshot,
                                           MemoryPerms added_perms) const;

  // Returns minimized value x of snapshot.memory_mappings() such that
  // applying the commands of x has the same effect on this->mapped_memory() as
  // calling AddNewMemoryMappings(mappings) would have on an empty MemoryState,
  // where `mappings` is snapshot.memory_mappings() with added_perms added to
  // every MemoryMapping.
  // For kProtectUnused mode, instead of unmapping things not in
  // snapshot.memory_mappings(), commands to re-protect them with empty perms
  // are added.
  // The returned MemoryMappingCmd values are disjoint.
  enum ExactnessMode { kUnmapUnused, kProtectUnused };
  MemoryMappingCmdList DeltaMemoryMappingsExact(const Snapshot& snapshot,
                                                MemoryPerms added_perms,
                                                ExactnessMode mode) const;

  // Returns minimized value x of `bytes` such that
  // SetMemoryBytes(x) still has the same effect on *this as
  // SetMemoryBytes(bytes).
  // The returned MemoryBytes values are disjoint.
  MemoryBytesList DeltaMemoryBytes(const MemoryBytes& bytes) const;

  // Generalization of the above overload.
  // REQUIRES: `bytes` are disjoint ranges
  MemoryBytesList DeltaMemoryBytes(const MemoryBytesList& bytes) const;

  // DeltaMemoryBytes() for all snapshot.memory_bytes().
  // The returned MemoryBytes values are disjoint.
  MemoryBytesList DeltaMemoryBytes(const Snapshot& snapshot) const;

 private:
  // Methods to define a RangeMap<> instance (see MemoryBytesMap below)
  // that maps the Address ranges to the ByteData blobs written into those
  // ranges.
  //
  // See RangeMap<> for the requirements on the "Methods" class needed by it.
  class MemoryBytesMethods {
   public:
    using Key = Address;
    using Value = ByteData;
    using Size = int;

    // Map will be in the Address order.
    static int Compare(const Key& x, const Key& y) {
      // Key=Address is unsigned, so simply x-y does not work:
      return x == y ? 0 : (x < y ? -1 : 1);
    }

    // We don't use this, but it needs to be defined, so we define it to count
    // reasonably accurate byte usage in the RangeMap<>.
    static Size Usage(
        const std::pair<const std::pair<Key, Key>, Value>* range) {
      return sizeof(*range) + range->second.size();
    }

    // Slices ByteData `v` in the [start, limit) range for the [s,l) subrange.
    static Value Slice(const Key& start, const Key& limit, const Value& v,
                       const Key& s, const Key& l) {
      // Sanity checks on RangeMap<>:
      DCHECK_LE(start, s);
      DCHECK_LT(s, l);
      DCHECK_LE(l, limit);
      // Support empty ByteData as the special removal value, that is
      // idempotent wrt extraction:
      if (v.empty()) return v;
      // Otherwise we slice the ByteData blob:
      DCHECK_EQ(v.size(), limit - start);  // sanity check on RangeMap<>
      return v.substr(s - start, l - s);
    }

    // It's a plain overwrite.
    template <typename ValueT>
    static bool AddTo(Value* dest, ValueT&& v, bool* empty) {
      bool change = *dest != v;
      if (change) *dest = std::forward<ValueT>(v);
      return change;
    }

    // We only support blind removal with empty ByteData as the special
    // removal value.
    static bool RemoveFrom(Value* dest, const Value& v, bool* empty) {
      DCHECK(v.empty());
      *empty = true;
      return true;
    }

    // RangeMap<> only asks this for adjacent ranges ...
    static bool CanMerge(const Value& v1, const Value& v2) { return true; }

    // ... where we can always concatenate the ByteData.
    template <typename ValueT>
    static void Merge(Value* dest, ValueT&& v) {
      dest->append(std::forward<ValueT>(v));
    }

    // We only support intersection for the map with empty ByteData v2 that
    // gets ignored. This way intersection only operates on the address ranges,
    // while values from the first intersection arg get processed through
    // Slice() and ignored for the second intersection arg.
    static void MakeIntersection(Value* dest, const Value& v1, const Value& v2,
                                 bool* empty) {
      DCHECK(v2.empty() && !v1.empty());
      *dest = v1;
    }
  };

  using MemoryBytesMap =
      RangeMap<MemoryBytesMethods::Key, MemoryBytesMethods::Value,
               MemoryBytesMethods>;

  // Helper for DeltaMemoryBytes(): see .cc for the spec.
  // Declared here only to get short type names for MemoryBytes and such.
  static void GrowResultChunk(const MemoryBytes& bytes, Address addr,
                              size_t size, std::optional<MemoryBytes>& chunk,
                              MemoryBytesList& result);

  // See mapped_memory().
  MappedMemoryMap mapped_memory_map_;

  // See written_memory().
  // Present only to support the written_memory() accessor.
  MemoryBytesSet written_memory_set_;

  // The memory bytes in the set of known (written) memory.
  // Same set of address ranges as written_memory_set_.
  MemoryBytesMap written_memory_bytes_;
};

// EnumStr() works for MemoryState::MemoryMappingCmd::Action.
template <>
extern const char*
    EnumNameMap<MemoryState::MemoryMappingCmd::
                    Action>[ToInt(MemoryState::MemoryMappingCmd::kUnmap) + 1];

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_MEMORY_STATE_H_
