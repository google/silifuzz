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

#ifndef THIRD_PARTY_SILIFUZZ_MAPPED_MEMORY_MAP_H_
#define THIRD_PARTY_SILIFUZZ_MAPPED_MEMORY_MAP_H_

#include <stddef.h>

#include <functional>
#include <optional>
#include <string>
#include <utility>

#include "./common/memory_mapping.h"
#include "./common/memory_perms.h"
#include "./common/snapshot_enums.h"
#include "./util/range_map.h"

namespace silifuzz {

// A type representing a mapping from address ranges to MemoryPerms.
// This is used in several places and has some associated helpers,
// hence a dedicated class.
//
// Note that for our caller there could be useful information in both which
// MemoryPerms exist for a given address range, as well as sometimes whether
// anything about MemoryPerms has been specified for a given address range.
// To support the latter, the caller should include MemoryPerms::kMapped
// whenever adding data to the map. Then, depending on whether
// MemoryPerms::kMapped is included into removal or difference arguments,
// the different desired outcomes can be obtained.
//
// This class is thread-compatible.
class MappedMemoryMap {
 public:
  // Type for a memory address (instructions or data inside a snapshot).
  using Address = snapshot_types::Address;

  MappedMemoryMap() {}
  ~MappedMemoryMap() {}

  // Movable, but not copyable (can be large and expensive to copy by accident).
  MappedMemoryMap(const MappedMemoryMap&) = delete;
  MappedMemoryMap(MappedMemoryMap&&) = default;
  MappedMemoryMap& operator=(const MappedMemoryMap&) = delete;
  MappedMemoryMap& operator=(MappedMemoryMap&&) = default;

  // Returns a copy of *this - for when we actually need to copy.
  MappedMemoryMap Copy() const;

  // Whether *this has no data.
  bool IsEmpty() const { return rep_.empty(); }

  // Resets *this to post-construction IsEmpty() state.
  void Clear() { rep_.clear(); }

  // Size of the map as the number of ranges with different values.
  size_t size() const { return rep_.size(); }

  bool operator==(const MappedMemoryMap& y) const { return rep_ == y.rep_; }
  bool operator!=(const MappedMemoryMap& y) const { return !(*this == y); }

  // Adds `perms` to the permissions in [start_address, limit_address).
  // REQUIRES: !perms.IsEmpty()
  // See class-level comment about MemoryPerms::kMapped if you need to
  // add or set logically empty `perms` (without any of the rwx bits).
  void Add(Address start_address, Address limit_address, MemoryPerms perms);

  // Whole-map version of Add().
  void Add(const MappedMemoryMap& y);

  // Sets the permissions in [start_address, limit_address) to be `perms`.
  // REQUIRES: !perms.IsEmpty()
  void Set(Address start_address, Address limit_address, MemoryPerms perms);

  // Like Add() but with the precondition that its execution is equivalent
  // to Set(). Use AddNew() instead of Set() when possible - cheaper to run.
  // REQUIRES: !Overlaps(start_address, limit_address)
  void AddNew(Address start_address, Address limit_address, MemoryPerms perms);

  // Removes specified permissions data in the [start_address, limit_address)
  // range. When empty permissions remain in an affected range, that range will
  // be removed from the map, so Contains() and Overlaps() below will be
  // affected.
  void Remove(Address start_address, Address limit_address,
              MemoryPerms perms = MemoryPerms::AllPlusMapped());

  // Removes (in the sense of Remove() above) from *this all ranges of `y`
  // using `perms` as the permissions to remove, while permission values in `y`
  // are disregarded.
  // Runs in O(# of ranges in *this + # of ranges of `y` overlapping *this),
  // disregarding logn factors.
  void RemoveRangesOf(const MappedMemoryMap& y,
                      MemoryPerms perms = MemoryPerms::AllPlusMapped());

  // Adds intersection of x and y to *this.
  // Runs in O(# of ranges in `y` + # of ranges of `x` overlapping `y`) +
  // O(# of ranges in *this intersecting with the added ragnes),
  // disregarding logn factors.
  void AddIntersectionOf(const MappedMemoryMap& x, const MappedMemoryMap& y);

  // Adds difference of y from [start_address, limit_address)->perms to *this.
  // Ranges where MemoryPerms were the same will not be added,
  // ranges where MemoryPerms were different will be present with the diff
  // of the perms, which could be MemoryPerms::None().
  // CAVEAT: This is the only way to create MemoryPerms::None() entries in a
  // MappedMemoryMap.
  // Runs in O(# of ranges in `y` overlapping [start_address, limit_address)) +
  // O(# of ranges in *this intersecting with the added ragnes),
  // disregarding logn factors.
  void AddDifferenceOf(Address start_address, Address limit_address,
                       MemoryPerms perms, const MappedMemoryMap& y);

  // Adds difference of y from x to *this -- same semantics as the one-range
  // overload above.
  // Runs in O(# of ranges in `x` + # of ranges of `y` overlapping `x`) +
  // O(# of ranges in *this intersecting with the added ranges),
  // disregarding logn factors.
  void AddDifferenceOf(const MappedMemoryMap& x, const MappedMemoryMap& y);

  // Note that RangeMap(), which is our implementation has more flavors of
  // intersection and other helpers that can be easily added here.
  // We only expose the interfaces for which we have uses.

  // Returns true iff *this contains data covering the byte at `address`.
  bool Contains(Address address) const;

  // Returns the permissions covering the byte at `address`
  // or MemoryPerms::None() if !Contains(address).
  MemoryPerms PermsAt(Address address) const;

  // Returns a memory mapping at `address` if permissions at `address` are
  // not MemoryPerms::None() or std::nullopt if no mapping exists. If a memory
  // mapping is returned, its permissions have kMapped clear.
  std::optional<MemoryMapping> MappingAt(Address address) const;

  // Returns true iff *this contains data completely covering the given range.
  bool Contains(Address start_address, Address limit_address) const;

  // Returns true iff *this contains data overlapping the given range.
  bool Overlaps(Address start_address, Address limit_address) const;

  // Returns union or intersection of permissions for the given Address range.
  // If portions of the [start_address, limit_address) range go outside
  // of the data in *this, empty perms are used there.
  MemoryPerms Perms(Address start_address, Address limit_address,
                    MemoryPerms::JoinMode mode) const;

  // Runs `func` for every element of *this.
  // A poor man's iterator interface.
  void Iterate(
      std::function<void(Address start, Address limit, MemoryPerms perms)> func)
      const;

  // Like above but only for elements overlapping with the given address range.
  void Iterate(
      std::function<void(Address start, Address limit, MemoryPerms perms)> func,
      Address start, Address limit) const;

  // For logging.
  std::string DebugString() const;

 private:
  // Methods to define a RangeMap<> instance below that maps the Address ranges
  // to the MemoryPerms covering those ranges.
  //
  // See RangeMap<> for the requirements on the "Methods" class needed by it.
  class MemoryPermsMethods {
   public:
    using Key = Address;
    using Value = MemoryPerms;
    using Size = int;

    // Map will be in the Address order.
    static int Compare(const Key& x, const Key& y) {
      // Key=Address is unsigned, so simply x-y does not work:
      return x == y ? 0 : (x < y ? -1 : 1);
    }

    // We don't use this, but it needs to be defined, so we define it to count
    // byte usage in the RangeMap<>.
    static Size Usage(
        const std::pair<const std::pair<Key, Key>, Value>* range) {
      return sizeof(*range);
    }

    // No slicing needed.
    static const Value& Slice(const Key& start, const Key& limit,
                              const Value& v, const Key& s, const Key& l) {
      return v;
    }

    // It's an actual addition.
    static bool AddTo(Value* dest, const Value& v, bool* empty) {
      bool change = !dest->HasAllOf(v);
      dest->Add(v);
      return change;
    }

    // It's an actual removal: any affected MemoryPerms::IsEmpty() values
    // are removed.
    static bool RemoveFrom(Value* dest, const Value& v, bool* empty) {
      dest->Clear(v);
      *empty = dest->IsEmpty();
      return true;
    }

    // So that we merge ranges with equal values:
    static bool CanMerge(const Value& v1, const Value& v2) { return v1 == v2; }
    static void Merge(Value* dest, const Value& v) {}

    // Actual intersection for MemoryPerms, all MemoryPerms::IsEmpty() values
    // will be removed from the intersection.
    static void MakeIntersection(Value* dest, const Value& v1, const Value& v2,
                                 bool* empty) {
      *dest = v1;
      dest->Intersect(v2);
      *empty = dest->IsEmpty();
    }

    // We define "difference" dissimilar to RemoveFrom(): A value is kept (with
    // v1-v2, which could be MemoryPerms::None()) iff v1 != v2.
    // This is used by RangeMap::AddDifferenceOf(), which does not use
    // RemoveFrom(), so the slightly different behavior of the two is fine.
    static void MakeDifference(Value* dest, const Value& v1, const Value& v2,
                               bool* empty) {
      if (v1 == v2) {
        *empty = true;
      } else {
        *dest = v1;
        dest->Clear(v2);
      }
    }
  };

  using Rep = RangeMap<MemoryPermsMethods::Key, MemoryPermsMethods::Value,
                       MemoryPermsMethods>;
  Rep rep_;
};

// ----------------------------------------------------------------------- //

// Inline to help compiler optimize it away.
inline void MappedMemoryMap::Iterate(
    std::function<void(Address start, Address limit, MemoryPerms perms)> func)
    const {
  for (auto i = rep_.begin(); i != rep_.end(); ++i) {
    func(i.start(), i.limit(), i.value());
  }
}

inline void MappedMemoryMap::Iterate(
    std::function<void(Address start, Address limit, MemoryPerms perms)> func,
    Address start, Address limit) const {
  rep_.Covers(start, limit, [&func](Rep::const_iterator i) {
    func(i.start(), i.limit(), i.value());
    return true;
  });
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_MAPPED_MEMORY_MAP_H_
