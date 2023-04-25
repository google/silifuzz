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

#ifndef THIRD_PARTY_SILIFUZZ_MEMORY_BYTES_SET_H_
#define THIRD_PARTY_SILIFUZZ_MEMORY_BYTES_SET_H_

#include <functional>
#include <optional>
#include <utility>

#include "./common/snapshot_enums.h"
#include "./util/range_map.h"

namespace silifuzz {

// A MemoryBytesSet is a set of right-opened memory address ranges of the form
// [start, limit) that are guaranteed to be minimal, i.e. any touching address
// ranges are coalesced into a single range.
//
// This class is thread-unsafe.
class MemoryBytesSet {
 public:
  using ByteSize = snapshot_types::ByteSize;
  using Address = snapshot_types::Address;

  MemoryBytesSet() = default;
  ~MemoryBytesSet() = default;

  // Copyable and movable.
  MemoryBytesSet(const MemoryBytesSet&) = default;
  MemoryBytesSet(MemoryBytesSet&&) = default;
  MemoryBytesSet& operator=(const MemoryBytesSet&) = default;
  MemoryBytesSet& operator=(MemoryBytesSet&&) = default;

  // Whether *this has no data.
  bool empty() const { return rep_.empty(); }

  // Resets *this to post-construction empty() state.
  void clear() { rep_.clear(); }

  // Size of the set as the number of non-touching memory ranges.
  ByteSize size() const { return rep_.size(); }

  // Number of bytes represented by *this.
  ByteSize byte_size() const;

  // Comparison operators.
  bool operator==(const MemoryBytesSet& y) const { return rep_ == y.rep_; }
  bool operator!=(const MemoryBytesSet& y) const { return !(*this == y); }

  // Adds memory address range [start_address, limit_address). If the range
  // overlaps with any existing range, it is coalesced.
  void Add(Address start_address, Address limit_address);

  // Whole-set version of Add().
  void Add(const MemoryBytesSet& y);

  // Removes memory address range [start_address, limit_address).
  void Remove(Address start_address, Address limit_address);

  // Modifies *this so that it contains only those addresses that are
  // currently present both in *this and in `y`.
  void Intersect(const MemoryBytesSet& y);

  // Returns true iff no data in *this overlaps the given range.
  bool IsDisjoint(Address start_address, Address limit_address) const;

  // Runs `func` for every address range of *this.
  // A poor man's iterator interface.
  void Iterate(std::function<void(Address start, Address limit)> func) const;

 private:
  // We use a map to simulate a set and we do not care about what mapped
  // values are.
  static constexpr bool kDummyMappedValue = false;

  // Methods to define a RangeMap<> instance below that maps the Address
  // ranges to bool.  We use a map to simulate a set as RangeMap is already
  // available. This could also be implemented using boost::icl::interval_set.
  //
  // See RangeMap<> for the requirements on the "Methods" class needed by it.
  class MemoryBytesSetMethods {
   public:
    using Key = Address;
    // We do not care about mapped vaule.  Choose type with the smallest size.
    using Value = bool;
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

    // We don't care about mapped value.  So no need to do anything here
    // to combine value.
    static bool AddTo(Value* dest, const Value& v, bool* empty) {
      *dest = kDummyMappedValue;
      return false;  // We do not change *dest.
    }

    // Removal does not depend on mapped value.
    static bool RemoveFrom(Value* dest, const Value& v, bool* empty) {
      *dest = kDummyMappedValue;
      *empty = true;
      return true;  // We can delete it.
    }

    // We can always merge two ranges.
    static bool CanMerge(const Value& v1, const Value& v2) { return true; }

    // We don't care about mapped value so this is a NOP.
    static void Merge(Value* dest, const Value& v) {
      *dest = kDummyMappedValue;
    }

    // Intersection is always non-empty.
    static void MakeIntersection(Value* dest, const Value& v1, const Value& v2,
                                 bool* empty) {
      *dest = kDummyMappedValue;
      *empty = false;
    }

    // We define "difference" dissimilar to RemoveFrom(): A value is kept
    // (with v1-v2, which could be MemoryPerms::None()) iff v1 != v2. This is
    // used by RangeMap::AddDifferenceOf(), which does not use RemoveFrom(),
    // so the slightly different behavior of the two is fine.
    static void MakeDifference(Value* dest, const Value& v1, const Value& v2,
                               bool* empty) {
      *empty = true;
    }
  };

  using Rep = RangeMap<MemoryBytesSetMethods::Key, MemoryBytesSetMethods::Value,
                       MemoryBytesSetMethods>;
  Rep rep_;
};

// ----------------------------------------------------------------------- //

// Inline to help compiler optimize it away.
inline void MemoryBytesSet::Iterate(
    std::function<void(Address start, Address limit)> func) const {
  for (auto i = rep_.begin(); i != rep_.end(); ++i) {
    func(i.start(), i.limit());
  }
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_MEMORY_BYTES_SET_H_
