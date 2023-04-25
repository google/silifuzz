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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_RANGE_MAP_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_RANGE_MAP_H_

#include <algorithm>  // for swap
#include <cstddef>
#include <functional>
#include <iosfwd>
#include <iostream>  // for ostream; NOLINT
#include <iterator>
#include <map>
#include <type_traits>
#include <utility>  // for pair<>

#include "./util/checks.h"

namespace silifuzz {

// RangeMap<Key, Value, Methods>, a map from half-open ranges over the Key
// data-type to the Value data type.
// Both Key and Value should support copy c-tor, equality, and << to streams.
// Methods should be a class that has the following static methods defined:
//
//   // An integer type used for usage accounting (should support + and -).
//   typedef ... Methods::Size;
//
//   // A way to convert another value type to the stored Value type.
//   // Needs to be defined only when one needs to be able to add/remove values
//   // of a different type ValueX either directly or using a
//   // RangeMap<Key, ValueX, MethodsX> object.
//   static Value Convert(ValueX v_x);
//
//   // 3-way comparison defining a total ordering on the Key type.
//   static int Methods::Compare(const Key& x, const Key& y);
//
//   // Computes usage (usually memory) of a stored [Key, Key)->Value range.
//   // Used only when callers of RangeMap<> request usage information.
//   // We make the argument const*, not const&, to make sure that no argument
//   // copying due to a slight type mismatch happens during a call.
//   static Size Methods::Usage(const pair<const pair<Key, Key>, Value>* range);
//
//   // For value `v` that is for the [start, limit) range, extracts and
//   // returns the subvalue slice for the [s, l) subrange.
//   // In the simple case when values do not split for subranges,
//   // implementation will look like this (yes, const& return type is ok too):
//   //   static const Value& Slice(..., const Value& v, ...) { return v; }
//   // REQUIRES: [start, limit) and [s, l) are non-empty and [s, l) is
//   //           fully contained in [start, limit).
//   // E.g. if Key is a byte offset and Value is std::string with the bytes
//   // for the given range of offsets, Slice() would return
//   // v.substr(s - start, l - s) to extract the appropriate bytes substring.
//   static Value Methods::Slice(const Key& start, const Key& limit,
//                               const Value& v, const Key& s, const Key& l);
//
//   // A method to incorporate Value v into Value *dest when we want to combine
//   // values from several intersecting ranges.
//   // *empty should be set to true if the record with *dest is to be deleted,
//   // but no need to touch it otherwise.
//   // Returns true iff we did add something to *dest and thus changed it.
//   // Only called when we need to combine values (hence can check for this).
//   // The implementation will move values when possible, so for performance
//   // this function can also take `v` by value or Value&& (in which case
//   // a const Value& overload might also need to be provided).
//   static bool Methods::AddTo(Value* dest, const Value& v, bool* empty);
//
//   // A method to remove Value v from Value *dest when we want to inverse
//   // the effect of an earlier AddTo().
//   // *empty should be set to true if the record with *dest is to be deleted,
//   // but no need to touch it otherwise.
//   // Returns true iff we could do this removal operation.
//   // False is forwarded to the caller of RangeMap<> to handle.
//   // Only called when we need to subtract values (hence can check for this).
//   // Same as AddTo() above in terms of the type for `v`.
//   static bool Methods::RemoveFrom(Value* dest, const Value& v, bool* empty);
//
//   // Returns true iff it is possible to merges ranges with v1 and v2
//   // in them when these ranges are adjacent.
//   // A standard implementation would be { return v1 == v2; }
//   static bool Methods::CanMerge(const Value& v1, const Value& v2);
//
//   // Do the merge of v into *dest when CanMerge(*dest, v);
//   // A standard implementation would do nothing.
//   // Same as AddTo() above in terms of the type for `v`.
//   static void Methods::Merge(Value* dest, const Value& v);
//
//   // Make *dest (is default-initialized on entry) the intersection
//   // of v1 and v2. *empty should be set to true if the record with *dest
//   // is to be deleted, but no need to touch it otherwise.
//   // One needs to define this only when one wants to use
//   // RangeMap<>::AddIntersectionOf().
//   // If one wishes to use RangeMap<>::AddIntersectionOf() with a different
//   // argument type ValueX or RangeMap<Key, ValueX, MethodsX>, then
//   // MakeIntersection() should be defined for the appropriate ValueX type(s)
//   // for the v1 and v2 arguments, plus Slice() should be defined for
//   // those ValueX type(s) as well.
//   static void Methods::MakeIntersection(Value* dest, const Value& v1,
//                                         const Value& v2, bool* empty);
//
//   // Similar to MakeIntersection() above, but for making *dest to be the
//   // difference of v2 subtracted from v1. *empty should be set to true
//   // if the record with *dest is to be deleted, but no need to touch it
//   // otherwise.
//   // One needs to define this only when one wants to use
//   // RangeMap<>::AddDifferenceOf(). Same note applies regarding arg. types.
//   // MakeDifference() should have the same effect as
//   // { *dest = v1;  RemoveFrom(dest, v2, empty); }
//   // but should if possible have time complexity better than the above.
//   static void Methods::MakeDifference(Value* dest, const Value& v1,
//                                       const Value& v2, bool* empty);
//
// RangeMap<> is not thread-safe.
// TODO(ksteuck): [design] Maybe should allow callers to specify what to use
// instead of current map<> as the representation.
template<typename Key, typename Value, typename MethodsArg>
class RangeMap {
 public:
  typedef MethodsArg Methods;
  typedef typename Methods::Size Size;

  // ----------------------------------------------------------------------- //
  // Various standard parts of an STL map<>-like container:

  typedef std::pair<Key, Key> key_type;
  typedef Value data_type;
  typedef std::pair<const key_type, data_type> value_type;
  struct key_compare {
    bool operator()(const key_type& x, const key_type& y) const {
      int s = Methods::Compare(x.first, y.first);
      return s < 0 || (s == 0 && Methods::Compare(x.second, y.second) < 0);
    }
  };
  typedef value_type* pointer;
  typedef value_type& reference;
  typedef const value_type& const_reference;
  typedef size_t size_type;
  typedef int difference_type;
  class const_iterator;
  class iterator;

  // Not STL-style:
  // (Const)IteratorRange are [,) ranges, i.e. they are empty if
  // x.first == x.second, not only if x.first == my_range_map.end().
  typedef std::pair<iterator, iterator> IteratorRange;
  typedef std::pair<const_iterator, const_iterator> ConstIteratorRange;

  // The following typedefs should not be used outside of this file. Sorry.
  typedef key_type KeyRange;
  typedef std::map<KeyRange, Value, key_compare> MapRep;
  typedef typename MapRep::iterator IterRep;
  typedef typename MapRep::const_iterator ConstIterRep;

  class iterator {
   public:
    typedef typename RangeMap::value_type value_type;
    typedef value_type& reference;
    typedef value_type* pointer;
    typedef typename IterRep::difference_type difference_type;
    typedef typename IterRep::iterator_category iterator_category;

    iterator() : rep_() { }

    iterator(const iterator& x) : rep_(x.rep_) { }
    iterator& operator=(const iterator& x) {
      rep_ = x.rep_;
      return *this;
    }

    // The [start, limit) -> value association pointed to by the iterator.
    // Not in STL style.
    const Key& start() const { return rep_->first.first; }
    const Key& limit() const { return rep_->first.second; }
    const Value& value() const { return rep_->second; }
    Value* mutable_value() { return &(rep_->second); }

    pointer operator->() const { return &(*rep_); }

    iterator& operator++() {
      ++rep_;
      return *this;
    }

    bool operator==(const iterator& x) const { return rep_ == x.rep_; }
    bool operator!=(const iterator& x) const { return rep_ != x.rep_; }

   private:
    friend class RangeMap;
    explicit iterator(const IterRep& rep) : rep_(rep) { }
    IterRep rep_;
  };

  class const_iterator {
   public:
    typedef const typename RangeMap::value_type value_type;
    typedef value_type& reference;
    typedef value_type* pointer;
    typedef typename ConstIterRep::difference_type difference_type;
    typedef typename ConstIterRep::iterator_category
        iterator_category;

    const_iterator() : rep_() { }

    const_iterator(const const_iterator& x) : rep_(x.rep_) { }
    const_iterator(const iterator& x) : rep_(x.rep_) { }  // NOLINT
    const_iterator& operator=(const const_iterator& x) {
      rep_ = x.rep_;
      return *this;
    }

    // The [start, limit) -> value association pointed to by the iterator.
    // Not in STL style.
    const Key& start() const { return rep_->first.first; }
    const Key& limit() const { return rep_->first.second; }
    const Value& value() const { return rep_->second; }

    pointer operator->() const { return &(*rep_); }
    reference operator*() const { return *rep_; }

    const_iterator& operator++() {
      ++rep_;
      return *this;
    }
    const_iterator& operator--() {
      --rep_;
      return *this;
    }

    bool operator==(const const_iterator& x) const { return rep_ == x.rep_; }
    bool operator!=(const const_iterator& x) const { return rep_ != x.rep_; }

   private:
    friend class RangeMap;
    explicit const_iterator(const ConstIterRep& rep) : rep_(rep) { }
    ConstIterRep rep_;
  };

  // Wrap std::reverse_iterator<> to provide non-STL, start(), limit(),
  // and value() methods while inheriting the rest.
  class const_reverse_iterator : public std::reverse_iterator<const_iterator> {
   private:
    typedef std::reverse_iterator<const_iterator> Rep;
   public:
    const_reverse_iterator(const const_iterator& x) : Rep(x) { }  // NOLINT
    const_reverse_iterator() : Rep() { }
    const_reverse_iterator(const const_reverse_iterator& x) : Rep(x) { }
    const_reverse_iterator& operator=(const const_reverse_iterator& x) {
      Rep::operator=(x);
      return *this;
    }

    // The [start, limit) -> value association pointed to by the iterator.
    // Not in STL style.
    const Key& limit() const { return Rep::operator*().first.second; }
  };

  iterator begin() { return iterator(map_.begin()); }
  iterator end() { return iterator(map_.end()); }

  const_iterator begin() const { return const_iterator(map_.begin()); }
  const_iterator end() const { return const_iterator(map_.end()); }

  const_reverse_iterator rbegin() const {
    return const_reverse_iterator(end());
  }

  size_type size() const { return map_.size(); }

  bool empty() const { return map_.empty(); }

  RangeMap() : map_() { }

  // There's no RangeMap(const key_compare& comp).
  template <class InputIterator>
  RangeMap(InputIterator f, InputIterator l) : map_() { insert(f, l); }
  // There's no
  // RangeMap(InputIterator f, InputIterator l, const key_compare& comp).

  // It's copyable:
  RangeMap(const RangeMap& x) : map_(x.map_) { }
  RangeMap& operator=(const RangeMap& x) {
    map_ = x.map_;
    return *this;
  }

  // Can convert from a different RangeMap<Key, ValueX, MethodsX> map type.
  template<typename ValueX, typename MethodsX>
  explicit RangeMap(const RangeMap<Key, ValueX, MethodsX>& x)
      : map_() { AddRangeMap(x); }

  // Insertion; semantics differ slightly from map<>::insert(): see Add() below.
  // 'usage' if non-NULL gets changed accordingly.
  // Note that insert() returns void.

  // Various signatures for erasing an iterator or a range.
  // 'usage' if non-NULL gets changed accordingly.
  void erase(iterator iter, Size* usage = nullptr) {
    SubUsage(iter.rep_, usage);
    map_.erase(iter.rep_);
  }
  // Same meaning as in map<>.
  void erase(iterator start, iterator limit, Size* usage = NULL) {
    if (usage) {
      for (ConstIterRep i = start.rep_; i != limit.rep_; ++i) {
        *usage -= Methods::Usage(&(*i));
      }
    }
    map_.erase(start.rep_, limit.rep_);
  }
  void erase(IteratorRange iter_range, Size* usage = NULL) {
    erase(iter_range.first, iter_range.second, usage);
  }

  void clear(Size* usage = nullptr) { erase(begin(), end(), usage); }

  // We can implement map<>-like querying primitives: find, count, lower_bound,
  // and upper_bound to have the same meaning as in map<>, but they are not
  // very useful as RangeMap<> essentially sorts Key-s, not key_type-s which
  // are ranges over Key-s. (Though do see FindAt().)
  // Find(), LowerBound(), UpperBound(), and Covers() below are more useful.

  // There's no data_type& operator[](const key_type& k).

  bool operator==(const RangeMap& x) const { return map_ == x.map_; }

  // ----------------------------------------------------------------------- //
  // Methods specific to map of ranges absent in STL containers:

  // NOTE: We use ValueX, MethodsX, ValueY, MethodsY types in the templates
  // below where we work with values and RangeMap<>-s whose values can be
  // converted to the Value type of this RangeMap<>. A common usage case is
  // when ValueX == ValueY == Value and MethodsX == MethodsY == Methods.
  // We also use value_x and value_y for variables of type ValueX and ValueY.

  // Add the knowledge that 'value' of type Value converted from value_x
  // applies to the [start, limit) range.
  // If 'usage' is non-NULL, it gets incremented and decremented accordingly.
  // post_merge determines whether Merge() is called on the affected range
  // after the addition.
  // REQUIRES: start < limit (wrt Methods::Compare)
  // Returns true iff we had added some new information to some (new) ranges,
  // i.e. iff *this changes after this call.
  // Note that for Key ranges that had no Value associated with them yet,
  // Add() will create range records with 'value' even when 'value' is empty
  // (w.r.t. how Methods::AddTo or Methods::RemoveFrom are implemented).
  // In most cases this would not make sense, so the caller would probably
  // want to check or ensure that it is not adding empty values.
  template <typename ValueX>
  bool Add(const Key& start, const Key& limit, const ValueX& value_x,
           Size* usage = nullptr, bool post_merge = true) {
    return Change(start, limit, value_x, kAdd, usage, post_merge);
  }

  // Remove the knowledge that 'value' of type Value converted from value_x
  // applies to the [start, limit) range.
  // 'usage' is non-NULL gets changed accordingly.
  // post_merge determines whether Merge() is called on the affected range
  // after the removal.
  // REQUIRES: start < limit (wrt Methods::Compare)
  // Returns true iff we had ranges covering *all* of the [start, limit) range
  // and the Value-s in each such range could successfully Methods::RemoveFrom()
  // the 'value' from themselves.
  // When false is returned we have performed the erasing on all the relevant
  // entries whenever possible (it works fine to Remove() from
  // subranges that were previously Add()-ed).
  // Remove() is aimed to remove only something that has been previously
  // Add()-ed and let the caller decide what to do when we tried to remove
  // something that was not there: it could be OK or an error.
  // Note that if Value has a notion of a sign, Add() itself can be used
  // as a more permissive version of Remove() that leaves information behind
  // when we remove something that was not there.
  template <typename ValueX>
  bool Remove(const Key& start, const Key& limit, const ValueX& value_x,
              Size* usage = nullptr, bool post_merge = true) {
    return Change(start, limit, value_x, kRemove, usage, post_merge);
  }

  // Merges, if possible, all the key ranges that are given by 'range'
  // (or the [start, limit) range) or are adjacent to this set of key ranges.
  // Updates *usage accordingly if non-NULL.
  void Merge(IteratorRange range, Size* usage = nullptr);
  void Merge(const Key& start, const Key& limit, Size* usage = nullptr) {
    Merge(Find(start, limit), usage);
  }

  // Same semantics as Add(), but for whole RangeMap-s.
  // Runs in O(range_map size + # of records of *this overlapping range_map),
  // assuming operations on values are O(1).
  template <typename ValueX, typename MethodsX>
  bool AddRangeMap(const RangeMap<Key, ValueX, MethodsX>& range_map,
                   Size* usage = nullptr, bool post_merge = true) {
    return ChangeRangeMap(range_map, kAdd, usage, post_merge);
  }

  // Same semantics as Remove(), but for whole RangeMap-s.
  // Runs in O(range_map size + # of records of *this overlapping range_map),
  // assuming operations on values are O(1).
  template <typename ValueX, typename MethodsX>
  bool RemoveRangeMap(const RangeMap<Key, ValueX, MethodsX>& range_map,
                      Size* usage = nullptr, bool post_merge = true) {
    return ChangeRangeMap(range_map, kRemove, usage, post_merge);
  }

  // Same semantics as Add(), but adds 'value' of type Value converted
  // from value_x to each existing RangeMap<> entry.
  // value_x is treated as covering the whole range of keys in *this:
  //   [begin().start(), rbegin().limit())
  // in terms of applying Methods::Slice() to it.
  template <typename ValueX>
  bool AddToEach(const ValueX& value_x, Size* usage = nullptr) {
    return ChangeEach(value_x, kAdd, usage);
  }

  // Same semantics as Remove(), but removes 'value' of type Value converted
  // from value_x from each existing RangeMap<> entry.
  // value_x is treated as covering the whole range of keys in *this in terms
  // of applying Methods::Slice() to it.
  template <typename ValueX>
  bool RemoveFromEach(const ValueX& value_x, Size* usage = nullptr) {
    return ChangeEach(value_x, kRemove, usage);
  }

  // Sum of Methods::Usage() over the stored ranges.
  Size Usage() const {
    Size usage = 0;
    for (ConstIterRep i = map_.begin(); i != map_.end(); ++i) {
      usage += Methods::Usage(&(*i));
    }
    return usage;
  }

  // LowerBound() returns the first iterator of the range that overlaps
  // or starts after the Key given.
  iterator LowerBound(const Key& k) {
    IterRep i = map_.lower_bound({k, k});
    if (i != map_.begin()) {
      IterRep p = i;
      --p;
      if (Methods::Compare(p->first.second, k) > 0) return iterator(p);
    }
    return iterator(i);
  }
  const_iterator LowerBound(const Key& k) const {
    ConstIterRep i = map_.lower_bound({k, k});
    if (i != map_.begin()) {
      ConstIterRep p = i;
      --p;
      if (Methods::Compare(p->first.second, k) > 0) return const_iterator(p);
    }
    return const_iterator(i);
  }

  // UpperBound() returns the iterator after the last range that overlaps
  // or ends before the Key given.
  iterator UpperBound(const Key& k) {
    return iterator(map_.upper_bound({k, k}));
  }
  const_iterator UpperBound(const Key& k) const {
    return const_iterator(map_.upper_bound({k, k}));
  }

  // Find the [,) range of iterators that covers all the range->value
  // mappings for all the key ranges that overlap the [start, limit) range.
  // Note that (only) the first and last key ranges inside the returned iterator
  // range may extend beyond 'start' and 'limit' respectively.
  // The returned ranges are not overlapping and are ordered according to
  // Methods::Compare().
  // REQUIRES: start <= limit (wrt Methods::Compare)
  IteratorRange Find(const Key& start, const Key& limit) {
    int cmp = Methods::Compare(start, limit);
    CHECK_LE(cmp, 0);  // << start << " !<= " << limit;
    if (cmp >= 0) return {end(), end()};
    return {LowerBound(start), UpperBound(limit)};
  }
  ConstIteratorRange Find(const Key& start, const Key& limit) const {
    int cmp = Methods::Compare(start, limit);
    CHECK_LE(cmp, 0);  // << start << " !<= " << limit;
    if (cmp >= 0) return {end(), end()};
    return {LowerBound(start), UpperBound(limit)};
  }

  IteratorRange FindAll() {
    return {begin(), end()};
  }
  ConstIteratorRange FindAll() const {
    return {begin(), end()};
  }

  // Returns the iterator for the range->value mapping containing key if it
  // exists, or end() if key is in no range with a value.
  iterator FindAt(const Key& key) {
    IterRep i = map_.upper_bound({key, key});
    if (i != map_.end()) {
      // Let i = [x, y). Since i > [key, key), either (a) x > key or (b) x = key
      // and y > key.  In case (a), key is not in this interval (but may be in a
      // previous one). In case (b), key is in this interval (it is the start of
      // the interval, even).
      if (Methods::Compare(i->first.first, key) == 0) return iterator(i);
    }
    if (i == map_.begin()) return end();  // key comes before all intervals.
    --i;
    // By the definition of upper_bound, we know that i->first <= (key, key),
    // and so i->first.first <= key.  So either i contains key, or key falls
    // strictly between the current value of i and the value i had before --i.
    if (Methods::Compare(i->first.second, key) <= 0) return end();
    return iterator(i);
  }
  const_iterator FindAt(const Key& key) const {
    ConstIterRep i = map_.upper_bound({key, key});
    if (i != map_.end()) {
      if (Methods::Compare(i->first.first, key) == 0) return const_iterator(i);
    }
    if (i == map_.begin()) return end();
    --i;
    if (Methods::Compare(i->first.second, key) <= 0) return end();
    return const_iterator(i);
  }

  // This is a method to iterate over everything in the Find(start, limit)
  // iterator range and apply the 'accumulator' function to all the ranges seen
  // while possibly accumulating some interesting information.
  // The returned bool is a logical-and of the following:
  // * All the return values of 'accumulator' invocations.
  // * The condition that the whole [start, limit) range is contiguously covered
  //   by the Key ranges contained in *this.
  // Usage ideas: Using a trivial true-returning accumulator one can check if
  // all of a given range is covered by a RangeMap or not. A slightly more
  // involved accumulator can help distinguish the something-is- vs
  // nothing-is-covered cases. An accumulator also helps if the coverage
  // we are interested in depends a lot on the values associated with the
  // stored Key ranges.
  bool Covers(const Key& start, const Key& limit,
              std::function<bool(const_iterator i)> accumulator) const;

  // Adds the intersection of map_x and [start, limit)->value_y to *this.
  // Adjusts *usage appropriately if non-NULL.
  // Runs in O(# of records of map_x overlapping the [start, limit) range),
  // assuming operations on values are O(1).
  // post_merge determines whether Merge() is called on the affected range
  // after the addition.
  template<typename ValueX, typename MethodsX, typename ValueY>
  void AddIntersectionOf(const RangeMap<Key, ValueX, MethodsX>& map_x,
                         const Key& start, const Key& limit,
                         const ValueY& value_y,
                         Size* usage = NULL, bool post_merge = true);

  // Adds the intersection of map_x and map_y to *this.
  // Adjusts *usage appropriately if non-NULL.
  // Runs in O(map_y size + # of records of map_x overlapping map_y records),
  // assuming operations on values are O(1).
  template <typename ValueX, typename MethodsX, typename ValueY,
            typename MethodsY>
  void AddIntersectionOf(const RangeMap<Key, ValueX, MethodsX>& map_x,
                         const RangeMap<Key, ValueY, MethodsY>& map_y,
                         Size* usage = nullptr, bool post_merge = true) {
    for (typename RangeMap<Key, ValueY, MethodsY>::const_iterator
         i = map_y.begin(); i != map_y.end(); ++i) {
      AddIntersectionOf(map_x, i.start(), i.limit(), i.value(),
                        usage, post_merge);
    }
  }

  // Adds the difference of map_y from [start, limit)->value_x to *this.
  // Adjusts *usage appropriately if non-NULL.
  // Runs in O(# of records of map_y overlapping the [start, limit) range),
  // assuming operations on values are O(1).
  // post_merge determines whether Merge() is called on the affected range
  // after the addition.
  template<typename ValueX, typename ValueY, typename MethodsY>
  void AddDifferenceOf(const Key& start, const Key& limit,
                       const ValueX& value_x,
                       const RangeMap<Key, ValueY, MethodsY>& map_y,
                       Size* usage = NULL, bool post_merge = true);

  // Adds the difference of map_y from map_x to *this.
  // Adjusts *usage appropriately if non-NULL.
  // Runs in O(map_x size + # of records of map_y overlapping map_x records),
  // assuming operations on values are O(1).
  template <typename ValueX, typename MethodsX, typename ValueY,
            typename MethodsY>
  void AddDifferenceOf(const RangeMap<Key, ValueX, MethodsX>& map_x,
                       const RangeMap<Key, ValueY, MethodsY>& map_y,
                       Size* usage = nullptr, bool post_merge = true) {
    for (typename RangeMap<Key, ValueX, MethodsX>::const_iterator
         i = map_x.begin(); i != map_x.end(); ++i) {
      AddDifferenceOf(i.start(), i.limit(), i.value(), map_y,
                      usage, post_merge);
    }
  }

  // Logging helper: Logs contents of this RangeMap to *stream prefixing
  // each line with line_prefix.
  void LogTo(std::ostream* stream, const char* line_prefix) const {
    for (const_iterator i = begin(); i != end(); ++i) {
      (*stream) << line_prefix << "[ " << i.start() << " .. "
                << i.limit() << " ) : " << i.value() << "\n";
    }
  }

 private:
  enum ChangeMode { kAdd, kRemove };  // for various Change*() methods below.

  // Implements Add() and Remove().
  // post_merge determines whether Merge() is called on the affected range
  // after the addition/removal.
  template<typename ValueX>
  bool Change(const Key& start, const Key& limit, const ValueX& value_x,
              ChangeMode mode, Size* usage, bool post_merge);

  // Implements AddToEach() and RemoveFromEach().
  template<typename ValueX>
  bool ChangeEach(const ValueX& value_x, ChangeMode mode, Size* usage);

  // Implements AddRangeMap() and RemoveRangeMap().
  // post_merge determines whether Merge() is called on the affected range
  // after the addition/removal.
  template<typename ValueX, typename MethodsX>
  bool ChangeRangeMap(const RangeMap<Key, ValueX, MethodsX>& range_map,
                      ChangeMode mode, Size* usage, bool post_merge);

  // Converts value of another type ValueX to Value.
  // Need to make it a struct to make C++ allow us to specialize it.
  // is_same is true if ValueX is the same type as Value.
  template<typename ValueX, bool is_same> struct Convertor;

  // Helpers to adding/subtracting from *usage.
  void AddUsage(const IterRep& iter, Size* usage) {
    if (usage) *usage += Methods::Usage(&(*iter));
  }
  void SubUsage(const IterRep& iter, Size* usage) {
    if (usage) *usage -= Methods::Usage(&(*iter));
  }

  // Adds or removes 'value' to/from *dest depending on 'add'
  // and falsifies *result if could not do the removal
  // or respectively makes *result true if addition has changed something.
  // Returns true iff the record with the resulting *dest is to be kept.
  template <typename ValueT>
  bool ChangeValue(Value* dest, ValueT&& value, ChangeMode mode, bool* result) {
    bool empty = false;
    if (mode == kAdd) {
      if (Methods::AddTo(dest, std::forward<ValueT>(value), &empty))
        *result = true;
    } else {
      if (!Methods::RemoveFrom(dest, std::forward<ValueT>(value), &empty))
        *result = false;
    }
    return !empty;
  }

  MapRep map_;
};

// ========================================================================= //

// Default implementation for logging.
template <typename Key, typename Value, typename Methods>
std::ostream& operator<<(std::ostream& stream,
                         const RangeMap<Key, Value, Methods>& range_map) {
  range_map.LogTo(&stream, "");
  return stream;
}

// ========================================================================= //

template<typename Key, typename Value, typename Methods>
template<typename ValueX>  // ValueX is always Value here
struct RangeMap<Key, Value, Methods>::Convertor<ValueX, true> {
  static const Value& Convert(const Value& value) { return value; }
};

template<typename Key, typename Value, typename Methods>
template<typename ValueX>
struct RangeMap<Key, Value, Methods>::Convertor<ValueX, false> {
  static Value Convert(const ValueX& value_x) {
    return Methods::Convert(value_x);
  }
};

template <typename Key, typename Value, typename Methods>
template <typename ValueX>
bool RangeMap<Key, Value, Methods>::Change(const Key& start, const Key& limit,
                                           const ValueX& value_x,
                                           ChangeMode mode, Size* usage,
                                           bool post_merge) {
  CHECK_LT(Methods::Compare(start, limit), 0);  // << start << " !< " << limit;
  // This can be a reference to a temporary, but compiler extends the life of
  // the temporary to match that of the reference:
  const Value& value =
      Convertor<ValueX, std::is_same<ValueX, Value>::value>::Convert(value_x);
  bool result = mode == kRemove;
  IteratorRange range = Find(start, limit);
  Key prev_start = start;
  for (iterator i(range.first); i != range.second;) {
    // Split up the range behind i as affected by this Change():
    int s = Methods::Compare(prev_start, i.start());
    int l = Methods::Compare(limit, i.limit());
    if (s < 0) {  // we start before *i
      if (mode == kAdd) {
        auto v = Methods::Slice(start, limit, value, prev_start, i.start());
        IterRep n =
            map_.emplace(KeyRange(prev_start, i.start()), std::move(v)).first;
        AddUsage(n, usage);
        result = true;
      } else {
        result = false;
      }
    }
    prev_start = i.limit();
    if (s <= 0 && l >= 0) {  // new range covers all of *i
      SubUsage(i.rep_, usage);
      auto v = Methods::Slice(start, limit, value, i.start(), i.limit());
      if (!ChangeValue(i.mutable_value(), std::move(v), mode, &result)) {
        IterRep n = i.rep_;
        ++i;
        map_.erase(n);
        continue;
      }
      AddUsage(i.rep_, usage);
    } else if (s <= 0 && l < 0) {  // new range covers a prefix of *i
      auto i_v1 =
          Methods::Slice(i.start(), i.limit(), i.value(), i.start(), limit);
      IterRep n =
          map_.emplace(KeyRange(i.start(), limit), std::move(i_v1)).first;
      auto v = Methods::Slice(start, limit, value, i.start(), limit);
      if (!ChangeValue(&n->second, std::move(v), mode, &result)) {
        map_.erase(n);
      } else {
        AddUsage(n, usage);
      }
      auto i_v2 =
          Methods::Slice(i.start(), i.limit(), i.value(), limit, i.limit());
      n = map_.emplace(KeyRange(limit, i.limit()), std::move(i_v2)).first;
      AddUsage(n, usage);
      SubUsage(i.rep_, usage);
      map_.erase(i.rep_);
      i.rep_ = n;
    } else if (s > 0 && l < 0) {  // new range covers a subrange of *i
      auto i_v1 =
          Methods::Slice(i.start(), i.limit(), i.value(), i.start(), start);
      IterRep n =
          map_.emplace(KeyRange(i.start(), start), std::move(i_v1)).first;
      AddUsage(n, usage);
      auto i_v2 = Methods::Slice(i.start(), i.limit(), i.value(), start, limit);
      n = map_.emplace(KeyRange(start, limit), std::move(i_v2)).first;
      // [start, limit) range, so no need to Methods::Slice() for `value`:
      if (!ChangeValue(&n->second, value, mode, &result)) {
        map_.erase(n);
      } else {
        AddUsage(n, usage);
      }
      auto i_v3 =
          Methods::Slice(i.start(), i.limit(), i.value(), limit, i.limit());
      n = map_.emplace(KeyRange(limit, i.limit()), i_v3).first;
      AddUsage(n, usage);
      SubUsage(i.rep_, usage);
      map_.erase(i.rep_);
      i.rep_ = n;
    } else if (s > 0 && l >= 0) {  // new range covers a suffix of *i
      auto i_v1 =
          Methods::Slice(i.start(), i.limit(), i.value(), i.start(), start);
      IterRep n0 =
          map_.emplace(KeyRange(i.start(), start), std::move(i_v1)).first;
      AddUsage(n0, usage);
      auto i_v2 =
          Methods::Slice(i.start(), i.limit(), i.value(), start, i.limit());
      IterRep n =
          map_.emplace(KeyRange(start, i.limit()), std::move(i_v2)).first;
      auto v = Methods::Slice(start, limit, value, start, i.limit());
      if (!ChangeValue(&n->second, std::move(v), mode, &result)) {
        map_.erase(n);
        n = n0;
      } else {
        AddUsage(n, usage);
      }
      SubUsage(i.rep_, usage);
      map_.erase(i.rep_);
      i.rep_ = n;
    }
    ++i;
  }
  if (Methods::Compare(prev_start, limit) < 0) {
    if (mode == kAdd) {
      auto v = Methods::Slice(start, limit, value, prev_start, limit);
      IterRep n = map_.emplace(KeyRange(prev_start, limit), std::move(v)).first;
      AddUsage(n, usage);
      result = true;
    } else {
      result = false;
    }
  }
  // Now we go over the same key range and try to merge
  // all the possibly modified ranges->value mappings with neighbors.
  if (post_merge) Merge(Find(start, limit), usage);
  return result;
}

template<typename Key, typename Value, typename Methods>
template<typename ValueX>
bool RangeMap<Key, Value, Methods>::ChangeEach(
    const ValueX& value_x, ChangeMode mode, Size* usage) {
  // This can be a reference to a temporary, but compiler extends the life of
  // the temporary to match that of the reference:
  const Value& value =
      Convertor<ValueX, std::is_same<ValueX, Value>::value>::Convert(value_x);
  bool result = mode == kRemove;
  if (empty()) return result;
  const Key start = begin().start();
  const Key limit = rbegin().limit();
  for (IterRep i = map_.begin(); i != map_.end(); /* incremented below */) {
    SubUsage(i, usage);
    auto v = Methods::Slice(start, limit, value, iterator(i).start(),
                            iterator(i).limit());
    if (!ChangeValue(&i->second, std::move(v), mode, &result)) {
      IterRep c = i;
      ++i;
      map_.erase(c);
    } else {
      AddUsage(i, usage);
      ++i;
    }
  }
  // Now we go over the whole key range and try to merge
  // all the possibly modified ranges->value mappings with neighbors.
  Merge(FindAll(), usage);
  return result;
}

template<typename Key, typename Value, typename Methods>
template<typename ValueX, typename MethodsX>
bool RangeMap<Key, Value, Methods>::ChangeRangeMap(
    const RangeMap<Key, ValueX, MethodsX>& range_map, ChangeMode mode,
    Size* usage, bool post_merge) {
  // TODO(ksteuck): [perf] Here, in AddIntersectionOf(), and in
  // AddDifferenceOf() it can be useful to let the caller provide
  // the value for merge_whole_range.
  // Making it true will help if range_map is much denser than its range
  // in *this. But doing that can be dangerous, because merging complexity
  // becomes O(# of elements in the affected range of *this) instead of
  // O(# of elements in range_map).
  const bool merge_whole_range = false;
  // TODO(ksteuck): [perf] Optimize this to take advantage of the fact
  // that the ranges in range_map are non-overlapping and ordered:
  // Maybe can speed-up range search in Change() a little.
  bool result = mode == kRemove;
  for (typename RangeMap<Key, ValueX, MethodsX>::const_iterator
       i = range_map.begin(); i != range_map.end(); ++i) {
    const bool changed = Change(i.start(), i.limit(), i.value(),
                                mode, usage, !merge_whole_range && post_merge);
    if (mode == kAdd) {
      if (changed) result = true;
    } else {
      if (!changed) result = false;
    }
  }
  if (merge_whole_range && post_merge && !range_map.empty()) {
    Merge(Find(range_map.begin().start(), range_map.rbegin().limit()), usage);
  }
  return result;
}

template<typename Key, typename Value, typename Methods>
void RangeMap<Key, Value, Methods>::Merge(IteratorRange range, Size* usage) {
  if (range.second != end()) ++range.second;  // to merge with what's after
  IterRep prev = range.first.rep_;
  if (range.first != begin()) {
    --prev;  // to merge with what's before
  } else {
    if (range.first == range.second) return;  // no pairs to merge
    ++range.first;
  }
  for (IterRep iter = range.first.rep_; iter != range.second.rep_; ++iter) {
    // Loop invariant: ++prev == iter.
    if (Methods::Compare(prev->first.second, iter->first.first) == 0 &&
        Methods::CanMerge(prev->second, iter->second)) {
      SubUsage(prev, usage);
      SubUsage(iter, usage);
      Methods::Merge(&(prev->second), iter->second);
      Key new_limit = iter->first.second;
      map_.erase(iter);
      // This mutation does not change the ordering of prev in map_, so is safe.
      const_cast<key_type&>(prev->first).second = new_limit;
      AddUsage(prev, usage);
      iter = prev;
    } else {
      prev = iter;
    }
  }
}

template <typename Key, typename Value, typename Methods>
bool RangeMap<Key, Value, Methods>::Covers(
    const Key& start, const Key& limit,
    std::function<bool(const_iterator i)> accumulator) const {
  ConstIteratorRange range = Find(start, limit);
  if (range.first == range.second) return Methods::Compare(start, limit) == 0;
  bool result = true;
  Key prev = start;
  for (const_iterator i = range.first; i != range.second; ++i) {
    if (Methods::Compare(i.start(), prev) > 0) result = false;  // coverage gap
    if (!accumulator(i)) result = false;  // insufficient range+Value
    prev = i.limit();
  }
  if (Methods::Compare(prev, limit) < 0) result = false;  // coverage gap
  return result;
}

template<typename Key, typename Value, typename Methods>
template<typename ValueX, typename MethodsX, typename ValueY>
void RangeMap<Key, Value, Methods>::AddIntersectionOf(
    const RangeMap<Key, ValueX, MethodsX>& map_x,
    const Key& start, const Key& limit, const ValueY& value_y,
    Size* usage, bool post_merge) {
  // merge_whole_range is explained in ChangeRangeMap() above.
  const bool merge_whole_range = false;
  typename RangeMap<Key, ValueX, MethodsX>::ConstIteratorRange range
      = map_x.Find(start, limit);
  for (typename RangeMap<Key, ValueX, MethodsX>::const_iterator
       i = range.first; i != range.second; ++i) {
    const Key s = Methods::Compare(start, i.start()) < 0 ? i.start() : start;
    const Key l = Methods::Compare(i.limit(), limit) < 0 ? i.limit() : limit;
    auto i_v = Methods::Slice(i.start(), i.limit(), i.value(), s, l);
    auto v_y = Methods::Slice(start, limit, value_y, s, l);
    bool empty = false;
    Value intersection;
    Methods::MakeIntersection(&intersection, i_v, v_y, &empty);
    if (!empty) {
      Change(s, l, std::move(intersection), kAdd, usage,
             !merge_whole_range && post_merge);
    }
  }
  if (merge_whole_range && post_merge) Merge(Find(start, limit), usage);
}

template<typename Key, typename Value, typename Methods>
template<typename ValueX, typename ValueY, typename MethodsY>
void RangeMap<Key, Value, Methods>::AddDifferenceOf(
    const Key& start, const Key& limit, const ValueX& value_x,
    const RangeMap<Key, ValueY, MethodsY>& map_y,
    Size* usage, bool post_merge) {
  // merge_whole_range is explained in ChangeRangeMap() above.
  const bool merge_whole_range = false;
  typename RangeMap<Key, ValueY, MethodsY>::ConstIteratorRange range
      = map_y.Find(start, limit);
  Key prev = start;
  for (typename RangeMap<Key, ValueY, MethodsY>::const_iterator
       i = range.first; i != range.second; ++i) {
    const Key s = Methods::Compare(start, i.start()) < 0 ? i.start() : start;
    const Key l = Methods::Compare(i.limit(), limit) < 0 ? i.limit() : limit;
    auto i_v = Methods::Slice(i.start(), i.limit(), i.value(), s, l);
    auto v_x = Methods::Slice(start, limit, value_x, s, l);
    bool empty = false;
    {
      Value difference;
      Methods::MakeDifference(&difference, v_x, i_v, &empty);
      if (!empty) {
        Change(s, l, std::move(difference), kAdd, usage,
               !merge_whole_range && post_merge);
      }
    }
    if (Methods::Compare(prev, i.start()) < 0) {
      auto v_x = Methods::Slice(start, limit, value_x, prev, i.start());
      Change(prev, i.start(), std::move(v_x), kAdd, usage,
             !merge_whole_range && post_merge);
    }
    prev = i.limit();
  }
  if (Methods::Compare(prev, limit) < 0) {
    auto v_x = Methods::Slice(start, limit, value_x, prev, limit);
    Change(prev, limit, std::move(v_x), kAdd, usage,
           !merge_whole_range && post_merge);
  }
  if (merge_whole_range && post_merge) Merge(Find(start, limit), usage);
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_RANGE_MAP_H_
