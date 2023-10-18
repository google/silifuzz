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

#include "./util/range_map.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/random/random.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "./util/checks.h"

// Similar to std::size() but works for {}.
#define SILIFUZZ_ARRAYSIZE(a)   \
  ((sizeof(a) / sizeof(*(a))) / \
   static_cast<size_t>(!(sizeof(a) % sizeof(*(a)))))

namespace silifuzz {
namespace {

// Controls some minor behavior differences in NumMethods<>.
static bool more_is_empty_mode = true;

template <typename Type>
class NumMethods {
 public:
  typedef Type Value;
  typedef int32_t Key;
  typedef int Size;

  static int Compare(const Key& x, const Key& y) { return x - y; }

  static Size Usage(const std::pair<const std::pair<Key, Key>, Value>* range) {
    return (range->first.second - range->first.first) *
           (more_is_empty_mode ? range->second : range->second + 1);
  }

  // TODO(ksteuck): [test] Add a comprehensive test for a usage scenario when
  // Slice() is non-trivial: smth like NumMethods<std::string>.
  static const Value& Slice(const Key& start, const Key& limit, const Value& v,
                            const Key& s, const Key& l) {
    DCHECK_LE(start, s);
    DCHECK_LT(s, l);
    DCHECK_LE(l, limit);
    return v;
  }

  static bool AddTo(Value* dest, const Value& v, bool* empty) {
    Value prev = *dest;
    if (more_is_empty_mode) {
      *dest += v;
      *empty = *dest == 0;
    } else {
      *dest *= v;
    }
    return *dest != prev;
  }

  static bool RemoveFrom(Value* dest, const Value& v, bool* empty) {
    *dest -= v;
    bool removed = *dest >= 0;
    if (more_is_empty_mode && !removed) *dest = 0;
    *empty = *dest == 0;
    return removed;
  }

  static bool CanMerge(const Value& v1, const Value& v2) { return v1 == v2; }

  static void Merge(Value* dest, const Value& v) {}

  // Our "intersection" is min. In the more_is_empty_mode we also decrement,
  // so that we can test that an intersection (with 1) that turns out
  // to be empty is deleted from the map.
  static void MakeIntersection(Value* dest, const Value& v1, const Value& v2,
                               bool* empty) {
    *dest = std::min(v1, v2) - (more_is_empty_mode ? 1 : 0);
    *empty = *dest == 0;
  }

  // Our "difference" is numerical difference. In the more_is_empty_mode
  // negative values are also treated as 0 (i.e. empty).
  static void MakeDifference(Value* dest, const Value& v1, const Value& v2,
                             bool* empty) {
    *dest = more_is_empty_mode ? std::max(v1 - v2, 0) : v1 - v2;
    *empty = *dest == 0;
  }
};

typedef NumMethods<int> IntMethods;
typedef RangeMap<IntMethods::Key, IntMethods::Value, IntMethods> IntRangeMap;

// ========================================================================= //

struct Range {
  IntMethods::Key start;
  IntMethods::Key limit;
  IntMethods::Value value;
};

template <typename ThisRangeMap>
static IntMethods::Size ExpectNumMap(
    const ThisRangeMap& ignored_map,  // for type inference
    const typename ThisRangeMap::ConstIteratorRange& range, Range expected[],
    int size) {
  int i = 0;
  IntMethods::Size usage = 0;
  for (typename ThisRangeMap::const_iterator r(range.first); r != range.second;
       ++r) {
    CHECK_LT(i, size);
    EXPECT_EQ(expected[i].start, r.start());
    EXPECT_EQ(expected[i].limit, r.limit());
    EXPECT_EQ(expected[i].value, r.value());
    ++i;
    usage += ThisRangeMap::Methods::Usage(&(*r));
  }
  EXPECT_EQ(i, size);
  return usage;
}

#define EXPECT_NUM_RANGE_EQ(map, from, to, values...)                     \
  {                                                                       \
    SCOPED_TRACE("EXPECT_NUM_RANGE_EQ");                                  \
    Range expected[] = values;                                            \
    ExpectNumMap(map, map.Find(from, to), expected,                       \
                 SILIFUZZ_ARRAYSIZE(expected));                           \
    ExpectNumMap(map, const_cast<const IntRangeMap&>(map).Find(from, to), \
                 expected, SILIFUZZ_ARRAYSIZE(expected));                 \
  }

// This is just for reducing the EXPECT_NUM_MAP_EQ macro below (else gcc
// complains that we have too large stack frame in the test case function).
template <typename Key, typename Value, typename Methods>
static void ExpectNumMapEq(RangeMap<Key, Value, Methods>* map,
                           IntMethods::Size usage, Range expected[], int size) {
  typedef RangeMap<Key, Value, Methods> ThisRangeMap;
  EXPECT_EQ(usage, ExpectNumMap(*map, map->FindAll(), expected, size));
  EXPECT_EQ(usage, ExpectNumMap(*map,
                                typename ThisRangeMap::IteratorRange(
                                    map->begin(), map->end()),
                                expected, size));
  EXPECT_EQ(usage,
            ExpectNumMap(*map, const_cast<const ThisRangeMap*>(map)->FindAll(),
                         expected, size));
  EXPECT_EQ(usage, map->Usage());
  EXPECT_EQ(map->empty(), size == 0);
  EXPECT_EQ(map->size(), size);
}

#define EXPECT_NUM_MAP_EQ(map, usage, values...)                         \
  {                                                                      \
    SCOPED_TRACE("EXPECT_NUM_MAP_EQ");                                   \
    Range expected[] = values;                                           \
    ExpectNumMapEq(&map, usage, expected, SILIFUZZ_ARRAYSIZE(expected)); \
  }

template <typename Key, typename Value, typename Methods>
static void ExpectFindAtHasValue(RangeMap<Key, Value, Methods>* m, const Key& k,
                                 const Value& v) {
  SCOPED_TRACE(absl::StrCat(k, " should map to ", v));
  // Test both const and non-const versions.
  typename RangeMap<Key, Value, Methods>::iterator it = m->FindAt(k);
  EXPECT_TRUE(it != m->end());
  EXPECT_EQ(it->second, v);
  const RangeMap<Key, Value, Methods>* c_m = m;
  typename RangeMap<Key, Value, Methods>::const_iterator c_it = c_m->FindAt(k);
  EXPECT_TRUE(c_it != c_m->end());
  EXPECT_EQ(c_it->second, v);
}

template <typename Key, typename Value, typename Methods>
static void ExpectFindAtHasNoValue(RangeMap<Key, Value, Methods>* m,
                                   const Key& k) {
  SCOPED_TRACE(absl::StrCat(k, " should map to nothing"));
  // Test both const and non-const versions.
  typename RangeMap<Key, Value, Methods>::iterator it = m->FindAt(k);
  EXPECT_TRUE(it == m->end());
  const RangeMap<Key, Value, Methods>* c_m = m;
  typename RangeMap<Key, Value, Methods>::const_iterator c_it = c_m->FindAt(k);
  EXPECT_TRUE(c_it == c_m->end());
}

struct CoversInfo {
  IntMethods::Value lower_value_limit;
  IntMethods::Value value_sum;

  void Init(IntMethods::Value limit) {
    lower_value_limit = limit;
    value_sum = 0;
  }
};

static bool Adder(IntRangeMap::const_iterator i, CoversInfo* info) {
  info->value_sum += i.value();
  return i.value() >= info->lower_value_limit;
}

// ========================================================================= //

TEST(RangeMapDeathTest, All) {
  IntRangeMap map;
  EXPECT_TRUE(map.empty());

  EXPECT_TRUE(map.Add(10, 11, 0));  // empty value gets stored fine:
  EXPECT_NUM_MAP_EQ(map, 0, {{10, 11, 0}});
  EXPECT_DEATH(map.Add(10, 10, 100), "");  // empty range
  EXPECT_DEATH(map.Add(20, 10, 100), "");  // bad range

  // One range:
  EXPECT_TRUE(map.Add(10, 11, 50));
  EXPECT_TRUE(map.Add(10, 11, 50));
  EXPECT_NUM_MAP_EQ(map, 100, {{10, 11, 100}});

  EXPECT_TRUE(map.Remove(10, 11, 0));
  EXPECT_DEATH(map.Remove(10, 10, 100), "");  // empty range
  EXPECT_DEATH(map.Remove(20, 10, 100), "");  // bad range

  EXPECT_NUM_MAP_EQ(map, 100, {{10, 11, 100}});
  EXPECT_TRUE(map.Remove(10, 11, 100));
  EXPECT_TRUE(map.empty());
  EXPECT_NUM_MAP_EQ(map, 0, {});

  // Add() non-overlapping ranges:
  IntMethods::Size usage = 0;
  EXPECT_TRUE(map.Add(40, 45, 400, &usage));
  EXPECT_TRUE(map.Add(10, 12, 100, &usage));
  EXPECT_TRUE(map.Add(25, 30, 300, &usage));
  EXPECT_TRUE(map.Add(50, 52, 500, &usage));
  EXPECT_TRUE(map.Add(20, 25, 200, &usage));
  EXPECT_NUM_MAP_EQ(map, usage,
                    {{10, 12, 100},
                     {20, 25, 200},
                     {25, 30, 300},
                     {40, 45, 400},
                     {50, 52, 500}});
  EXPECT_FALSE(map.Add(22, 28, 0, &usage));  // 0 does not add anything

  // Test FindAt():
  ExpectFindAtHasNoValue(&map, 9);
  ExpectFindAtHasValue(&map, 10, 100);
  ExpectFindAtHasValue(&map, 11, 100);
  ExpectFindAtHasNoValue(&map, 12);
  ExpectFindAtHasNoValue(&map, 19);
  ExpectFindAtHasValue(&map, 20, 200);
  ExpectFindAtHasValue(&map, 24, 200);
  ExpectFindAtHasValue(&map, 25, 300);
  ExpectFindAtHasValue(&map, 50, 500);
  ExpectFindAtHasValue(&map, 51, 500);
  ExpectFindAtHasNoValue(&map, 52);
  ExpectFindAtHasNoValue(&map, 53);

  // TODO(ksteuck): [cleanup] Refactor the above into test fixture
  // initialization and below into several tests.

  // Test AddToEach() and RemoveFromEach():
  {
    IntRangeMap map2(map);
    IntMethods::Size usage2 = usage;
    EXPECT_FALSE(map2.AddToEach(0, &usage2));  // 0 does not add anything
    EXPECT_TRUE(map2 == map);
    EXPECT_EQ(usage2, usage);
    EXPECT_TRUE(map2.RemoveFromEach(0, &usage2));  // 0 does not remove
    EXPECT_TRUE(map2 == map);
    EXPECT_EQ(usage2, usage);

    EXPECT_TRUE(map2.AddToEach(20, &usage2));
    EXPECT_NUM_MAP_EQ(map2, usage2,
                      {{10, 12, 120},
                       {20, 25, 220},
                       {25, 30, 320},
                       {40, 45, 420},
                       {50, 52, 520}});
    EXPECT_TRUE(map2.RemoveFromEach(10, &usage2));
    EXPECT_NUM_MAP_EQ(map2, usage2,
                      {{10, 12, 110},
                       {20, 25, 210},
                       {25, 30, 310},
                       {40, 45, 410},
                       {50, 52, 510}});
    EXPECT_TRUE(map2.RemoveFromEach(10, &usage2));
    EXPECT_TRUE(map2 == map);
    EXPECT_EQ(usage2, usage);
    EXPECT_FALSE(map2.RemoveFromEach(300, &usage2));
    EXPECT_NUM_MAP_EQ(map2, usage2, {{40, 45, 100}, {50, 52, 200}});
  }

  // Test Find():
  EXPECT_DEATH(map.Find(22, 21), "");  // bad range

  EXPECT_NUM_RANGE_EQ(map, 21, 21, {});
  EXPECT_NUM_RANGE_EQ(map, 21, 22, {{20, 25, 200}});

  EXPECT_NUM_RANGE_EQ(map, 21, 25, {{20, 25, 200}});
  EXPECT_NUM_RANGE_EQ(map, 20, 25, {{20, 25, 200}});
  EXPECT_NUM_RANGE_EQ(map, 15, 25, {{20, 25, 200}});

  EXPECT_NUM_RANGE_EQ(map, 25, 26, {{25, 30, 300}});
  EXPECT_NUM_RANGE_EQ(map, 25, 30, {{25, 30, 300}});
  EXPECT_NUM_RANGE_EQ(map, 25, 35, {{25, 30, 300}});

  EXPECT_NUM_RANGE_EQ(map, 0, 26,
                      {{10, 12, 100}, {20, 25, 200}, {25, 30, 300}});
  EXPECT_NUM_RANGE_EQ(
      map, 15, 55,
      {{20, 25, 200}, {25, 30, 300}, {40, 45, 400}, {50, 52, 500}});

  // Test Covers():
  CoversInfo info;
  info.Init(200);
  auto adder = [&info](IntRangeMap::const_iterator i) {
    return Adder(i, &info);
  };
  EXPECT_TRUE(map.Covers(20, 30, adder));  // all ok
  EXPECT_EQ(info.value_sum, 500);
  info.value_sum = 0;
  EXPECT_TRUE(map.Covers(21, 29, adder));  // all ok
  EXPECT_EQ(info.value_sum, 500);

  info.Init(250);
  EXPECT_FALSE(map.Covers(20, 30, adder));  // large limit
  EXPECT_TRUE(map.Covers(20, 20, adder));   // empty ranges
  EXPECT_TRUE(map.Covers(25, 25, adder));   // are always
  EXPECT_TRUE(map.Covers(30, 30, adder));   // covered though
  EXPECT_EQ(info.value_sum, 500);           // we visit all ranges
  info.value_sum = 0;
  EXPECT_FALSE(map.Covers(22, 37, adder));  // large limit
  EXPECT_EQ(info.value_sum, 500);           // we visit all ranges

  info.Init(100);
  EXPECT_FALSE(map.Covers(12, 15, adder));  // none of query covered
  EXPECT_FALSE(map.Covers(15, 17, adder));  // none of query covered
  EXPECT_FALSE(map.Covers(15, 20, adder));  // none of query covered
  EXPECT_FALSE(map.Covers(12, 20, adder));  // none of query covered
  EXPECT_EQ(info.value_sum, 0);

  EXPECT_FALSE(map.Covers(15, 22, adder));  // range prefix not covered
  EXPECT_EQ(info.value_sum, 200);
  info.value_sum = 0;
  EXPECT_FALSE(map.Covers(15, 27, adder));  // range prefix not covered
  EXPECT_EQ(info.value_sum, 500);
  info.value_sum = 0;
  EXPECT_FALSE(map.Covers(15, 35, adder));  // prefix&suffix not covered
  EXPECT_EQ(info.value_sum, 500);
  info.value_sum = 0;
  EXPECT_FALSE(map.Covers(22, 35, adder));  // range suffix not covered
  EXPECT_EQ(info.value_sum, 500);
  info.value_sum = 0;
  EXPECT_FALSE(map.Covers(27, 35, adder));  // range suffix not covered
  EXPECT_EQ(info.value_sum, 300);
  info.value_sum = 0;
  EXPECT_FALSE(map.Covers(11, 21, adder));  // subrange not covered
  EXPECT_EQ(info.value_sum, 300);

  // Various overlapping Add()-s:
  IntRangeMap map2 = map;
  IntMethods::Size usage2 = usage;
  EXPECT_TRUE(map2.Add(11, 23, 77, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{10, 11, 100},
                     {11, 12, 177},
                     {12, 20, 77},
                     {20, 23, 277},
                     {23, 25, 200},
                     {25, 30, 300},
                     {40, 45, 400},
                     {50, 52, 500}});
  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map2.Add(15, 30, 77, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{10, 12, 100},
                     {15, 20, 77},
                     {20, 25, 277},
                     {25, 30, 377},
                     {40, 45, 400},
                     {50, 52, 500}});

  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map2.Add(25, 40, 77, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{10, 12, 100},
                     {20, 25, 200},
                     {25, 30, 377},
                     {30, 40, 77},
                     {40, 45, 400},
                     {50, 52, 500}});

  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map2.Add(30, 55, 77, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{10, 12, 100},
                     {20, 25, 200},
                     {25, 30, 300},
                     {30, 40, 77},
                     {40, 45, 477},
                     {45, 50, 77},
                     {50, 52, 577},
                     {52, 55, 77}});

  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map2.Add(20, 22, 77, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{10, 12, 100},
                     {20, 22, 277},
                     {22, 25, 200},
                     {25, 30, 300},
                     {40, 45, 400},
                     {50, 52, 500}});

  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map2.Add(23, 25, 77, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{10, 12, 100},
                     {20, 23, 200},
                     {23, 25, 277},
                     {25, 30, 300},
                     {40, 45, 400},
                     {50, 52, 500}});

  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map2.Add(21, 23, 77, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{10, 12, 100},
                     {20, 21, 200},
                     {21, 23, 277},
                     {23, 25, 200},
                     {25, 30, 300},
                     {40, 45, 400},
                     {50, 52, 500}});

  // Test AddRangeMap():
  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map2.AddRangeMap(map, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{10, 12, 200},
                     {20, 25, 400},
                     {25, 30, 600},
                     {40, 45, 800},
                     {50, 52, 1000}});

  // Test AddRangeMap() that does not change our state:
  {
    IntRangeMap map3;
    EXPECT_TRUE(map3.Add(21, 28, 0));
    EXPECT_TRUE(map3.Add(40, 45, 0));
    EXPECT_NUM_MAP_EQ(map3, map3.Usage(), {{21, 28, 0}, {40, 45, 0}});
    EXPECT_FALSE(map2.AddRangeMap(map3, &usage2));
    EXPECT_NUM_MAP_EQ(map2, usage2,
                      {{10, 12, 200},
                       {20, 25, 400},
                       {25, 30, 600},
                       {40, 45, 800},
                       {50, 52, 1000}});
    EXPECT_TRUE(map3.Add(45, 52, 0));
    EXPECT_NUM_MAP_EQ(map3, map3.Usage(), {{21, 28, 0}, {40, 52, 0}});
    EXPECT_TRUE(map2.AddRangeMap(map3, &usage2));
    EXPECT_NUM_MAP_EQ(map2, usage2,
                      {{10, 12, 200},
                       {20, 25, 400},
                       {25, 30, 600},
                       {40, 45, 800},
                       {45, 50, 0},
                       {50, 52, 1000}});
    EXPECT_TRUE(map2.RemoveRangeMap(map3, &usage2));
  }

  // Test RemoveRangeMap():
  EXPECT_TRUE(map2.RemoveRangeMap(map, &usage2));
  EXPECT_EQ(map, map2);
  EXPECT_EQ(usage, usage2);
  EXPECT_TRUE(map2.RemoveRangeMap(map, &usage2));
  EXPECT_TRUE(map2.empty());
  EXPECT_NUM_MAP_EQ(map2, usage2, {});

  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map2.Remove(20, 25, 100, &usage2));
  EXPECT_FALSE(map2.RemoveRangeMap(map, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2, {});

  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map2.Add(20, 25, 77, &usage2));
  EXPECT_TRUE(map2.RemoveRangeMap(map, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2, {{20, 25, 77}});

  // Prepare "map" for testing Remove():
  EXPECT_TRUE(map.Add(20, 25, 200, &usage));
  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map.Add(12, 40, 55, &usage));
  // LOG_INFO("Map state:\n", map.);
  EXPECT_NUM_MAP_EQ(map, usage,
                    {{10, 12, 100},
                     {12, 20, 55},
                     {20, 25, 455},
                     {25, 30, 355},
                     {30, 40, 55},
                     {40, 45, 400},
                     {50, 52, 500}});

  // Remove() undoes an Add():
  EXPECT_TRUE(map.Remove(12, 40, 55, &usage));
  EXPECT_EQ(map, map2);
  EXPECT_EQ(usage, usage2);
  EXPECT_TRUE(map.Add(12, 40, 55, &usage));

  // Test various other Remove() scenarios:
  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map2.Remove(20, 25, 100, &usage2));  // a merge happens here
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{10, 12, 100},
                     {12, 20, 55},
                     {20, 30, 355},
                     {30, 40, 55},
                     {40, 45, 400},
                     {50, 52, 500}});

  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map2.Remove(10, 45, 55, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{10, 12, 45},
                     {20, 25, 400},
                     {25, 30, 300},
                     {40, 45, 345},
                     {50, 52, 500}});

  map2 = map;
  usage2 = usage;
  EXPECT_FALSE(map2.Remove(10, 25, 75, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{10, 12, 25},
                     {20, 25, 380},
                     {25, 30, 355},
                     {30, 40, 55},
                     {40, 45, 400},
                     {50, 52, 500}});

  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map2.Remove(15, 23, 33, &usage2));
  EXPECT_FALSE(map2.Remove(12, 45, 55, &usage2));
  EXPECT_TRUE(map2.Remove(41, 43, 77, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{10, 12, 100},
                     {20, 23, 400 - 33},
                     {23, 25, 400},
                     {25, 30, 300},
                     {40, 41, 345},
                     {41, 43, 345 - 77},
                     {43, 45, 345},
                     {50, 52, 500}});

  map2 = map;
  usage2 = usage;
  EXPECT_FALSE(map2.Remove(45, 50, 75, &usage2));
  EXPECT_EQ(map, map2);
  EXPECT_EQ(usage, usage2);

  map2 = map;
  usage2 = usage;
  EXPECT_FALSE(map2.Remove(20, 30, 455, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{10, 12, 100},
                     {12, 20, 55},
                     {30, 40, 55},
                     {40, 45, 400},
                     {50, 52, 500}});

  // Compare with map2.Remove(10, 45, 55) above:
  map2 = map;
  usage2 = usage;
  EXPECT_TRUE(map2.Add(5, 60, -55, &usage2));
  EXPECT_NUM_MAP_EQ(map2, usage2,
                    {{5, 10, -55},
                     {10, 12, 45},
                     {20, 25, 400},
                     {25, 30, 300},
                     {40, 45, 345},
                     {45, 50, -55},
                     {50, 52, 445},
                     {52, 60, -55}});

  // Test erase():
  map2 = map;
  usage2 = usage;
  map2.erase(map2.FindAll().first, &usage2);
  map2.erase(map2.Find(22, 27), &usage2);
  map2.erase(map2.Find(41, 42).first, map2.Find(41, 42).second, &usage2);
  EXPECT_NUM_MAP_EQ(map2, usage2, {{12, 20, 55}, {30, 40, 55}, {50, 52, 500}});
}

void TestRangeMerge(int from, int to, int extra) {
  SCOPED_TRACE(
      absl::StrCat("from ", from, " to ", to, " with ", extra, " extra"));
  IntMethods::Size usage = 0;
  IntRangeMap map;
  EXPECT_TRUE(map.Add(10, 20, 0, &usage));
  EXPECT_TRUE(map.Add(30, 40, 0, &usage));
  EXPECT_NUM_MAP_EQ(map, usage, {{10, 20, 0}, {30, 40, 0}});
  if (extra > 0) {
    EXPECT_TRUE(map.Add(24, 26, 2, &usage));
    EXPECT_NUM_MAP_EQ(map, usage, {{10, 20, 0}, {24, 26, 2}, {30, 40, 0}});
  }
  if (extra > 1) {
    EXPECT_TRUE(map.Add(26, 28, 3, &usage));
    EXPECT_NUM_MAP_EQ(map, usage,
                      {{10, 20, 0}, {24, 26, 2}, {26, 28, 3}, {30, 40, 0}});
  }
  if (extra > 2) {
    EXPECT_TRUE(map.Add(20, 24, 1, &usage));
    EXPECT_NUM_MAP_EQ(
        map, usage,
        {{10, 20, 0}, {20, 24, 1}, {24, 26, 2}, {26, 28, 3}, {30, 40, 0}});
  }
  if (extra > 3) {
    EXPECT_TRUE(map.Add(28, 30, 4, &usage));
    EXPECT_NUM_MAP_EQ(map, usage,
                      {{10, 20, 0},
                       {20, 24, 1},
                       {24, 26, 2},
                       {26, 28, 3},
                       {28, 30, 4},
                       {30, 40, 0}});
  }
  // 0 acts as a multiplier, so 1,2,3,4 become 0
  IntMethods::Size usage_copy = usage;
  IntRangeMap map_copy(map);
  EXPECT_TRUE(map.Add(from, to, 0, &usage));
  EXPECT_NUM_MAP_EQ(map, usage, {{std::min(from, 10), std::max(to, 40), 0}});
  EXPECT_TRUE(map_copy.Add(from, to, 0, &usage_copy, false));
  map_copy.Merge(from, to);
  EXPECT_NUM_MAP_EQ(map_copy, usage_copy,
                    {{std::min(from, 10), std::max(to, 40), 0}});
}

TEST(RangeMapTest, Merges) {
  more_is_empty_mode = false;

  {
    IntMethods::Size usage = 0;
    IntRangeMap map;
    IntMethods::Size usage_copy = 0;
    IntRangeMap map_copy;

// Expect that adding [start, limit) -> value to 'map' without merging
// returns expected_ret and we get expected_map as a result.
#define EXPECT_ADD_NO_MERGE(start, limit, value, expected_ret,     \
                            expected_map...)                       \
  map_copy = map;                                                  \
  usage_copy = usage;                                              \
  EXPECT_EQ(map_copy.Add(start, limit, value, &usage_copy, false), \
            expected_ret);                                         \
  EXPECT_NUM_MAP_EQ(map_copy, usage_copy, expected_map);           \
  map_copy.Merge(start, limit, &usage_copy);                       \
  EXPECT_EQ(map.Add(start, limit, value, &usage), expected_ret);

// Expect that the add described by the last EXPECT_ADD_NO_MERGE()
// done with merging results in expected_map.
#define EXPECT_ADD_MERGE(expected_map...)                \
  EXPECT_NUM_MAP_EQ(map_copy, usage_copy, expected_map); \
  EXPECT_NUM_MAP_EQ(map, usage, expected_map);

    // Initial map setup.
    EXPECT_ADD_NO_MERGE(10, 20, 0, true, {{10, 20, 0}});
    EXPECT_ADD_MERGE({{10, 20, 0}});

    // Inside-range "extensions" that don't change the range:
    EXPECT_ADD_NO_MERGE(13, 16, 0, false,
                        {{10, 13, 0}, {13, 16, 0}, {16, 20, 0}});
    EXPECT_ADD_MERGE({{10, 20, 0}});  // inside
    EXPECT_ADD_NO_MERGE(10, 11, 0, false, {{10, 11, 0}, {11, 20, 0}});
    EXPECT_ADD_MERGE({{10, 20, 0}});  // at left boundary
    EXPECT_ADD_NO_MERGE(19, 20, 0, false, {{10, 19, 0}, {19, 20, 0}});
    EXPECT_ADD_MERGE({{10, 20, 0}});  // at right boundary
    EXPECT_ADD_NO_MERGE(10, 20, 0, false, {{10, 20, 0}});
    EXPECT_ADD_MERGE({{10, 20, 0}});  // at both boundaries

    // Extend one range in all kinds of ways still leading to one range,
    // because 0*0=0 and we merge ranges.
    EXPECT_ADD_NO_MERGE(9, 10, 0, true, {{9, 10, 0}, {10, 20, 0}});
    EXPECT_ADD_MERGE({{9, 20, 0}});  // extend left
    EXPECT_ADD_NO_MERGE(8, 11, 0, true, {{8, 9, 0}, {9, 11, 0}, {11, 20, 0}});
    EXPECT_ADD_MERGE({{8, 20, 0}});  // extend left with overlap
    EXPECT_ADD_NO_MERGE(7, 20, 0, true, {{7, 8, 0}, {8, 20, 0}});
    EXPECT_ADD_MERGE({{7, 20, 0}});  // extend left with total overlap
    EXPECT_ADD_NO_MERGE(20, 21, 0, true, {{7, 20, 0}, {20, 21, 0}});
    EXPECT_ADD_MERGE({{7, 21, 0}});  // extend right
    EXPECT_ADD_NO_MERGE(19, 22, 0, true,
                        {{7, 19, 0}, {19, 21, 0}, {21, 22, 0}});
    EXPECT_ADD_MERGE({{7, 22, 0}});  // extend right with overlap
    EXPECT_ADD_NO_MERGE(7, 23, 0, true, {{7, 22, 0}, {22, 23, 0}});
    EXPECT_ADD_MERGE({{7, 23, 0}});  // extend right with total overlap
    EXPECT_ADD_NO_MERGE(6, 24, 0, true, {{6, 7, 0}, {7, 23, 0}, {23, 24, 0}});
    EXPECT_ADD_MERGE({{6, 24, 0}});  // extend left and right

#undef EXPECT_ADD_NO_MERGE
#undef EXPECT_ADD_MERGE
  }

  // Merge two ranges with another one in various ways.
  // Also same with 1 to 4 extra adjacent ranges in the middle.
  {
    int extra;
    int froms[] = {5, 10, 15, 20, 0};
    int tos[] = {30, 35, 40, 45, 0};
    for (extra = 0; extra <= 4; ++extra) {
      for (int* from = froms; *from != 0; ++from) {
        for (int* to = tos; *to != 0; ++to) {
          TestRangeMerge(*from, *to, extra);
        }
      }
    }
  }

  more_is_empty_mode = true;
}

// Test the case of intersection getting empty due to the intersection value
// becoming empty.
TEST(RangeMapTest, AddIntersectionOf_EmptyValue) {
  ASSERT_TRUE(more_is_empty_mode);
  IntRangeMap map1;
  EXPECT_TRUE(map1.Add(10, 20, 1));
  IntRangeMap map2;
  EXPECT_TRUE(map2.Add(15, 25, 2));
  IntMethods::Size usage = 0;
  IntRangeMap map;
  map.AddIntersectionOf(map1, map2, &usage);
  map.AddIntersectionOf(map1, 5, 15, 2, &usage);
  EXPECT_TRUE(map.empty());  // [15,20) and [10,15) are dropped because
                             // min(1,2) - 1 is 0
  EXPECT_EQ(usage, 0);
}

// Test intersections of various range patterns.
TEST(RangeMapTest, AddIntersectionOf_AddDifferenceOf) {
  more_is_empty_mode = false;

  // The range we'll be intersecting with.
  const int kStart = 3;
  const int kLimit = 8;
  IntRangeMap crop_range;
  EXPECT_TRUE(crop_range.Add(kStart, kLimit, 1));

  // Interesting points to start/end a range to intersect with [kStart, kLimit).
  const int kPoints[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

  // What we do is
  // * We construct 'map' as a union of a few ranges with the endpoints
  //   from 'kPoints'.
  // * At the same time we add to expected_* the intersections of those ranges
  //   with crop_range and the differences of crop_range.
  // * We then intersect and difference 'map' with crop_range and check that
  //   it's the same as expected_*.

  int seed = []() {
    const char* seed_env_var = std::getenv("TEST_RANDOM_SEED");
    int out = 1;
    if (seed_env_var != nullptr) {
      (void)absl::SimpleAtoi(seed_env_var, &out);
    }
    return out;
  }();
  LOG_INFO("Random seed: ", seed);
  absl::SeedSeq seq({seed});
  absl::BitGen random(seq);

  for (int i = 0; i < 300; ++i) {  // 300 random tests
    IntMethods::Size expected_isec_usage = 0;
    IntMethods::Size expected_diff_usage = 0;
    IntMethods::Size isec_usage = 0;
    IntMethods::Size isec_usage2 = 0;
    IntRangeMap expected_isec;
    IntRangeMap expected_diff;
    IntRangeMap all_map;
    IntMethods::Size all_map_usage = 0;
    IntRangeMap intersection;
    IntRangeMap intersection2;
    const int num_adds = 1 + absl::Uniform<int32_t>(random, 0, 3);
    for (int a = 0; a < num_adds; ++a) {
      IntRangeMap map;
      const int num_ranges = 1 + absl::Uniform<int32_t>(random, 0, 4);
      for (int r = 0; r < num_ranges; ++r) {
        const int s = absl::Uniform<int32_t>(random, 0, std::size(kPoints) - 1);
        const int e =
            s + 1 +
            absl::Uniform<int32_t>(random, 0, std::size(kPoints) - 1 - s);
        EXPECT_TRUE(map.Add(kPoints[s], kPoints[e], 7));
        all_map.Add(kPoints[s], kPoints[e], 1, &all_map_usage);
        if (kPoints[s] < kLimit &&
            kPoints[e] > kStart) {  // non-empty intersection
          expected_isec.Add(std::max(kStart, kPoints[s]),
                            std::min(kLimit, kPoints[e]), 1,
                            &expected_isec_usage);  // min(1, 7) == 1
        }
        if (kPoints[s] < kStart) {  // non-empty difference before crop_range
          expected_diff.Add(kPoints[s], std::min(kStart, kPoints[e]), 1,
                            &expected_diff_usage);
        }
        if (kPoints[e] > kLimit) {  // non-empty difference after crop_range
          expected_diff.Add(std::max(kLimit, kPoints[s]), kPoints[e], 1,
                            &expected_diff_usage);
        }
      }
      intersection.AddIntersectionOf(map, crop_range, &isec_usage);
      EXPECT_EQ(intersection, expected_isec);
      EXPECT_EQ(isec_usage, expected_isec_usage);
      intersection2.AddIntersectionOf(crop_range, map, &isec_usage2);
      EXPECT_EQ(intersection2, expected_isec);
      EXPECT_EQ(isec_usage2, expected_isec_usage);
      EXPECT_EQ(expected_isec_usage, expected_isec.Usage());
      IntRangeMap difference;
      IntMethods::Size diff_usage = 0;
      difference.AddDifferenceOf(all_map, crop_range, &diff_usage);
      EXPECT_EQ(difference, expected_diff);
      EXPECT_EQ(diff_usage, expected_diff_usage);
      // Equivalent difference computation:
      difference = all_map;
      diff_usage = all_map_usage;
      difference.RemoveRangeMap(crop_range, &diff_usage);
      EXPECT_EQ(difference, expected_diff);
      EXPECT_EQ(diff_usage, expected_diff_usage);
    }
  }

  more_is_empty_mode = true;
}

// Test the case of difference getting empty due to the difference value
// becoming empty.
TEST(RangeMapTest, AddDifferenceOf_EmptyValue) {
  ASSERT_TRUE(more_is_empty_mode);
  IntRangeMap map1;
  EXPECT_TRUE(map1.Add(10, 20, 1));
  IntRangeMap map2;
  EXPECT_TRUE(map2.Add(5, 25, 2));
  IntMethods::Size usage = 0;
  IntRangeMap map;
  map.AddDifferenceOf(map1, map2, &usage);
  EXPECT_TRUE(map.empty());  // because 1 - 2 <= 0
  map.AddDifferenceOf(5, 25, 2, map2, &usage);
  EXPECT_TRUE(map.empty());  // because 2 - 2 <= 0
  EXPECT_EQ(usage, 0);
}

// ========================================================================= //

class IntConvMethods : public IntMethods {
 public:
  // So that we can import data from DoubleRangeMap and Int64RangeMap.
  static Value Convert(double v_x) { return v_x + 0.5 + 1000000; }
  static Value Convert(int64_t v_x) { return v_x + 1000; }
  // So that we can add the intersection/difference of a DoubleRangeMap
  // with an Int64RangeMap.
  using IntMethods::Slice;
  static const double& Slice(const Key& start, const Key& limit,
                             const double& v, const Key& s, const Key& l) {
    DCHECK_LE(start, s);
    DCHECK_LT(s, l);
    DCHECK_LE(l, limit);
    return v;
  }
  static const int64_t& Slice(const Key& start, const Key& limit,
                              const int64_t& v, const Key& s, const Key& l) {
    DCHECK_LE(start, s);
    DCHECK_LT(s, l);
    DCHECK_LE(l, limit);
    return v;
  }
  static void MakeIntersection(Value* dest, const double& v1, int64_t v2,
                               bool* empty) {
    *dest = std::min(Convert(v1), Convert(v2)) - 500;
    *empty = *dest == 0;
  }
  static void MakeDifference(Value* dest, int64_t v1, const double& v2,
                             bool* empty) {
    NumMethods<int>::MakeDifference(dest, Convert(v1) - 600, Convert(v2),
                                    empty);
  }
  static void MakeDifference(Value* dest, const double& v1, int64_t v2,
                             bool* empty) {
    NumMethods<int>::MakeDifference(dest, Convert(v1) - 700, Convert(v2),
                                    empty);
  }
};
typedef RangeMap<IntConvMethods::Key, IntConvMethods::Value, IntConvMethods>
    IntConvRangeMap;

typedef NumMethods<double> DoubleMethods;
typedef RangeMap<DoubleMethods::Key, DoubleMethods::Value, DoubleMethods>
    DoubleRangeMap;

class Int64Methods : public NumMethods<int64_t> {
 public:
  // So that we can import data from IntConvRangeMap.
  static Value Convert(int v_x) { return v_x; }
};
typedef RangeMap<Int64Methods::Key, Int64Methods::Value, Int64Methods>
    Int64RangeMap;

TEST(RangeMapTest, OtherTypes) {
  IntConvRangeMap map;
  IntMethods::Size usage = 0;
  EXPECT_TRUE(map.Add(10, 20, 1000, &usage));
  EXPECT_TRUE(map.Add(30, 40, 2000, &usage));
  EXPECT_NUM_MAP_EQ(map, usage, {{10, 20, 1000}, {30, 40, 2000}});

  // c-tor:
  {
    Int64RangeMap i64map(map);
    EXPECT_NUM_MAP_EQ(i64map, usage, {{10, 20, 1000}, {30, 40, 2000}});
    IntConvRangeMap map2(i64map);
    // Conversion from int64_t adds a 1000:
    EXPECT_NUM_MAP_EQ(map2, map2.Usage(), {{10, 20, 2000}, {30, 40, 3000}});
  }

  // Add() and Remove():
  {
    IntConvRangeMap map2(map);
    IntMethods::Size usage2 = usage;
    // Conversion from double adds a 1000000:
    EXPECT_TRUE(map2.Add(15, 35, static_cast<double>(77.0), &usage2));
    EXPECT_NUM_MAP_EQ(map2, usage2,
                      {{10, 15, 1000},
                       {15, 20, 1001077},
                       {20, 30, 1000077},
                       {30, 35, 1002077},
                       {35, 40, 2000}});
    // Conversion from int64_t adds a 1000:
    EXPECT_FALSE(map2.Remove(10, 20, static_cast<int64_t>(55), &usage2));
    EXPECT_NUM_MAP_EQ(map2, usage2,
                      {{15, 20, 1000022},
                       {20, 30, 1000077},
                       {30, 35, 1002077},
                       {35, 40, 2000}});
  }

  DoubleRangeMap dmap;
  EXPECT_TRUE(dmap.Add(15, 35, static_cast<double>(77.0)));
  EXPECT_NUM_MAP_EQ(dmap, dmap.Usage(), {{15, 35, 77}});

  Int64RangeMap i64map;
  EXPECT_TRUE(i64map.Add(10, 20, static_cast<int64_t>(55)));
  EXPECT_NUM_MAP_EQ(i64map, i64map.Usage(), {{10, 20, 55}});

  // AddRangeMap() and RemoveRangeMap():
  {
    IntConvRangeMap map2(map);
    IntMethods::Size usage2 = usage;
    // Conversion from double adds a 1000000:
    EXPECT_TRUE(map2.AddRangeMap(dmap, &usage2));
    EXPECT_NUM_MAP_EQ(map2, usage2,
                      {{10, 15, 1000},
                       {15, 20, 1001077},
                       {20, 30, 1000077},
                       {30, 35, 1002077},
                       {35, 40, 2000}});
    // Conversion from int64_t adds a 1000:
    EXPECT_FALSE(map2.RemoveRangeMap(i64map, &usage2));
    EXPECT_NUM_MAP_EQ(map2, usage2,
                      {{15, 20, 1000022},
                       {20, 30, 1000077},
                       {30, 35, 1002077},
                       {35, 40, 2000}});
  }

  // AddToEach() and RemoveFromEach():
  {
    IntConvRangeMap map2(map);
    IntMethods::Size usage2 = usage;
    // Conversion from double adds a 1000000:
    EXPECT_TRUE(map2.AddToEach(static_cast<double>(77.0), &usage2));
    EXPECT_NUM_MAP_EQ(map2, usage2, {{10, 20, 1001077}, {30, 40, 1002077}});
    // Conversion from int64_t adds a 1000:
    EXPECT_TRUE(map2.RemoveFromEach(static_cast<int64_t>(55), &usage2));
    EXPECT_NUM_MAP_EQ(map2, usage2, {{10, 20, 1000022}, {30, 40, 1001022}});
  }

  // AddIntersectionOf():
  {
    IntConvRangeMap map2(map);
    IntMethods::Size usage2 = usage;
    map2.AddIntersectionOf(dmap, 17, 32, static_cast<int64_t>(33), &usage2);
    EXPECT_NUM_MAP_EQ(map2, usage2,
                      {{10, 17, 1000},
                       {17, 20, 1533},
                       {20, 30, 533},
                       {30, 32, 2533},
                       {32, 40, 2000}});
  }
  {
    IntConvRangeMap map2(map);
    IntMethods::Size usage2 = usage;
    map2.AddIntersectionOf(dmap, i64map, &usage2);
    EXPECT_NUM_MAP_EQ(
        map2, usage2,
        {{10, 15, 1000}, {15, 20, 1000 + 1055 - 500}, {30, 40, 2000}});
  }

  // AddDifferenceOf():
  {
    IntConvRangeMap map2(map);
    IntMethods::Size usage2 = usage;
    EXPECT_NUM_MAP_EQ(map2, usage, {{10, 20, 1000}, {30, 40, 2000}});
    EXPECT_NUM_MAP_EQ(dmap, dmap.Usage(),
                      {{15, 35, 77 /* becomes 1000077 as int */}});
    map2.AddDifferenceOf(
        13, 37, static_cast<int64_t>(1000088) /* becomes 1001088 as int */,
        dmap, &usage2);
    EXPECT_NUM_MAP_EQ(map2, usage2,
                      {
                          {10, 13, 1000},
                          {13, 15, 1000 + 1001088},
                          // -600 is from IntConvMethods::MakeDifference():
                          {15, 20, 1000 + 1001088 - 600 - 1000077},
                          {20, 30, 1001088 - 600 - 1000077},
                          {30, 35, 2000 + 1001088 - 600 - 1000077},
                          {35, 37, 2000 + 1001088},
                          {37, 40, 2000},
                      });

    map2 = map;
    usage2 = usage;
    map2.AddDifferenceOf(
        17, 33, static_cast<int64_t>(1000088) /* becomes 1001088 as int */,
        dmap, &usage2);
    EXPECT_NUM_MAP_EQ(map2, usage2,
                      {
                          {10, 17, 1000},
                          {17, 20, 1000 + 1001088 - 600 - 1000077},
                          {20, 30, 1001088 - 600 - 1000077},
                          {30, 33, 2000 + 1001088 - 600 - 1000077},
                          {33, 40, 2000},
                      });
  }
  {
    IntConvRangeMap map2(map);
    IntMethods::Size usage2 = usage;
    EXPECT_NUM_MAP_EQ(map2, usage, {{10, 20, 1000}, {30, 40, 2000}});
    EXPECT_NUM_MAP_EQ(dmap, dmap.Usage(),
                      {{15, 35, 77 /* becomes 1000077 as int */}});
    EXPECT_NUM_MAP_EQ(i64map, i64map.Usage(),
                      {{10, 20, 55 /* becomes 1055 as int */}});
    map2.AddDifferenceOf(dmap, i64map, &usage2);
    EXPECT_NUM_MAP_EQ(map2, usage2,
                      {
                          {10, 15, 1000},
                          // -700 is from IntConvMethods::MakeDifference():
                          {15, 20, 1000 + 1000077 - 700 - 1055},
                          {20, 30, 1000077},
                          {30, 35, 2000 + 1000077},
                          {35, 40, 2000},
                      });

    map2 = map;
    usage2 = usage;
    map2.AddDifferenceOf(i64map, dmap, &usage2);
    EXPECT_NUM_MAP_EQ(map2, usage2,
                      {
                          {10, 15, 1000 + 1055},
                          {15, 20, 1000},
                          {30, 40, 2000},
                      });
  }
}

}  // unnamed namespace
}  // namespace silifuzz
