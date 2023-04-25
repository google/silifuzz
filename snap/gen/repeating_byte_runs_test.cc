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

#include "./snap/gen/repeating_byte_runs.h"

#include <unistd.h>

#include <cstddef>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "./common/mapped_memory_map.h"
#include "./common/memory_perms.h"
#include "./common/snapshot.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {

using silifuzz::testing::IsOkAndHolds;
using silifuzz::testing::StatusIs;
using ::testing::HasSubstr;
using ::testing::SizeIs;

using Address = Snapshot::Address;
using ByteData = Snapshot::ByteData;
using MemoryBytes = Snapshot::MemoryBytes;
using MemoryBytesList = Snapshot::MemoryBytesList;

TEST(RepeatingByteRuns, Empty) {
  MemoryBytesList empty_list;
  auto runs_or = GetRepeatingByteRuns(empty_list);
  EXPECT_THAT(runs_or, IsOkAndHolds(empty_list));
}

TEST(RepeatingByteRuns, RejectUnsorted) {
  const ByteData byte_data("01234567");
  constexpr Address addr1 = 0x123400;
  constexpr Address addr2 = addr1 + 0x100;

  const MemoryBytesList unsorted{MemoryBytes(addr2, byte_data),
                                 MemoryBytes(addr1, byte_data)};

  auto runs_or = GetRepeatingByteRuns(unsorted);
  EXPECT_THAT(runs_or, StatusIs(absl::StatusCode::kFailedPrecondition,
                                HasSubstr("not sorted")));
}

TEST(RepeatingByteRuns, RejectUnalignedStartAddress) {
  const ByteData byte_data("01234567");
  constexpr Address addr = 0x123401;

  const MemoryBytesList unaligned_start{MemoryBytes(addr, byte_data)};

  auto runs_or = GetRepeatingByteRuns(unaligned_start);
  EXPECT_THAT(runs_or, StatusIs(absl::StatusCode::kFailedPrecondition,
                                HasSubstr("unaligned start address")));
}

TEST(RepeatingByteRuns, RejectUnalignedLimitAddress) {
  const ByteData byte_data("012345");
  constexpr Address addr = 0x123400;

  const MemoryBytesList unaligned_limit{MemoryBytes(addr, byte_data)};

  auto runs_or = GetRepeatingByteRuns(unaligned_limit);
  EXPECT_THAT(runs_or, StatusIs(absl::StatusCode::kFailedPrecondition,
                                HasSubstr("unaligned limit address")));
}

TEST(RepeatingByteRuns, BelowMinRepeatingByteRunSize) {
  static_assert(kMinRepeatingByteRunSize > 8);
  ByteData byte_data(8, 'a');
  byte_data.append(ByteData("0123456789abcdef"));
  byte_data.append(ByteData(8, 'b'));
  constexpr Address addr = 0x1234000;
  MemoryBytesList memory_bytes_list{MemoryBytes(addr, byte_data)};
  ASSERT_OK_AND_ASSIGN(auto runs, GetRepeatingByteRuns(memory_bytes_list));
  EXPECT_TRUE(Snapshot::MemoryBytesListEq(memory_bytes_list, runs));
}

TEST(RepeatingByteRuns, SplitMemoryBytesAsExpected) {
  const ByteData run_of_x(kMinRepeatingByteRunSize, 'x');
  const ByteData non_repeating("xx0123456789abxx");

  constexpr Address addr_1 = 0x1230000;
  constexpr Address addr_2 = 0x2340000;
  constexpr Address addr_3 = 0x3450000;

  // Construct runs we expect to get.
  struct ConstructorArgs {
    Address addr;
    ByteData byte_data;
  };
  const ConstructorArgs constructor_args[] = {
      // Repeating byte run in front.
      {addr_1, run_of_x},
      {addr_1 + run_of_x.size(), non_repeating},
      // Repeating byte run at back.
      {addr_2, non_repeating},
      {addr_2 + non_repeating.size(), run_of_x},
      // Repeating byte run in middle.
      {addr_3, non_repeating},
      {addr_3 + non_repeating.size(), run_of_x},
      {addr_3 + non_repeating.size() + run_of_x.size(), non_repeating},
  };

  MemoryBytesList expected;
  for (const auto& [addr, byte_data] : constructor_args) {
    expected.push_back(MemoryBytes(addr, byte_data));
  }

  // Construct MappedMemoryMap for NormalizeMemoryBytes() below.
  MappedMemoryMap memory_map;
  const size_t page_size = getpagesize();
  auto add_page_at = [&memory_map, page_size](Address addr) {
    memory_map.Add(addr, addr + page_size, MemoryPerms::All());
  };
  add_page_at(addr_1);
  add_page_at(addr_2);
  add_page_at(addr_3);

  // NormalizedMemoryBytes() merges adjacent MemoryBytes.
  MemoryBytesList merged = expected;
  Snapshot::NormalizeMemoryBytes(memory_map, &merged);
  EXPECT_THAT(merged, SizeIs(3));

  // We should get back the original runs.
  auto runs_or = GetRepeatingByteRuns(merged);
  EXPECT_THAT(runs_or, IsOkAndHolds(expected));
}

TEST(RepeatingByteRuns, InputNotMerged) {
  // Test that original MemoryBytes objects are not merged in the output.
  // This is important as the input objects may be split due to different
  // memory permissions.
  const size_t page_size = getpagesize();
  const Address kAddr1 = 0x123 * page_size;
  const ByteData page_of_zeros(page_size, 0);
  MemoryBytes memory_bytes_1(kAddr1, page_of_zeros);
  const Address kAddr2 = memory_bytes_1.limit_address();
  MemoryBytes memory_bytes_2(kAddr2, page_of_zeros);

  MemoryBytesList memory_bytes_list{memory_bytes_1, memory_bytes_2};

  // We should get back the original runs.
  MemoryBytesList expected = memory_bytes_list;
  auto runs_or = GetRepeatingByteRuns(memory_bytes_list);
  EXPECT_THAT(runs_or, IsOkAndHolds(expected));
}

TEST(RepeatingByteRuns, IsRepeatingByteRun) {
  static_assert(kByteRunAlignmentSize > 1);
  ByteData too_short_and_unaligned(kMinRepeatingByteRunSize - 1, 'A');
  EXPECT_FALSE(IsRepeatingByteRun(too_short_and_unaligned));

  if (kMinRepeatingByteRunSize > kByteRunAlignmentSize) {
    ByteData too_short_but_aligned(
        kMinRepeatingByteRunSize - kByteRunAlignmentSize, 'B');
    EXPECT_FALSE(IsRepeatingByteRun(too_short_but_aligned));
  }

  ByteData unaligned(kMinRepeatingByteRunSize + 1, 'C');
  EXPECT_FALSE(IsRepeatingByteRun(unaligned));

  ByteData non_repeating("hello");
  non_repeating.resize(kMinRepeatingByteRunSize);
  EXPECT_FALSE(IsRepeatingByteRun(non_repeating));

  ByteData repeating(kMinRepeatingByteRunSize, 'D');
  EXPECT_TRUE(IsRepeatingByteRun(repeating));
}
}  // namespace
}  // namespace silifuzz
