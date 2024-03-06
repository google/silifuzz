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

#include "./common/proxy_config.h"

#include <stddef.h>

#include <algorithm>
#include <vector>

#include "gtest/gtest.h"
#include "./common/mapped_memory_map.h"
#include "./common/memory_perms.h"
#include "./common/snapshot_enums.h"
#include "./util/arch.h"

namespace silifuzz {
namespace {

bool SortMemoryRange(const MemoryRange& a, const MemoryRange& b) {
  return a.start_address < b.start_address;
}

void CheckMemoryRanges(std::vector<MemoryRange>& ranges) {
  ASSERT_GT(ranges.size(), 1);
  std::sort(ranges.begin(), ranges.end(), SortMemoryRange);
  for (size_t i = 0; i < ranges.size() - 1; ++i) {
    EXPECT_LE(ranges[i].start_address + ranges[i].num_bytes,
              ranges[i + 1].start_address);
  }
}

void CheckMemoryRange(const MemoryRange& range, const MemoryPerms& perms,
                      MappedMemoryMap& mapped_memory_map) {
  snapshot_types::Address limit_address = range.start_address + range.num_bytes;
  EXPECT_TRUE(mapped_memory_map.Contains(range.start_address, limit_address));
  MemoryPerms min_perms = mapped_memory_map.Perms(
      range.start_address, limit_address, MemoryPerms::kAnd);
  MemoryPerms max_perms = mapped_memory_map.Perms(
      range.start_address, limit_address, MemoryPerms::kOr);
  // The memory range should have exactly `perms`.
  EXPECT_EQ(min_perms, perms);
  EXPECT_EQ(max_perms, perms);
}

void RemoveMemoryRange(const MemoryRange& range,
                       MappedMemoryMap& mapped_memory_map) {
  snapshot_types::Address limit_address = range.start_address + range.num_bytes;
  mapped_memory_map.Remove(range.start_address, limit_address);
}

TEST(ProxyConfig, NoOverlap_X86_64) {
  FuzzingConfig<X86_64> config = DEFAULT_FUZZING_CONFIG<X86_64>;
  std::vector<MemoryRange> ranges = {config.code_range, config.data1_range,
                                     config.data2_range};
  CheckMemoryRanges(ranges);
}

TEST(ProxyConfig, NoOverlap_AArch64) {
  FuzzingConfig<AArch64> config = DEFAULT_FUZZING_CONFIG<AArch64>;
  std::vector<MemoryRange> ranges = {config.code_range, config.stack_range,
                                     config.data1_range, config.data2_range};
  CheckMemoryRanges(ranges);
}

TEST(ProxyConfig, FuzzConfigToMappedMemoryMap_X86_64) {
  FuzzingConfig<X86_64> fuzz_config = DEFAULT_FUZZING_CONFIG<X86_64>;
  MappedMemoryMap mapped_memory_map = FuzzConfigToMappedMemoryMap(fuzz_config);
  CheckMemoryRange(fuzz_config.code_range, MemoryPerms::XR(),
                   mapped_memory_map);
  CheckMemoryRange(fuzz_config.data1_range, MemoryPerms::RW(),
                   mapped_memory_map);
  CheckMemoryRange(fuzz_config.data2_range, MemoryPerms::RW(),
                   mapped_memory_map);

  // Remove the above memory ranges. The map should be empty after that.
  RemoveMemoryRange(fuzz_config.code_range, mapped_memory_map);
  RemoveMemoryRange(fuzz_config.data1_range, mapped_memory_map);
  RemoveMemoryRange(fuzz_config.data2_range, mapped_memory_map);
  EXPECT_TRUE(mapped_memory_map.IsEmpty());
}

TEST(ProxyConfig, FuzzConfigToMappedMemoryMap_AArch64) {
  FuzzingConfig<AArch64> fuzz_config = DEFAULT_FUZZING_CONFIG<AArch64>;
  MappedMemoryMap mapped_memory_map = FuzzConfigToMappedMemoryMap(fuzz_config);
  CheckMemoryRange(fuzz_config.code_range, MemoryPerms::XR(),
                   mapped_memory_map);
  CheckMemoryRange(fuzz_config.stack_range, MemoryPerms::RW(),
                   mapped_memory_map);
  CheckMemoryRange(fuzz_config.data1_range, MemoryPerms::RW(),
                   mapped_memory_map);
  CheckMemoryRange(fuzz_config.data2_range, MemoryPerms::RW(),
                   mapped_memory_map);

  // Remove the above memory ranges. The map should be empty after that.
  RemoveMemoryRange(fuzz_config.code_range, mapped_memory_map);
  RemoveMemoryRange(fuzz_config.stack_range, mapped_memory_map);
  RemoveMemoryRange(fuzz_config.data1_range, mapped_memory_map);
  RemoveMemoryRange(fuzz_config.data2_range, mapped_memory_map);
  EXPECT_TRUE(mapped_memory_map.IsEmpty());
}

}  // namespace
}  // namespace silifuzz
