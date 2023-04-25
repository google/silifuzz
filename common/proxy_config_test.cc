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

}  // namespace
}  // namespace silifuzz
