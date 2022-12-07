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

#include "./snap/gen/reserved_memory_mappings.h"

#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "gtest/gtest.h"
#include "./snap/gen/runner_base_address.h"

namespace silifuzz {
namespace {

TEST(ReservedMemoryMappings, MustInclude) {
  // Test some known reserved addresses.
  const MappedMemoryMap& reserved_memory_mappings = ReservedMemoryMappings();
  const uint64_t kPageSize = getpagesize();
  EXPECT_TRUE(reserved_memory_mappings.Contains(0, kPageSize));
  EXPECT_TRUE(reserved_memory_mappings.Contains(
      SILIFUZZ_RUNNER_BASE_ADDRESS,
      SILIFUZZ_RUNNER_BASE_ADDRESS + (1ULL << 32)));
#if defined(__x86_64__) || defined(__aarch64__)
  constexpr uint64_t kUserSpaceLimit = 1ULL << 48;
#else
#error "need to define user space limit for this architecture"
#endif
  EXPECT_TRUE(reserved_memory_mappings.Contains(kUserSpaceLimit,
                                                ~static_cast<uint64_t>(0)));
}

TEST(ReservedMemoryMappings, MustExclude) {
  // The address after the first mega byte is far away from the NULL pointer
  // reserved mapping.  It is also low enough that it should not overlap with
  // any reserved mappings.
  constexpr uint64_t kTestAddress = 1 << 20;
  constexpr size_t kMiB = 1 << 20;
  EXPECT_FALSE(
      ReservedMemoryMappings().Contains(kTestAddress, kTestAddress + kMiB));
}

}  // namespace
}  // namespace silifuzz
