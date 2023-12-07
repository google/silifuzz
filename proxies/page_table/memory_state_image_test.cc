// Copyright 2023 The SiliFuzz Authors.
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

#include "./proxies/page_table/memory_state_image.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/cleanup/cleanup.h"
#include "./common/memory_mapping.h"
#include "./common/memory_perms.h"
#include "./common/memory_state.h"
#include "./common/snapshot.h"
#include "./proxies/page_table/page_table_test_util.h"
#include "./util/arch.h"
#include "./util/testing/status_macros.h"

namespace silifuzz::proxies {

namespace {

template <typename arch>
class MemoryStateImageTest : public ::testing::Test {};

TYPED_TEST_SUITE_P(MemoryStateImageTest);

// Construct a minimal memory state image with 1 code and 1 data page.
TYPED_TEST_P(MemoryStateImageTest, BasicTest) {
  Snapshot s(Snapshot::ArchitectureTypeToEnum<TypeParam>());
  const Snapshot::ByteSize kPageSize = s.page_size();
  constexpr Snapshot::Address kCodeAddr = 0x123400000;
  const Snapshot::ByteSize kCodeSize = kPageSize;
  constexpr Snapshot::Address kDataAddr = 0x567800000;
  const Snapshot::ByteSize kDataSize = kPageSize;

  MemoryState memory_state;
  memory_state.AddNewMemoryMapping(
      MemoryMapping::MakeSized(kCodeAddr, kCodeSize, MemoryPerms::X()));
  Snapshot::ByteData code_bytes = "code";
  code_bytes.resize(kPageSize);
  memory_state.SetMemoryBytes(Snapshot::MemoryBytes{kCodeAddr, code_bytes});
  memory_state.AddNewMemoryMapping(
      MemoryMapping::MakeSized(kDataAddr, kDataSize, MemoryPerms::RW()));
  Snapshot::ByteData data_bytes = "data";
  data_bytes.resize(kPageSize);
  memory_state.SetMemoryBytes(Snapshot::MemoryBytes{kDataAddr, data_bytes});

  // We cannot use physical addresses in user mode. For testing, we allocate
  // a big enough buffer with proper alignment and pretend that we have
  // physical memory access.
  const size_t kMaxSize = 10 * kPageSize;
  void *fake_physical_memory;
  ASSERT_EQ(posix_memalign(&fake_physical_memory, kPageSize, kMaxSize), 0);
  ASSERT_NE(fake_physical_memory, nullptr);
  absl::Cleanup free_fake_physical_memory = [fake_physical_memory] {
    free(fake_physical_memory);
  };

  // Build the image and copy it to fake physical memory.
  ASSERT_OK_AND_ASSIGN(
      MemoryStateImage<TypeParam> image,
      MemoryStateImage<TypeParam>::Build(
          memory_state, reinterpret_cast<uintptr_t>(fake_physical_memory)));
  ASSERT_LE(image.image_data().size(), kMaxSize);
  memcpy(fake_physical_memory, image.image_data().data(),
         image.image_data().size());

  auto is_in_range = [fake_physical_memory, kMaxSize](uint64_t addr) {
    uint64_t start = reinterpret_cast<uint64_t>(fake_physical_memory);
    return addr >= start && addr < start + kMaxSize;
  };

  // Verify that we can get code and data using page table.
  uint64_t *page_table_root =
      reinterpret_cast<uint64_t *>(image.page_table_root());
  auto code_addr = TranslateVirtualAddress<TypeParam>(
      page_table_root, kCodeAddr,
      /*writeable=*/false, /*executable=*/true);
  ASSERT_OK(code_addr);
  ASSERT_TRUE(is_in_range(code_addr.value()));
  EXPECT_EQ(memcmp(reinterpret_cast<void *>(code_addr.value()),
                   code_bytes.data(), code_bytes.size()),
            0);

  auto data_addr = TranslateVirtualAddress<TypeParam>(
      page_table_root, kDataAddr,
      /*writeable=*/true, /*executable=*/false);
  ASSERT_OK(data_addr);
  ASSERT_TRUE(is_in_range(data_addr.value()));
  EXPECT_EQ(memcmp(reinterpret_cast<void *>(data_addr.value()),
                   data_bytes.data(), data_bytes.size()),
            0);
}

REGISTER_TYPED_TEST_SUITE_P(MemoryStateImageTest, BasicTest);

INSTANTIATE_TYPED_TEST_SUITE_P(AArch64MemoryStateImageTest,
                               MemoryStateImageTest, AArch64);

INSTANTIATE_TYPED_TEST_SUITE_P(X86_64MemoryStateImageTest, MemoryStateImageTest,
                               X86_64);

}  // namespace

}  // namespace silifuzz::proxies
