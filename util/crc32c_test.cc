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

#include "./util/crc32c.h"

#include <string.h>

#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {
namespace {
constexpr char kInput[] = "The quick brown fox jumps over the lazy dog";
constexpr uint32_t kInputChecksum = 0x22620404;

template <internal::crc32c_function_ptr crc32c_function>
void BasicTestImpl() {
  constexpr size_t n = sizeof(kInput) - 1;
  alignas(sizeof(uint64_t)) uint8_t buffer[n + sizeof(uint64_t)];
  // Try different alignments.
  for (size_t i = 0; i < sizeof(uint64_t); ++i) {
    memcpy(buffer + i, kInput, n);
    CHECK_EQ((*crc32c_function)(0, buffer + i, n), kInputChecksum);
  }
}

// This test crc32_accelerated if h/w acceleration is available.
// Otherwise, it just tests the unaccelerated one.
TEST(crc32c, BasicTestBestCrcImpl) { BasicTestImpl<&crc32c>(); }

TEST(crc32c, BasicTestUnaccelerated) {
  BasicTestImpl<&internal::crc32c_unaccelerated>();
}

template <internal::crc32c_function_ptr crc32c_function>
void IncrementalUpdateTestImpl() {
  uint64_t crc = 0;
  const uint8_t* p = reinterpret_cast<const uint8_t*>(kInput);
  const size_t n = sizeof(kInput) - 1;
  const size_t half = n / 2;
  crc = (*crc32c_function)(crc, p, half);
  crc = (*crc32c_function)(crc, p + half, n - half);
  CHECK_EQ(crc, kInputChecksum);
}

// This tests crc32_accelerated if h/w acceleration is available.
// Otherwise, it just tests the unaccelerated one.
TEST(crc32c, IncrementalUpdateBestCrcImpl) {
  IncrementalUpdateTestImpl<crc32c>();
}

TEST(crc32c, IncrementalUpdateUnaccelerated) {
  IncrementalUpdateTestImpl<internal::crc32c_unaccelerated>();
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(crc32c, BasicTestBestCrcImpl);
  RUN_TEST(crc32c, BasicTestUnaccelerated);
  RUN_TEST(crc32c, IncrementalUpdateBestCrcImpl);
  RUN_TEST(crc32c, IncrementalUpdateUnaccelerated);
})
