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

#include <cstdint>

#include "./util/checks.h"
#include "./util/crc32c_internal.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {
namespace {
constexpr uint8_t kInput[] = "The quick brown fox jumps over the lazy dog";
constexpr size_t kInputSize = sizeof(kInput) - 1;
constexpr uint32_t kInputChecksum = 0x22620404;

template <internal::crc32c_function_ptr crc32c_function>
void BasicTestImpl() {
  alignas(sizeof(uint64_t)) uint8_t buffer[kInputSize + sizeof(uint64_t)];
  // Try different alignments.
  for (size_t i = 0; i < sizeof(uint64_t); ++i) {
    memcpy(buffer + i, kInput, kInputSize);
    CHECK_EQ((*crc32c_function)(0, buffer + i, kInputSize), kInputChecksum);
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

TEST(crc32c, ZeroExtendTables) {
  internal::CRC32CZeroExtensionTable zero =
      internal::CRC32CZeroExtensionTable::Zero();
  internal::CRC32CZeroExtensionTable one =
      internal::CRC32CZeroExtensionTable::One();
  internal::CRC32CZeroExtensionTable two =
      internal::CRC32CZeroExtensionTable::Add(one, one);
  internal::CRC32CZeroExtensionTable three =
      internal::CRC32CZeroExtensionTable::Add(two, one);

  static const uint8_t kZeros[10] = {0};
  uint32_t crc = crc32c(0, kZeros, 1);

  // Wrapper to undo bit-flipping in the CRC32C API. The extension
  // tables are used internally without bit-flipping.
  auto crc_no_bitflip = [](uint32_t crc, const uint8_t* p, size_t n) {
    return internal::crc32c_unaccelerated(crc ^ 0xffffffffUL, p, n) ^
           0xffffffffUL;
    ;
  };

  for (size_t i = 0; i < 10; i++) {
    uint32_t extended_by_one = crc_no_bitflip(crc, kZeros, 1);
    uint32_t extended_by_two = crc_no_bitflip(crc, kZeros, 2);
    uint32_t extended_by_three = crc_no_bitflip(crc, kZeros, 3);

    CHECK_EQ(zero.Extend(crc), crc);
    CHECK_EQ(one.Extend(crc), extended_by_one);
    CHECK_EQ(two.Extend(crc), extended_by_two);
    CHECK_EQ(three.Extend(crc), extended_by_three);

    crc = extended_by_one;
  }
}

TEST(crc32c, ZeroExtend) {
  const uint8_t kZero = 0;
  uint32_t initial_crc = crc32c(0, &kZero, 1);
  uint32_t expected = initial_crc;
  for (size_t i = 0; i < 1000; i++) {
    uint32_t crc = crc32c_zero_extend(initial_crc, i);
    CHECK_EQ(crc, expected);
    // incrementally append a zero to expected CRC for the next iteration.
    expected = crc32c(expected, &kZero, 1);
  }
}

TEST(crc32c, BigBlockSizes) {
  // Use block sizes enough to trigger multi-stream CRC computation if h/w
  // acceleration is available.
  constexpr size_t kBufferSize = 8192;
  alignas(sizeof(uint64_t)) uint8_t buffer[kBufferSize];
  for (int i = 0; i < kBufferSize; ++i) {
    buffer[i] = i;
  }
  // Start with a small size and double size in every iteration.
  // Multi-stream CRC will kick in once we have crossed the size threshold.
  for (size_t size = 64; size <= kBufferSize; size *= 2) {
    uint32_t checksum = crc32c(0, buffer, size);
    uint32_t expected = internal::crc32c_unaccelerated(0, buffer, size);
    CHECK_EQ(checksum, expected);
  }
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(crc32c, BasicTestBestCrcImpl);
  RUN_TEST(crc32c, BasicTestUnaccelerated);
  RUN_TEST(crc32c, IncrementalUpdateBestCrcImpl);
  RUN_TEST(crc32c, IncrementalUpdateUnaccelerated);
  RUN_TEST(crc32c, ZeroExtendTables);
  RUN_TEST(crc32c, ZeroExtend);
  RUN_TEST(crc32c, BigBlockSizes);
})
