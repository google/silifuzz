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

#include "./util/mem_util.h"

#include <cstdint>
#include <cstring>

#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

// ========================================================================= //

namespace silifuzz {
namespace {

struct alignas(sizeof(uint64_t)) TestBuffer {
  static constexpr size_t kBufferSize = 128;

  // Large test data size supported by GenerateData();
  static constexpr size_t kMaxDataSize = kBufferSize - 2 * sizeof(uint64_t);
  char data[kBufferSize];

  TestBuffer() {
    CHECK_EQ(reinterpret_cast<uintptr_t>(data) % sizeof(uint64_t), 0);
    Reset();
  }

  // Clears test data buffer with a given filler value.
  void Reset(char filler = 0) { memset(data, 0, sizeof(data)); }

  // Generates a test patterns with 'size' bytes and returns a pointer to
  // the first byte. The returned pointer has an 8-byte alignment offset
  // as 'offset' % 8. Generate() returns the same pattern for the same
  // 'size'.  All the bytes not covered by the generated data are
  // zero. The bytes immediately before and after the test data are guranteed
  // to be inside the buffer, i.e ptr[-1] and ptr[size] are valid.
  char* Generate(size_t size, size_t offset);

  // Allocate a buffer of 'size' as a destination for MemCopy and returns a
  // pointer to buffer. The returned pointer has an 8-byte alignment offset as
  // 'offset' % 8. The bytes immediately before and after the test data are
  // guranteed to be inside the buffer, i.e ptr[-1] and ptr[size] are valid.
  char* AllocateCopyBuffer(size_t size, size_t offset);
};

char* TestBuffer::Generate(size_t size, size_t offset) {
  CHECK_LE(size, kMaxDataSize);
  Reset();

  // Offset of the byte before generated data.
  const size_t pre_offset = (offset - 1) % sizeof(uint64_t);
  char* ptr = &data[pre_offset + 1];
  for (size_t i = 0; i < size; ++i) {
    ptr[i] = i + 1;
  }

  return ptr;
}

char* TestBuffer::AllocateCopyBuffer(size_t size, size_t offset) {
  CHECK_LE(size, kMaxDataSize);
  Reset();

  // Offset of the byte before generated data.
  const size_t pre_offset = (offset - 1) % sizeof(uint64_t);
  return &data[pre_offset + 1];
}

TEST(Memeq, Equal) {
  TestBuffer buffer1, buffer2;

  // Empty ranges are always equal.
  CHECK(MemEq(nullptr, nullptr, 0));
  CHECK(MemEq(buffer1.Generate(4, 0), buffer2.Generate(4, 0) + 1, 0));

  auto EqualTestHelper = [&buffer1, &buffer2](size_t size) {
    char* ptr1 = buffer1.Generate(size, 0);
    // Flip bytes before and after data to check over shoot.
    ptr1[-1] ^= 0xff;
    ptr1[size] ^= 0xff;

    // Both ranges are aligned.
    CHECK(MemEq(ptr1, buffer2.Generate(size, 0), size));

    // One of the ranges is unaligned, this should fall back to bcmp().
    CHECK(MemEq(ptr1, buffer2.Generate(size, 1), size));
  };

  // Size is aligned.
  EqualTestHelper(sizeof(uint64_t));

  // Size is not aligned.
  EqualTestHelper(sizeof(uint64_t) - 1);
}

TEST(Memeq, NotEqual) {
  TestBuffer buffer1, buffer2;

  auto NotEqualTestHelper = [&buffer1, &buffer2](size_t size) {
    char* ptr1 = buffer1.Generate(size, 0);
    // Flip middle byte.
    ptr1[size / 2] ^= 0xff;

    // Both ranges are aligned.
    CHECK(!MemEq(ptr1, buffer2.Generate(size, 0), size));

    // One of the ranges is unaligned, this should fall back to bcmp().
    CHECK(!MemEq(ptr1, buffer2.Generate(size, 1), size));
  };

  // Size is aligned.
  NotEqualTestHelper(sizeof(uint64_t));

  // Size is not aligned.
  NotEqualTestHelper(sizeof(uint64_t) - 1);
}

TEST(MemCopy, BasicTest) {
  TestBuffer buffer1, buffer2;

  auto MemCopyTestHelper = [&buffer1, &buffer2](size_t size) {
    char* ptr1 = buffer1.Generate(size, 0);

    // Both ranges are aligned.
    buffer2.Reset(0x55);
    char* ptr2 = buffer2.AllocateCopyBuffer(size, 0);
    MemCopy(ptr2, ptr1, size);
    CHECK(MemEq(ptr1, ptr2, size));

    // One of the ranges is unaligned.
    buffer2.Reset(0xaa);
    ptr2 = buffer2.AllocateCopyBuffer(size, 1);
    MemCopy(ptr2, ptr1, size);
    CHECK(MemEq(ptr1, ptr2, size));
  };

  // Size is aligned.
  MemCopyTestHelper(sizeof(uint64_t) * 2);

  // Size is not aligned.
  MemCopyTestHelper(sizeof(uint64_t) * 2 - 1);
}

TEST(MemSet, BasicTest) {
  TestBuffer buffer;

  auto MemSetTestHelper = [&buffer](size_t size, size_t offset) {
    // Both ranges are aligned.
    buffer.Reset();
    constexpr uint8_t kData = 42;
    char* ptr = buffer.AllocateCopyBuffer(size, 0);
    MemSet(ptr, kData, size);
    CHECK(MemAllEqualTo(ptr, kData, size));
    // Check no overwrite.
    CHECK_EQ(ptr[-1], 0);
    CHECK_EQ(ptr[size], 0);
  };

  // Address and size are aligned.
  MemSetTestHelper(sizeof(uint64_t) * 2, 0);
  // Only size is aligned.
  MemSetTestHelper(sizeof(uint64_t) * 2, 1);
  // Only address is aligned
  MemSetTestHelper(sizeof(uint64_t) * 2 - 1, 0);
  // Both address and size are unaligned.
  MemSetTestHelper(sizeof(uint64_t) * 2 - 1, 1);
}

TEST(MemAllEqualTo, BasicTest) {
  TestBuffer buffer;

  struct TestCase {
   public:
    constexpr TestCase(size_t o, size_t s) : offset(o), size(s) {}

    // Offset of source address from 8-byte alignment boundary.
    // If this % 8 != 0, the test address is mis-aligned.
    size_t offset;

    // Number of bytes to be set.
    size_t size;
  };

  constexpr size_t kNumTestCase = 7;
  constexpr TestCase test_cases[kNumTestCase] = {
      // 0 byte case should be a no-op.
      {1, 0},

      // aligned test cases.
      {0, 8},   // small size
      {0, 64},  // big size to test unrolling.

      // mis-aligned test cases.
      {1, 8},
      {0, 9},
      {1, 9},
      {4, 2},
  };

  for (const auto& [offset, size] : test_cases) {
    char* ptr = buffer.AllocateCopyBuffer(size, offset);
    buffer.Reset();

    constexpr uint8_t kData = 0xaa;
    for (size_t i = 0; i < size; ++i) {
      ptr[i] = kData;
    }

    CHECK(MemAllEqualTo(ptr, kData, size));

    if (size != 0) {
      ptr[size / 2] ^= 0xff;
      CHECK(!MemAllEqualTo(ptr, kData, size));
    }
  }
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(Memeq, Equal);
  RUN_TEST(Memeq, NotEqual);
  RUN_TEST(MemCopy, BasicTest);
  RUN_TEST(MemSet, BasicTest);
  RUN_TEST(MemAllEqualTo, BasicTest);
})
