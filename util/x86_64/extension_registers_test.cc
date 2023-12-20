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

#include <x86intrin.h>

#include <cstring>

#include "gtest/gtest.h"
#include "./util/cpu_features.h"
#include "./util/x86_64/extension_registers_test_helpers.h"

namespace silifuzz {
namespace {

// Fill a block of memory with no trivial repeated patterns in extension
// registers. We want to avoid the situation when 2 different registers have
// the same values in a test.
void FillPattern(uint8_t* buffer, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    buffer[i] = i % 251;  // prime.
  }
}

// All SSE, AVX and AVX-512 registers are like arrays. We can share lots of
// test code by factoring out the differences into *TypeInfo structs below.
struct XMMTypeInfo {
  typedef __m128 ElementType;
  static constexpr size_t kNumElements = 16;
};

struct YMMTypeInfo {
  typedef __m256 ElementType;
  static constexpr size_t kNumElements = 16;
};

struct ZMMTypeInfo {
  typedef __m512 ElementType;
  static constexpr size_t kNumElements = 32;
};

struct Opmask16TypeInfo {
  // Opmask16 functions operate on uint64_t
  typedef uint64_t ElementType;
  static constexpr size_t kNumElements = 8;
};

struct Opmask64TypeInfo {
  typedef uint64_t ElementType;
  static constexpr size_t kNumElements = 8;
};

// XMM/YMM/ZMM Save test: This tests that registers are saved in the right
// order.
template <typename TypeInfo, void helper(typename TypeInfo::ElementType*)>
void XYZMMSaveTestImpl() {
  typename TypeInfo::ElementType output[TypeInfo::kNumElements];
  memset(output, 0xff, sizeof(output));
  helper(output);
  for (size_t i = 0; i < TypeInfo::kNumElements; ++i) {
    EXPECT_EQ(output[i][0], i) << "mismatch at index " << i;
  }
}

// Opmask Save test: This is similar to XYZMMSaveTestImpl.
template <typename TypeInfo, void helper(typename TypeInfo::ElementType*)>
void OpmaskSaveTestImpl() {
  typename TypeInfo::ElementType output[TypeInfo::kNumElements];
  memset(output, 0xff, sizeof(output));
  helper(output);
  for (size_t i = 0; i < TypeInfo::kNumElements; ++i) {
    EXPECT_EQ(output[i], i) << "mismatch at index " << i;
  }
}

// Round-trip test: This test that loading random data and saving gets the
// same random data. If this passes, we know that the load register function
// is correct IF the save register function is correct.  The save function
// is verify by itself using another unit test.
template <typename TypeInfo, void helper(const typename TypeInfo::ElementType*,
                                         typename TypeInfo::ElementType*)>
void RoundTripTestImpl() {
  typename TypeInfo::ElementType input[TypeInfo::kNumElements],
      output[TypeInfo::kNumElements];
  FillPattern(reinterpret_cast<uint8_t*>(input), sizeof(input));
  memset(output, 0, sizeof(output));
  helper(input, output);
  for (size_t i = 0; i < TypeInfo::kNumElements; ++i) {
    EXPECT_EQ(memcmp(&input[i], &output[i], sizeof(input[i])), 0)
        << "mismatch at index " << i;
  }
}

// Clear test: This tests the register clearing function, assuming that both
// the register loading and saving functions work correctly.
template <typename TypeInfo, void helper(const typename TypeInfo::ElementType*,
                                         typename TypeInfo::ElementType*)>
void ClearTestImpl() {
  typename TypeInfo::ElementType input[TypeInfo::kNumElements],
      output[TypeInfo::kNumElements], empty[TypeInfo::kNumElements];
  memset(input, 0xff, sizeof(input));
  memset(output, 0xaa, sizeof(output));
  memset(empty, 0, sizeof(empty));
  helper(input, output);
  for (size_t i = 0; i < TypeInfo::kNumElements; ++i) {
    EXPECT_EQ(memcmp(&empty[i], &output[i], sizeof(empty[i])), 0)
        << "mismatch at index " << i;
  }
}

TEST(ExtenstionRegistrs, XMMSave) {
  if (!HasX86CPUFeature(X86CPUFeatures::kSSE))
    GTEST_SKIP() << "SSE not supported";
  XYZMMSaveTestImpl<XMMTypeInfo, XMMSaveTestHelper>();
}

TEST(ExtenstionRegistrs, XMMRoundTrip) {
  if (!HasX86CPUFeature(X86CPUFeatures::kSSE))
    GTEST_SKIP() << "SSE not supported";
  RoundTripTestImpl<XMMTypeInfo, XMMRoundTripTestHelper>();
}

TEST(ExtenstionRegistrs, XMMClear) {
  if (!HasX86CPUFeature(X86CPUFeatures::kSSE))
    GTEST_SKIP() << "SSE not supported";
  ClearTestImpl<XMMTypeInfo, XMMClearTestHelper>();
}

TEST(ExtenstionRegistrs, YMMSave) {
  if (!HasX86CPUFeature(X86CPUFeatures::kAVX))
    GTEST_SKIP() << "AVX not supported";
  XYZMMSaveTestImpl<YMMTypeInfo, YMMSaveTestHelper>();
}

TEST(ExtenstionRegistrs, YMMRoundTrip) {
  if (!HasX86CPUFeature(X86CPUFeatures::kAVX))
    GTEST_SKIP() << "AVX not supported";
  RoundTripTestImpl<YMMTypeInfo, YMMRoundTripTestHelper>();
}

TEST(ExtenstionRegistrs, YMMClear) {
  if (!HasX86CPUFeature(X86CPUFeatures::kAVX))
    GTEST_SKIP() << "AVX not supported";
  ClearTestImpl<YMMTypeInfo, YMMClearTestHelper>();
}

TEST(ExtenstionRegistrs, ZMMSave) {
  if (!HasX86CPUFeature(X86CPUFeatures::kAVX512F))
    GTEST_SKIP() << "AVX-512F not supported";
  XYZMMSaveTestImpl<ZMMTypeInfo, ZMMSaveTestHelper>();
}

TEST(ExtenstionRegistrs, ZMMRoundTrip) {
  if (!HasX86CPUFeature(X86CPUFeatures::kAVX512F))
    GTEST_SKIP() << "AVX-512F not supported";
  RoundTripTestImpl<ZMMTypeInfo, ZMMRoundTripTestHelper>();
}

TEST(ExtenstionRegistrs, ZMMClear) {
  if (!HasX86CPUFeature(X86CPUFeatures::kAVX512F))
    GTEST_SKIP() << "AVX-512F not supported";
  ClearTestImpl<ZMMTypeInfo, ZMMClearTestHelper>();
}

TEST(ExtenstionRegistrs, Opmask16Save) {
  if (!HasX86CPUFeature(X86CPUFeatures::kAVX512F))
    GTEST_SKIP() << "AVX-512F not supported";
  OpmaskSaveTestImpl<Opmask16TypeInfo, Opmask16SaveTestHelper>();
}

TEST(ExtenstionRegistrs, Opmask64ave) {
  if (!HasX86CPUFeature(X86CPUFeatures::kAVX512BW))
    GTEST_SKIP() << "AVX-512BW not supported";
  OpmaskSaveTestImpl<Opmask64TypeInfo, Opmask64SaveTestHelper>();
}

TEST(ExtenstionRegistrs, Opmask16RoundTrip) {
  if (!HasX86CPUFeature(X86CPUFeatures::kAVX512F))
    GTEST_SKIP() << "AVX-512F not supported";
  constexpr size_t kNumElements = 8;
  uint64_t input[kNumElements], output[kNumElements];
  FillPattern(reinterpret_cast<uint8_t*>(input), sizeof(input));
  memset(output, 0, sizeof(output));
  Opmask16RoundTripTestHelper(input, output);
  for (size_t i = 0; i < kNumElements; ++i) {
    // 16-bit opmasks are saved as uint64_t with upper 48 bits cleared.
    EXPECT_EQ(input[i] & 0xffff, output[i]) << "mismatch at index " << i;
  }
}

TEST(ExtenstionRegistrs, Opmask64RoundTrip) {
  if (!HasX86CPUFeature(X86CPUFeatures::kAVX512BW))
    GTEST_SKIP() << "AVX-512BW not supported";
  RoundTripTestImpl<Opmask64TypeInfo, Opmask64RoundTripTestHelper>();
}

TEST(ExtenstionRegistrs, Opmask16Clear) {
  if (!HasX86CPUFeature(X86CPUFeatures::kAVX512F))
    GTEST_SKIP() << "AVX-512F not supported";
  ClearTestImpl<Opmask16TypeInfo, Opmask16ClearTestHelper>();
}

TEST(ExtenstionRegistrs, Opmask64Clear) {
  if (!HasX86CPUFeature(X86CPUFeatures::kAVX512BW))
    GTEST_SKIP() << "AVX-512BW not supported";
  ClearTestImpl<Opmask64TypeInfo, Opmask64ClearTestHelper>();
}

}  // namespace

}  // namespace silifuzz
