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

#include "./util/ucontext/serialize.h"

#include <sys/types.h>

#include <cstring>
#include <string>
#include <type_traits>

#include "gtest/gtest.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {
namespace {

// For docs on TYPED_TEST_SUITE:
// http://google.github.io/googletest/reference/testing.html#TYPED_TEST_SUITE
using arch_typelist = testing::Types<ALL_ARCH_TYPES>;

template <class>
struct SerializeTest : testing::Test {};
TYPED_TEST_SUITE(SerializeTest, arch_typelist);

void pattern_init(void* data, size_t size) {
  uint16_t* ptr = reinterpret_cast<uint16_t*>(data);
  for (int i = 0; i < size / sizeof(*ptr); ++i) {
    ptr[i] = (uint16_t)(i + 1) * 63073;
  }
}

TYPED_TEST(SerializeTest, RawGRegs) {
  // Set up a randomized context.
  GRegSet<TypeParam> original;
  pattern_init(&original, sizeof(original));
  ZeroOutGRegsPadding(&original);

  // Copy to user context.
  uint8_t tmp[serialize_internal::SerializedSizeMax<decltype(original)>()];
  memset(&tmp, 0xca, sizeof(tmp));
  ssize_t size = serialize_internal::SerializeGRegs(original, tmp, sizeof(tmp));
  ASSERT_GT(size, 0);
  ASSERT_LE(size, sizeof(tmp));
  ASSERT_TRUE(serialize_internal::MayBeSerializedGRegs<TypeParam>(tmp, size));

  // Copy back.
  GRegSet<TypeParam> bounced;
  memset(&bounced, 0x35, sizeof(bounced));
  size = serialize_internal::DeserializeGRegs(tmp, size, &bounced);
  ASSERT_GT(size, 0);
  ASSERT_LE(size, sizeof(tmp));

  EXPECT_EQ(original, bounced);
}

TYPED_TEST(SerializeTest, WrappedGRegs) {
  // Set up a randomized context.
  GRegSet<TypeParam> original;
  pattern_init(&original, sizeof(original));
  ZeroOutGRegsPadding(&original);

  Serialized<decltype(original)> tmp;
  ASSERT_TRUE(SerializeGRegs(original, &tmp));

  GRegSet<TypeParam> bounced;
  ASSERT_EQ(serialize_internal::DeserializeGRegs(tmp.data, tmp.size, &bounced),
            tmp.size);

  EXPECT_EQ(original, bounced);
}

TYPED_TEST(SerializeTest, StringGRegs) {
  // Set up a randomized context.
  GRegSet<TypeParam> original;
  pattern_init(&original, sizeof(original));
  ZeroOutGRegsPadding(&original);

  std::string tmp;
  ASSERT_TRUE(SerializeGRegs(original, &tmp));
  ASSERT_TRUE(MayBeSerializedGRegs<TypeParam>(tmp));

  GRegSet<TypeParam> bounced;
  ASSERT_TRUE(DeserializeGRegs(tmp, &bounced));
  EXPECT_EQ(original, bounced);
}

TYPED_TEST(SerializeTest, MayBeGRegs_X86_64) {
  // Set up a randomized context.
  GRegSet<X86_64> original;
  pattern_init(&original, sizeof(original));
  ZeroOutGRegsPadding(&original);

  std::string tmp;
  ASSERT_TRUE(SerializeGRegs(original, &tmp));

  constexpr bool expected = std::is_same<ARCH_OF(original), TypeParam>();
  ASSERT_EQ(MayBeSerializedGRegs<TypeParam>(tmp), expected);
}

TYPED_TEST(SerializeTest, MayBeGRegs_AArch64) {
  // Set up a randomized context.
  GRegSet<AArch64> original;
  pattern_init(&original, sizeof(original));
  ZeroOutGRegsPadding(&original);

  std::string tmp;
  ASSERT_TRUE(SerializeGRegs(original, &tmp));

  constexpr bool expected = std::is_same<ARCH_OF(original), TypeParam>();
  ASSERT_EQ(MayBeSerializedGRegs<TypeParam>(tmp), expected);
}

TYPED_TEST(SerializeTest, RawFPRegs) {
  // Set up a randomized context.
  FPRegSet<TypeParam> original;
  pattern_init(&original, sizeof(original));
  ZeroOutFPRegsPadding(&original);

  // Copy to user context.
  uint8_t tmp[serialize_internal::SerializedSizeMax<decltype(original)>()];
  memset(&tmp, 0xca, sizeof(tmp));
  ssize_t size =
      serialize_internal::SerializeFPRegs(original, tmp, sizeof(tmp));
  ASSERT_GT(size, 0);
  ASSERT_LE(size, sizeof(tmp));
  ASSERT_TRUE(serialize_internal::MayBeSerializedFPRegs<TypeParam>(tmp, size));

  // Copy back.
  FPRegSet<TypeParam> bounced;
  memset(&bounced, 0x35, sizeof(bounced));
  size = serialize_internal::DeserializeFPRegs(tmp, size, &bounced);
  ASSERT_GT(size, 0);
  ASSERT_LE(size, sizeof(tmp));

  EXPECT_EQ(original, bounced);
}

TYPED_TEST(SerializeTest, WrappedFPRegs) {
  // Set up a randomized context.
  FPRegSet<TypeParam> original;
  pattern_init(&original, sizeof(original));
  ZeroOutFPRegsPadding(&original);

  Serialized<decltype(original)> tmp;
  ASSERT_TRUE(SerializeFPRegs(original, &tmp));

  FPRegSet<TypeParam> bounced;
  ASSERT_EQ(serialize_internal::DeserializeFPRegs(tmp.data, tmp.size, &bounced),
            tmp.size);
  EXPECT_EQ(original, bounced);
}

TYPED_TEST(SerializeTest, StringFPRegs) {
  // Set up a randomized context.
  FPRegSet<TypeParam> original;
  pattern_init(&original, sizeof(original));
  ZeroOutFPRegsPadding(&original);

  std::string tmp;
  ASSERT_TRUE(SerializeFPRegs(original, &tmp));
  ASSERT_TRUE(MayBeSerializedFPRegs<TypeParam>(tmp));

  FPRegSet<TypeParam> bounced;
  ASSERT_TRUE(DeserializeFPRegs(tmp, &bounced));
  EXPECT_EQ(original, bounced);
}

// Legacy serialization tests will only run on x86_64 because they depend on
// arch-specific system headers.
#if defined(__x86_64__)

TEST(SerializeLegacyTest, GRegs) {
  // Set up a randomized context.
  GRegSet<X86_64> original;
  pattern_init(&original, sizeof(original));
  ZeroOutGRegsPadding(&original);

  // Copy to user context.
  uint8_t tmp[serialize_internal::SerializedSizeMax<decltype(original)>()];
  memset(&tmp, 0xca, sizeof(tmp));
  ssize_t size =
      serialize_internal::SerializeLegacyGRegs(original, tmp, sizeof(tmp));
  ASSERT_GT(size, 0);
  ASSERT_LE(size, sizeof(tmp));
  ASSERT_TRUE(serialize_internal::MayBeSerializedGRegs<X86_64>(tmp, size));

  // Copy back.
  GRegSet<X86_64> bounced;
  memset(&bounced, 0x35, sizeof(bounced));
  // Intentionally using the non-legacy API to show it falls back.
  size = serialize_internal::DeserializeGRegs(tmp, size, &bounced);
  ASSERT_GT(size, 0);
  ASSERT_LE(size, sizeof(tmp));

  EXPECT_EQ(original, bounced);
}

TEST(SerializeLegacyTest, FPRegs) {
  // Set up a randomized context.
  FPRegSet<X86_64> original;
  pattern_init(&original, sizeof(original));
  ZeroOutFPRegsPadding(&original);

  // Copy to user context.
  uint8_t tmp[serialize_internal::SerializedSizeMax<decltype(original)>()];
  memset(&tmp, 0xca, sizeof(tmp));
  ssize_t size =
      serialize_internal::SerializeLegacyFPRegs(original, tmp, sizeof(tmp));
  ASSERT_GT(size, 0);
  ASSERT_LE(size, sizeof(tmp));
  ASSERT_TRUE(serialize_internal::MayBeSerializedFPRegs<X86_64>(tmp, size));

  // Copy back.
  FPRegSet<X86_64> bounced;
  memset(&bounced, 0x35, sizeof(bounced));
  // Intentionally using the non-legacy API to show it falls back.
  size = serialize_internal::DeserializeFPRegs(tmp, size, &bounced);
  ASSERT_GT(size, 0);
  ASSERT_LE(size, sizeof(tmp));

  EXPECT_EQ(original, bounced);
}
#endif

}  // namespace
}  // namespace silifuzz
