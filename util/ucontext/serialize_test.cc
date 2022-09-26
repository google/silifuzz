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

#include <string>

#include "gtest/gtest.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {
namespace {

// For docs on TYPED_TEST_SUITE:
// http://google.github.io/googletest/reference/testing.html#TYPED_TEST_SUITE
// TODO(ncbray): enable x86_64 serialization on other arches.
#if defined(__x86_64__)
using arch_typelist = testing::Types<X86_64, AArch64>;
#else
using arch_typelist = testing::Types<AArch64>;
#endif

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
  ASSERT_EQ(serialize_internal::SerializeGRegs(original, tmp, sizeof(tmp)),
            sizeof(tmp));

  // Copy back.
  GRegSet<TypeParam> bounced;
  memset(&bounced, 0x35, sizeof(bounced));
  ASSERT_EQ(serialize_internal::DeserializeGRegs(tmp, sizeof(tmp), &bounced),
            sizeof(tmp));

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

  GRegSet<TypeParam> bounced;
  ASSERT_TRUE(DeserializeGRegs(tmp, &bounced));
  EXPECT_EQ(original, bounced);
}

TYPED_TEST(SerializeTest, RawFPRegs) {
  // Set up a randomized context.
  FPRegSet<TypeParam> original;
  pattern_init(&original, sizeof(original));
  ZeroOutFPRegsPadding(&original);

  // Copy to user context.
  uint8_t tmp[serialize_internal::SerializedSizeMax<decltype(original)>()];
  memset(&tmp, 0xca, sizeof(tmp));
  ASSERT_EQ(serialize_internal::SerializeFPRegs(original, tmp, sizeof(tmp)),
            sizeof(tmp));

  // Copy back.
  FPRegSet<TypeParam> bounced;
  memset(&bounced, 0x35, sizeof(bounced));
  ASSERT_EQ(serialize_internal::DeserializeFPRegs(tmp, sizeof(tmp), &bounced),
            sizeof(tmp));

  // For some reason EXPECT_EQ cannot find the equality operator when FPRegSet
  // is typedefed.
  EXPECT_TRUE(original == bounced);
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
  EXPECT_TRUE(original == bounced);
}

TYPED_TEST(SerializeTest, StringFPRegs) {
  // Set up a randomized context.
  FPRegSet<TypeParam> original;
  pattern_init(&original, sizeof(original));
  ZeroOutFPRegsPadding(&original);

  std::string tmp;
  ASSERT_TRUE(SerializeFPRegs(original, &tmp));

  FPRegSet<TypeParam> bounced;
  ASSERT_TRUE(DeserializeFPRegs(tmp, &bounced));
  EXPECT_TRUE(original == bounced);
}

}  // namespace
}  // namespace silifuzz
