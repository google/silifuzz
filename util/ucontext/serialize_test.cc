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

void pattern_init(void* data, size_t size) {
  uint16_t* ptr = reinterpret_cast<uint16_t*>(data);
  for (int i = 0; i < size / sizeof(*ptr); ++i) {
    ptr[i] = (uint16_t)(i + 1) * 63073;
  }
}

TEST(SerializeTest, RawGRegs) {
  // Set up a randomized context.
  GRegSet original;
  pattern_init(&original, sizeof(original));
  ZeroOutGRegsPadding(&original);

  // Copy to user context.
  uint8_t tmp[serialize_internal::kSerializeGRegsMaxSize];
  memset(&tmp, 0xca, sizeof(tmp));
  ASSERT_EQ(serialize_internal::SerializeGRegs(original, tmp, sizeof(tmp)),
            sizeof(tmp));

  // Copy back.
  GRegSet bounced;
  memset(&bounced, 0x35, sizeof(bounced));
  ASSERT_EQ(serialize_internal::DeserializeGRegs(tmp, sizeof(tmp), &bounced),
            sizeof(tmp));

  EXPECT_EQ(original, bounced);
}

TEST(SerializeTest, WrappedGRegs) {
  // Set up a randomized context.
  GRegSet original;
  pattern_init(&original, sizeof(original));
  ZeroOutGRegsPadding(&original);

  SerializedGRegs tmp;
  ASSERT_TRUE(SerializeGRegs(original, &tmp));

  GRegSet bounced;
  ASSERT_EQ(serialize_internal::DeserializeGRegs(tmp.data, tmp.size, &bounced),
            tmp.size);

  EXPECT_EQ(original, bounced);
}

TEST(SerializeTest, StringGRegs) {
  // Set up a randomized context.
  GRegSet original;
  pattern_init(&original, sizeof(original));
  ZeroOutGRegsPadding(&original);

  std::string tmp;
  ASSERT_TRUE(SerializeGRegs(original, &tmp));

  GRegSet bounced;
  ASSERT_TRUE(DeserializeGRegs(tmp, &bounced));
  EXPECT_EQ(original, bounced);
}

TEST(SerializeTest, RawFPRegs) {
  // Set up a randomized context.
  FPRegSet original;
  pattern_init(&original, sizeof(original));
  ZeroOutFPRegsPadding(&original);

  // Copy to user context.
  uint8_t tmp[serialize_internal::kSerializeFPRegsMaxSize];
  memset(&tmp, 0xca, sizeof(tmp));
  ASSERT_EQ(serialize_internal::SerializeFPRegs(original, tmp, sizeof(tmp)),
            sizeof(tmp));

  // Copy back.
  FPRegSet bounced;
  memset(&bounced, 0x35, sizeof(bounced));
  ASSERT_EQ(serialize_internal::DeserializeFPRegs(tmp, sizeof(tmp), &bounced),
            sizeof(tmp));

  // For some reason EXPECT_EQ cannot find the equality operator when FPRegSet
  // is typedefed.
  EXPECT_TRUE(original == bounced);
}

TEST(SerializeTest, WrappedFPRegs) {
  // Set up a randomized context.
  FPRegSet original;
  pattern_init(&original, sizeof(original));
  ZeroOutFPRegsPadding(&original);

  SerializedFPRegs tmp;
  ASSERT_TRUE(SerializeFPRegs(original, &tmp));

  FPRegSet bounced;
  ASSERT_EQ(serialize_internal::DeserializeFPRegs(tmp.data, tmp.size, &bounced),
            tmp.size);
  EXPECT_TRUE(original == bounced);
}

TEST(SerializeTest, StringFPRegs) {
  // Set up a randomized context.
  FPRegSet original;
  pattern_init(&original, sizeof(original));
  ZeroOutFPRegsPadding(&original);

  std::string tmp;
  ASSERT_TRUE(SerializeFPRegs(original, &tmp));

  FPRegSet bounced;
  ASSERT_TRUE(DeserializeFPRegs(tmp, &bounced));
  EXPECT_TRUE(original == bounced);
}

}  // namespace
}  // namespace silifuzz
