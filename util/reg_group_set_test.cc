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

#include "./util/reg_group_set.h"

#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/nolibc_gunit.h"
#include "./util/reg_group_bits.h"
namespace silifuzz {

namespace {

template <typename Arch>
void BasicTestImpl() {
  RegisterGroupSet<Arch> reg_group_set;
  CHECK(reg_group_set.Empty());

  constexpr uint64_t kBits = 42;
  constexpr RegisterGroupSet<Arch> constexpr_reg_group_set =
      RegisterGroupSet<Arch>::Deserialize(kBits);
  static_assert(!constexpr_reg_group_set.Empty());
  static_assert(constexpr_reg_group_set.Serialize() == kBits);

  reg_group_set = constexpr_reg_group_set;
  CHECK_EQ(reg_group_set.Serialize(), kBits);
  CHECK(constexpr_reg_group_set == reg_group_set);
  CHECK(RegisterGroupSet<Arch>{} != reg_group_set);
}

TEST(RegisterGroupSet, BasicTest) {
  BasicTestImpl<AArch64>();
  BasicTestImpl<X86_64>();
}

// Test accessors
#define TOGGLE_GROUP(name)             \
  do {                                 \
    CHECK(reg_group_set.Empty());      \
    CHECK(!reg_group_set.Get##name()); \
    reg_group_set.Set##name(true);     \
    CHECK(reg_group_set.Get##name());  \
    reg_group_set.Set##name(false);    \
    CHECK(!reg_group_set.Get##name()); \
  } while (0)

TEST(RegisterGroupSet, ToggleX86_64Groups) {
  RegisterGroupSet<X86_64> reg_group_set;
  TOGGLE_GROUP(GPR);
  TOGGLE_GROUP(FPRAndSSE);
  TOGGLE_GROUP(AVX);
  TOGGLE_GROUP(AVX512);
  TOGGLE_GROUP(AMX);
}

TEST(RegisterGroupSet, ToggleAArch64Groups) {
  RegisterGroupSet<AArch64> reg_group_set;
  TOGGLE_GROUP(GPR);
  TOGGLE_GROUP(FPR);
  TOGGLE_GROUP(SVE);
}

#undef TOGGLE_GROUP

// Test bit encoding.
#define VERIFY_ENCODING(name, bit)                  \
  do {                                              \
    reg_group_set = {};                             \
    reg_group_set.Set##name(true);                  \
    CHECK_EQ(reg_group_set.Serialize(), bit);       \
    reg_group_set = reg_group_set.Deserialize(bit); \
    CHECK(reg_group_set.Get##name());               \
  } while (0)

TEST(RegisterGroupSet, X86_64BitEncoding) {
  RegisterGroupSet<X86_64> reg_group_set;
  VERIFY_ENCODING(GPR, X86_REG_GROUP_GPR);
  VERIFY_ENCODING(FPRAndSSE, X86_REG_GROUP_FPR_AND_SSE);
  VERIFY_ENCODING(AVX, X86_REG_GROUP_AVX);
  VERIFY_ENCODING(AVX512, X86_REG_GROUP_AVX512);
  VERIFY_ENCODING(AMX, X86_REG_GROUP_AMX);
}

TEST(RegisterGroupSet, AArch64BitEncoding) {
  RegisterGroupSet<AArch64> reg_group_set;
  VERIFY_ENCODING(GPR, AARCH64_REG_GROUP_GPR);
  VERIFY_ENCODING(FPR, AARCH64_REG_GROUP_FPR);
  VERIFY_ENCODING(SVE, AARCH64_REG_GROUP_SVE);
}

#undef VERIFY_ENCODING

}  // namespace

}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(RegisterGroupSet, BasicTest);
  RUN_TEST(RegisterGroupSet, ToggleX86_64Groups);
  RUN_TEST(RegisterGroupSet, ToggleAArch64Groups);
  RUN_TEST(RegisterGroupSet, X86_64BitEncoding);
  RUN_TEST(RegisterGroupSet, AArch64BitEncoding);
})
