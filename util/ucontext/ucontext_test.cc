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

#include <type_traits>

#include "gtest/gtest.h"
#include "./util/arch.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

namespace {

using arch_typelist = testing::Types<ALL_ARCH_TYPES>;

template <class>
struct UContextGeneric : testing::Test {};
TYPED_TEST_SUITE(UContextGeneric, arch_typelist);

TYPED_TEST(UContextGeneric, UContextSize) {
  // No padding.
  EXPECT_EQ(sizeof(UContext<TypeParam>),
            sizeof(GRegSet<TypeParam>) + sizeof(FPRegSet<TypeParam>));

  // Historically we played some tricks with the alignment of FPRegSet.
  // We aren't playing any tricks right now, but still check things are OK.
  EXPECT_GE(alignof(UContext<TypeParam>), alignof(GRegSet<TypeParam>));
  EXPECT_GE(alignof(UContext<TypeParam>), alignof(FPRegSet<TypeParam>));
}

TYPED_TEST(UContextGeneric, ConsistentArch) {
  // Extra parenthesis needed to play well with preprocessor because of commas
  // in the type parameters.
  EXPECT_TRUE((std::is_same<typename GRegSet<TypeParam>::Arch, TypeParam>()));
  EXPECT_TRUE((std::is_same<typename FPRegSet<TypeParam>::Arch, TypeParam>()));
  EXPECT_TRUE((std::is_same<typename UContext<TypeParam>::Arch, TypeParam>()));

  UContext<TypeParam> uctx;
  EXPECT_TRUE((std::is_same<ARCH_OF(uctx), TypeParam>()));
  EXPECT_TRUE((std::is_same<ARCH_OF(uctx.gregs), TypeParam>()));
  EXPECT_TRUE((std::is_same<ARCH_OF(uctx.fpregs), TypeParam>()));
}

TYPED_TEST(UContextGeneric, RegsEquality) {
  GRegSet<TypeParam> gregs;
  ASSERT_EQ(gregs, gregs);
  ASSERT_FALSE(gregs != gregs);
  FPRegSet<TypeParam> fpregs;
  ASSERT_EQ(fpregs, fpregs);
  ASSERT_FALSE(fpregs != fpregs);
}

TYPED_TEST(UContextGeneric, View) {
  UContext<TypeParam> uctx;
  UContextView<TypeParam> const_view(uctx);
  EXPECT_TRUE((std::is_same<ARCH_OF(const_view), TypeParam>()));
}

}  // namespace

}  // namespace silifuzz
