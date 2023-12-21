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

#include "./util/cpu_features.h"

#include "gtest/gtest.h"
#include "./util/itoa.h"

namespace silifuzz {

namespace {

TEST(X86CPUFeatures, EnumStr) {
#define CHECK_ENUM(name) EXPECT_STREQ(EnumStr(X86CPUFeatures::k##name), #name);
  CHECK_ENUM(AMX_TILE);
  CHECK_ENUM(AVX);
  CHECK_ENUM(AVX512BW);
  CHECK_ENUM(AVX512F);
  CHECK_ENUM(OSXSAVE);
  CHECK_ENUM(SSE);
  CHECK_ENUM(SSE4_2);
  CHECK_ENUM(XSAVE);
#undef CHECK_ENUM
}

}  // namespace

}  // namespace silifuzz
