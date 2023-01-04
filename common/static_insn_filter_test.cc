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

#include "./common/static_insn_filter.h"

#include "gtest/gtest.h"
#include "./util/arch.h"

namespace silifuzz {

namespace {

std::string FromInts(std::vector<uint32_t>&& data) {
  return std::string(reinterpret_cast<char*>(&*data.begin()),
                     reinterpret_cast<char*>(&*data.end()));
}

#define EXPECT_AARCH64_FILTER_ACCEPT(insn) \
  EXPECT_TRUE(StaticInstructionFilter<AArch64>(FromInts(insn)))

#define EXPECT_AARCH64_FILTER_REJECT(insn) \
  EXPECT_FALSE(StaticInstructionFilter<AArch64>(FromInts(insn)))

TEST(StaticInsnFilter, ReadTPIDR) {
  // We'll want to filter our a number of system register accesses in the
  // future, but this one should stay valid.
  // mrs    x0, tpidr_el0
  EXPECT_AARCH64_FILTER_ACCEPT({0xd53bd040});
}

TEST(StaticInsnFilter, LDXRB) {
  // The filter for store exclusive should not hit load exclusive.
  // ldxrb     w16, [x6]
  EXPECT_AARCH64_FILTER_ACCEPT({0x085f7cd0});
}

TEST(StaticInsnFilter, STR) {
  // The filter for store exclusive should not hit normal stores.
  // str     w16, [x6]
  EXPECT_AARCH64_FILTER_ACCEPT({0xb90000d0});
}

TEST(StaticInsnFilter, STXRB) {
  // Store exclusive is effectively non-deterministic.
  // stxrb     w4, w16, [x6]
  EXPECT_AARCH64_FILTER_REJECT({0x080400d0});
}

TEST(StaticInsnFilter, STXP) {
  // Store exclusive is effectively non-deterministic.
  // stxp     w11, w13, w21, [x6]
  EXPECT_AARCH64_FILTER_REJECT({0x882b54cd});
}

}  // namespace

}  // namespace silifuzz
