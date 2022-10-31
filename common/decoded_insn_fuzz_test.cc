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

#include <sys/user.h>

#include <cstddef>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "fuzztest/fuzztest.h"
#include "./common/decoded_insn.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {
using ::fuzztest::Arbitrary;
using testing::IsOk;

void ConstructorWithRandomInsnBytes(const std::string& bytes) {
  // This should not crash.
  DecodedInsn insn(bytes);
}

FUZZ_TEST(FuzzDecodedInsn, ConstructorWithRandomInsnBytes)
    .WithDomains(Arbitrary<std::string>().WithMaxSize(256));

void MayHaveSplitLockRandomInsnAndRegs(const std::string& bytes,
                                       const std::string& regs) {
  DecodedInsn insn(bytes);
  // If bytes contain a valid locking instruction, may_have_split_lock()
  // should not fail.
  if (insn.is_valid() && insn.is_locking()) {
    struct user_regs_struct regs_struct;
    memcpy(&regs_struct, regs.data(), sizeof(regs_struct));
    EXPECT_THAT(insn.may_have_split_lock(regs_struct), IsOk());
  }
}

FUZZ_TEST(FuzzDecodedInsn, MayHaveSplitLockRandomInsnAndRegs)
    .WithDomains(Arbitrary<std::string>().WithMaxSize(256),
                 Arbitrary<std::string>().WithSize(sizeof(user_regs_struct)));

TEST(FuzzDecodedInsn, ConstructorWithRandomInsnBytesRegression) {
  ConstructorWithRandomInsnBytes(
      std::string("ggKi\274;"
                  "\204j\005kk\017\001\370\032\000\366\362\322\322\2512\020\000"
                  "\000\000\231\200\000\000\000\006k\323",
                  34));
}

}  // namespace

}  // namespace silifuzz
