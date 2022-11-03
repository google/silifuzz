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

#include "./proxies/unicorn_x86_64.h"

#include <cstdint>
#include <limits>
#include <vector>

#include "gtest/gtest.h"
#include "absl/random/distributions.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "./util/testing/status_matchers.h"
#include "third_party/unicorn/unicorn.h"

namespace {

using silifuzz::testing::IsOkAndHolds;
using silifuzz::testing::StatusIs;

auto run_bytes(std::vector<uint8_t>&& data) {
  return silifuzz::RunInstructions(
      {reinterpret_cast<const char*>(data.data()), data.size()});
}

TEST(UnicornX86_64, Nop) {
  EXPECT_THAT(run_bytes({0x90}), IsOkAndHolds(UC_ERR_OK));
}

TEST(UnicornX86_64, Hlt) {
  EXPECT_THAT(run_bytes({0xF4}), IsOkAndHolds(UC_ERR_OK));
}

TEST(UnicornX86_64, ReadMappedMem) {
  // movabs eax,ds:0x1000010000
  EXPECT_THAT(run_bytes({0xA1, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00}),
              IsOkAndHolds(UC_ERR_OK));
}

TEST(UnicornX86_64, ReadUnmappedMem) {
  // mov eax, dword ptr [0]
  EXPECT_THAT(run_bytes({0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00}),
              IsOkAndHolds(UC_ERR_READ_UNMAPPED));
}

TEST(UnicornX86_64, Loop10) {
  // xor rcx, rcx
  // mov cl, 10
  // loop .
  EXPECT_THAT(run_bytes({0x48, 0x31, 0xC9, 0xB1, 0x0A, 0xE2, 0xFE}),
              IsOkAndHolds(UC_ERR_OK));
}

TEST(UnicornX86_64, Runaway) {
  //  jmp .
  EXPECT_THAT(run_bytes({0xEB, 0xFE}), StatusIs(absl::StatusCode::kOutOfRange));
}

TEST(UnicornX86_64, JmpFar) {
  // jmp .+0x60
  EXPECT_THAT(run_bytes({0xEB, 0x60}), IsOkAndHolds(UC_ERR_EXCEPTION));
}

TEST(UnicornX86_64, UD) {
  EXPECT_THAT(run_bytes({0x0F, 0xFF}), IsOkAndHolds(UC_ERR_INSN_INVALID));
}

TEST(UnicornX86_64, ReadFewPages) {
  /* Attempt to touch few pages
    0:  48 c7 c1 00 01 00 00    mov    rcx,0x5
    7:  48 be 00 00 01 00 10    movabs rsi,0x1000010000
    e:  00 00 00
    11: 48 8b 06                mov    rax,QWORD PTR [rsi]
    14: 48 81 c6 00 10 00 00    add    rsi,0x1000
    1b: e2 f4                   loop   0x11
  */
  EXPECT_THAT(
      run_bytes({0x48, 0xC7, 0xC1, 0x05, 0x00, 0x00, 0x00, 0x48, 0xBE, 0x00,
                 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x06,
                 0x48, 0x81, 0xC6, 0x00, 0x10, 0x00, 0x00, 0xE2, 0xF4}),
      IsOkAndHolds(UC_ERR_OK));
}

TEST(UnicornX86_64, ReadManyPages) {
  /* Attempt to touch many pages
    0:  48 c7 c1 00 01 00 00    mov    rcx,0x100
    7:  48 be 00 00 01 00 10    movabs rsi,0x1000010000
    e:  00 00 00
    11: 48 8b 06                mov    rax,QWORD PTR [rsi]
    14: 48 81 c6 00 10 00 00    add    rsi,0x1000
    1b: e2 f4                   loop   0x11
  */
  EXPECT_THAT(
      run_bytes({0x48, 0xC7, 0xC1, 0x00, 0x01, 0x00, 0x00, 0x48, 0xBE, 0x00,
                 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x06,
                 0x48, 0x81, 0xC6, 0x00, 0x10, 0x00, 0x00, 0xE2, 0xF4}),
      StatusIs(absl::StatusCode::kOutOfRange));
}

TEST(UnicornX86_64, Many) {
  // Execute some random bytes and make sure the basic infra is functioning e.g.
  // all memory can be mapped.
  absl::BitGen gen;
  for (int i = 0; i < 1000; ++i) {
    uint64_t bytes =
        absl::Uniform(gen, 0ULL, std::numeric_limits<uint64_t>::max());
    const uint8_t* v = reinterpret_cast<const uint8_t*>(&bytes);
    auto s = run_bytes({v, v + sizeof(uint64_t)});
    if (!s.ok()) {
      EXPECT_THAT(s, StatusIs(absl::StatusCode::kOutOfRange));
    } else {
      // All valid and expected uc_emu_start() return values.
      ASSERT_TRUE(*s == UC_ERR_OK || *s == UC_ERR_READ_UNMAPPED ||
                  *s == UC_ERR_WRITE_UNMAPPED || *s == UC_ERR_FETCH_UNMAPPED ||
                  *s == UC_ERR_INSN_INVALID || *s == UC_ERR_EXCEPTION ||
                  *s == UC_ERR_FETCH_PROT)
          << bytes << ": " << uc_strerror(*s);
    }
  }
}

}  // namespace
