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

#include <stddef.h>

#include <cstdint>
#include <limits>
#include <vector>

#include "gtest/gtest.h"
#include "absl/random/random.h"
#include "./util/testing/status_matchers.h"
#include "third_party/unicorn/unicorn.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace {

int run_bytes(std::vector<uint8_t>&& data) {
  return LLVMFuzzerTestOneInput(data.data(), data.size());
}

// The preprocessor does not understand initializer lists, so hack around this
// with vardic macros.
#define EXPECT_BYTES_ACCEPTED(...) EXPECT_EQ(0, run_bytes(__VA_ARGS__));
#define EXPECT_BYTES_REJECTED(...) EXPECT_EQ(-1, run_bytes(__VA_ARGS__));

TEST(UnicornX86_64, Nop) { EXPECT_BYTES_ACCEPTED({0x90}); }

TEST(UnicornX86_64, Hlt) { EXPECT_BYTES_ACCEPTED({0xF4}); }

TEST(UnicornX86_64, ReadMappedMem) {
  // movabs eax,ds:0x1000010000
  EXPECT_BYTES_ACCEPTED({0xA1, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00, 0x00});
}

TEST(UnicornX86_64, ReadUnmappedMem) {
  // mov eax, dword ptr [0]
  EXPECT_BYTES_REJECTED({0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00});
}

TEST(UnicornX86_64, Loop10) {
  // xor rcx, rcx
  // mov cl, 10
  // loop .
  EXPECT_BYTES_ACCEPTED({0x48, 0x31, 0xC9, 0xB1, 0x0A, 0xE2, 0xFE});
}

TEST(UnicornX86_64, Runaway) {
  //  jmp .
  EXPECT_BYTES_REJECTED({0xEB, 0xFE});
}

TEST(UnicornX86_64, JmpFar) {
  // jmp .+0x60
  EXPECT_BYTES_REJECTED({0xEB, 0x60});
}

TEST(UnicornX86_64, UD) { EXPECT_BYTES_REJECTED({0x0F, 0xFF}); }

TEST(UnicornX86_64, ReadFewPages) {
  /* Attempt to touch few pages
    0:  48 c7 c1 00 01 00 00    mov    rcx,0x5
    7:  48 be 00 00 01 00 10    movabs rsi,0x1000010000
    e:  00 00 00
    11: 48 8b 06                mov    rax,QWORD PTR [rsi]
    14: 48 81 c6 00 10 00 00    add    rsi,0x1000
    1b: e2 f4                   loop   0x11
  */
  EXPECT_BYTES_ACCEPTED({0x48, 0xC7, 0xC1, 0x05, 0x00, 0x00, 0x00, 0x48,
                         0xBE, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00,
                         0x00, 0x48, 0x8B, 0x06, 0x48, 0x81, 0xC6, 0x00,
                         0x10, 0x00, 0x00, 0xE2, 0xF4});
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
  EXPECT_BYTES_REJECTED({0x48, 0xC7, 0xC1, 0x00, 0x01, 0x00, 0x00, 0x48,
                         0xBE, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00,
                         0x00, 0x48, 0x8B, 0x06, 0x48, 0x81, 0xC6, 0x00,
                         0x10, 0x00, 0x00, 0xE2, 0xF4});
}

}  // namespace
