// Copyright 2024 The SiliFuzz Authors.
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

// TODO(herooutman): The inline asm is prone to a lot of subtle bugs. We should
// consider to rewrite these tests either using out-of-line assembly or in C++.

#include "./util/aarch64/extension_registers.h"

#include "./util/aarch64/sve.h"
#include "./util/nolibc_gunit.h"
#include "./util/reg_group_io.h"

namespace silifuzz {
namespace {

void ClearBuffer(RegisterGroupIOBuffer<AArch64> &buf) {
  memset(&buf, 0, sizeof buf);
}

void SeedBuffer(RegisterGroupIOBuffer<AArch64> &buf) {
  for (int ffr_byte = 0; ffr_byte < sizeof buf.ffr; ffr_byte++) {
    buf.ffr[ffr_byte] = ffr_byte + 0xa0;
  }
  for (int p_byte = 0; p_byte < sizeof buf.p; p_byte++) {
    buf.p[p_byte] = p_byte + 0xc0;
  }
  for (int z_byte = 0; z_byte < sizeof buf.z; z_byte++) {
    buf.z[z_byte] = z_byte + 0xd0;
  }
}

TEST(AArch64ExtensionRegistersTest, StoreAndLoadZRegisters) {
  if (!SveIsSupported()) {
    SILIFUZZ_TEST_SKIP();
  }

  RegisterGroupIOBuffer<AArch64> original_buf;
  ClearBuffer(original_buf);
  RegisterGroupIOBuffer<AArch64> seed_buf;
  SeedBuffer(seed_buf);
  RegisterGroupIOBuffer<AArch64> buf_after_seeding;
  ClearBuffer(buf_after_seeding);
  RegisterGroupIOBuffer<AArch64> buf_after_clearing;
  ClearBuffer(buf_after_clearing);

  // 1. Store the original Z register contents (into original_buf).
  // 2. Load seed values (from seed_buf) into the Z registers.
  // 3. Store the Z register contents (into buf_after_seeding).
  // 4. Clear the Z registers.
  // 5. Store the Z register contents (into buf_after_clearing).
  // 6. Load the original contents (from original_buf) into the Z registers.
  //
  // Note: Per SVE procedure calling convention, a callee needs to preserve only
  // the low 64 bits of z8-z15 across a call. We save & restore all the Z
  // registers because that is easier.
  asm inline(
      "mov x0, %[original]\n"
      "bl StoreZRegisters\n"
      "mov x0, %[seed]\n"
      "bl LoadZRegisters\n"
      "mov x0, %[after_seeding]\n"
      "bl StoreZRegisters\n"
      "bl ClearZRegisters\n"
      "mov x0, %[after_clearing]\n"
      "bl StoreZRegisters\n"
      "mov x0, %[original]\n"
      "bl LoadZRegisters\n"
      :
      : [original] "r"(original_buf.z), [seed] "r"(seed_buf.z),
        [after_seeding] "r"(buf_after_seeding.z),
        [after_clearing] "r"(buf_after_clearing.z)
      : "x0", "p0", "cc", "memory");

  // If the vector registers are smaller than the theoretical max, part of
  // the buf_after_seeding should be empty.
  RegisterGroupIOBuffer<AArch64> empty_buf;
  ClearBuffer(empty_buf);
  size_t expected_populated_size = SveGetCurrentVectorLength() * kSveNumZReg;
  size_t expected_empty_size =
      sizeof buf_after_seeding.z - expected_populated_size;
  CHECK_GT(expected_populated_size, 0);

  CHECK_EQ(memcmp(buf_after_seeding.z, seed_buf.z, expected_populated_size), 0);
  CHECK_EQ(memcmp(buf_after_seeding.z + expected_populated_size, empty_buf.z,
                  expected_empty_size),
           0);
  CHECK_NE(memcmp(buf_after_seeding.z, empty_buf.z, sizeof empty_buf.z), 0);

  // Check that the Z registers were cleared successfully.
  CHECK_EQ(memcmp(buf_after_clearing.z, empty_buf.z, sizeof empty_buf.z), 0);
}

TEST(AArch64ExtensionRegistersTest, StoreAndLoadPRegisters) {
  if (!SveIsSupported()) {
    SILIFUZZ_TEST_SKIP();
  }

  RegisterGroupIOBuffer<AArch64> original_buf;
  ClearBuffer(original_buf);
  RegisterGroupIOBuffer<AArch64> seed_buf;
  SeedBuffer(seed_buf);
  RegisterGroupIOBuffer<AArch64> buf_after_seeding;
  ClearBuffer(buf_after_seeding);
  RegisterGroupIOBuffer<AArch64> buf_after_clearing;
  ClearBuffer(buf_after_clearing);

  // 1. Store the original P register contents (into original_buf).
  // 2. Load seed values (from seed_buf) into the P registers.
  // 3. Store the P register contents (into buf_after_seeding).
  // 4. Clear the P registers.
  // 5. Store the P register contents (into buf_after_clearing).
  // 6. Load the original contents (from original_buf) into the P registers.
  asm inline(
      "mov x0, %[original]\n"
      "bl StorePRegisters\n"
      "mov x0, %[seed]\n"
      "bl LoadPRegisters\n"
      "mov x0, %[after_seeding]\n"
      "bl StorePRegisters\n"
      "bl ClearPRegisters\n"
      "mov x0, %[after_clearing]\n"
      "bl StorePRegisters\n"
      "mov x0, %[original]\n"
      "bl LoadPRegisters\n"
      :
      : [original] "r"(original_buf.z), [seed] "r"(seed_buf.p),
        [after_seeding] "r"(buf_after_seeding.p),
        [after_clearing] "r"(buf_after_clearing.p)
      : "x0", "p0", "cc", "memory");

  // If the predicate registers are smaller than the theoretical max, part of
  // the buf_after_seeding should be empty.
  RegisterGroupIOBuffer<AArch64> empty_buf;
  ClearBuffer(empty_buf);
  size_t expected_populated_size = SveGetPredicateLength() * kSveNumPReg;
  size_t expected_empty_size =
      sizeof buf_after_seeding.p - expected_populated_size;
  CHECK_GT(expected_populated_size, 0);

  CHECK_EQ(memcmp(buf_after_seeding.p, seed_buf.p, expected_populated_size), 0);
  CHECK_EQ(memcmp(buf_after_seeding.p + expected_populated_size, empty_buf.p,
                  expected_empty_size),
           0);
  CHECK_NE(memcmp(buf_after_seeding.p, empty_buf.p, sizeof empty_buf.p), 0);

  // Clear the p registers and check that they were indeed cleared.
  CHECK_EQ(memcmp(buf_after_clearing.p, empty_buf.p, sizeof empty_buf.p), 0);
}

TEST(AArch64ExtensionRegistersTest, StoreAndLoadFfrRegister) {
  if (!SveIsSupported()) {
    SILIFUZZ_TEST_SKIP();
  }

  RegisterGroupIOBuffer<AArch64> original_buf;
  ClearBuffer(original_buf);
  RegisterGroupIOBuffer<AArch64> seed_buf;
  SeedBuffer(seed_buf);
  RegisterGroupIOBuffer<AArch64> buf_after_seeding;
  ClearBuffer(buf_after_seeding);
  RegisterGroupIOBuffer<AArch64> buf_after_clearing;
  ClearBuffer(buf_after_clearing);

  // 1. Store the original FFR register contents (into original_buf).
  // 2. Load seed values (from seed_buf) into the FFR registers.
  // 3. Store the FFR register contents (into buf_after_seeding).
  // 4. Clear the FFR registers.
  // 5. Store the FFR register contents (into buf_after_clearing).
  // 6. Load the original contents (from original_buf) into the FFR register.
  asm inline(
      "mov x0, %[original]\n"
      "bl StoreFfrRegister\n"
      "mov x0, %[seed]\n"
      "bl LoadFfrRegister\n"
      "mov x0, %[after_seeding]\n"
      "bl StoreFfrRegister\n"
      "bl ClearFfrRegister\n"
      "mov x0, %[after_clearing]\n"
      "bl StoreFfrRegister\n"
      "mov x0, %[original]\n"
      "bl LoadFfrRegister\n"
      :
      : [original] "r"(original_buf.ffr), [seed] "r"(seed_buf.ffr),
        [after_seeding] "r"(buf_after_seeding.ffr),
        [after_clearing] "r"(buf_after_clearing.ffr)
      : "x0", "p0", "cc", "memory");

  // If the predicate registers are smaller than the theoretical max, part of
  // the buf_after_seeding should be empty.
  RegisterGroupIOBuffer<AArch64> empty_buf;
  ClearBuffer(empty_buf);
  size_t expected_populated_size = SveGetPredicateLength();
  size_t expected_empty_size =
      sizeof buf_after_seeding.ffr - expected_populated_size;
  CHECK_GT(expected_populated_size, 0);

  CHECK_EQ(memcmp(buf_after_seeding.ffr, seed_buf.ffr, expected_populated_size),
           0);
  CHECK_EQ(memcmp(buf_after_seeding.ffr + expected_populated_size,
                  empty_buf.ffr, expected_empty_size),
           0);
  CHECK_NE(memcmp(buf_after_seeding.ffr, empty_buf.ffr, sizeof empty_buf.ffr),
           0);

  // Clear the p registers and check that they were indeed cleared.
  CHECK_EQ(memcmp(buf_after_clearing.ffr, empty_buf.ffr, sizeof empty_buf.ffr),
           0);
}

TEST(AArch64ExtensionRegistersTest, ClearRegisterGroups) {
  if (!SveIsSupported()) {
    SILIFUZZ_TEST_SKIP();
  }
  const size_t sve_predicate_width =
      SveGetCurrentVectorLength() / kSvePRegSizeZRegFactor;
  // Override the vector width to be the theoretical max. This is to ensure that
  // ClearRegisterGroups() works with double-byte SVE vector length.
  SetSVEVectorWidthGlobal(0x100);
  RegisterGroupIOBuffer<AArch64> original_buf;
  ClearBuffer(original_buf);
  RegisterGroupIOBuffer<AArch64> seed_buf;
  SeedBuffer(seed_buf);
  RegisterGroupIOBuffer<AArch64> buf_after_clearing;
  SeedBuffer(buf_after_clearing);

  // 1. Store the original FFR & P register contents (into original_buf).
  // 2. Load seed values (from seed_buf) into the FFR & P registers.
  // 3. Call ClearRegisterGroups()
  // 4. Store the FFR & P register contents (into buf_after_clearing).
  // 5. seed_buf values should be non empty but buf_after_clearing should be
  // empty.
  // 6. Load the original contents (from original_buf) into the FFR & P
  // registers.
  asm inline(
      "mov x0, %[original_p]\n"
      "bl StorePRegisters\n"
      "mov x0, %[original_ffr]\n"
      "bl StoreFfrRegister\n"
      "mov x0, %[seed_ffr]\n"
      "bl LoadFfrRegister\n"
      "mov x0, %[seed_p]\n"
      "bl LoadPRegisters\n"
      "bl ClearRegisterGroups\n"
      "mov x0, %[after_clearing_p]\n"
      "bl StorePRegisters\n"
      "mov x0, %[after_clearing_ffr]\n"
      "bl StoreFfrRegister\n"
      "mov x0, %[original_ffr]\n"
      "bl LoadFfrRegister\n"
      "mov x0, %[original_p]\n"
      "bl LoadPRegisters\n"
      :
      : [original_ffr] "r"(original_buf.ffr), [original_p] "r"(original_buf.p),
        [seed_ffr] "r"(seed_buf.ffr), [seed_p] "r"(seed_buf.p),
        [after_clearing_ffr] "r"(buf_after_clearing.ffr),
        [after_clearing_p] "r"(buf_after_clearing.p)
      : "x0", "p0", "cc", "memory");

  RegisterGroupIOBuffer<AArch64> empty_buf;
  ClearBuffer(empty_buf);

  CHECK_NE(memcmp(seed_buf.ffr, empty_buf.ffr, sizeof empty_buf.ffr), 0);
  CHECK_NE(memcmp(seed_buf.p, empty_buf.p, sizeof empty_buf.p), 0);
  CHECK_EQ(memcmp(buf_after_clearing.ffr, empty_buf.ffr, sve_predicate_width),
           0);
  CHECK_EQ(memcmp(buf_after_clearing.p, empty_buf.p,
                  sve_predicate_width * kSveNumPReg),
           0);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(AArch64ExtensionRegistersTest, StoreAndLoadZRegisters);
  RUN_TEST(AArch64ExtensionRegistersTest, StoreAndLoadPRegisters);
  RUN_TEST(AArch64ExtensionRegistersTest, StoreAndLoadFfrRegister);
  RUN_TEST(AArch64ExtensionRegistersTest, ClearRegisterGroups);
})
