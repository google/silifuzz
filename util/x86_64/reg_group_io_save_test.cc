// Copyright 2025 The SiliFuzz Authors.
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

#include <x86intrin.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/cpu_features.h"
#include "./util/crc32c.h"
#include "./util/nolibc_gunit.h"
#include "./util/reg_checksum.h"
#include "./util/reg_group_io.h"
#include "./util/reg_group_set.h"
#include "./util/reg_groups.h"

namespace silifuzz {
namespace {

extern "C" void SaveAVXTestDataToRegisterGroupsBuffer(
    const __m256*, RegisterGroupIOBuffer<X86_64>&);
extern "C" void SaveAVX512TestDataToRegisterGroupsBuffer(
    const __m512*, const uint64_t*, bool opmask_is_64_bit,
    RegisterGroupIOBuffer<X86_64>&);

void FillTestPattern(uint8_t* buffer, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    buffer[i] = i % 251;  // prime.
  }
}

TEST(SaveRegisterGroupsToBuffer, AVX) {
  InitRegisterGroupIO();
  RegisterGroupSet<X86_64> all_register_groups =
      GetCurrentPlatformChecksumRegisterGroups();
  if (!all_register_groups.GetAVX()) SILIFUZZ_TEST_SKIP();

  RegisterGroupIOBuffer<X86_64> buffer{};
  buffer.register_groups.SetAVX(true);

  __m256 ymm[16];
  FillTestPattern(reinterpret_cast<uint8_t*>(ymm), sizeof(ymm));
  SaveAVXTestDataToRegisterGroupsBuffer(ymm, buffer);
  uint32_t expected_crc =
      crc32c(0, reinterpret_cast<const uint8_t*>(ymm), sizeof(ymm));

  RegisterChecksum<X86_64> register_checksum =
      GetRegisterGroupsChecksum(buffer);
  CHECK_EQ(register_checksum.checksum, expected_crc);
}

TEST(SaveRegisterGroupsToBuffer, AVX512) {
  InitRegisterGroupIO();
  RegisterGroupSet<X86_64> all_register_groups =
      GetCurrentPlatformChecksumRegisterGroups();
  if (!all_register_groups.GetAVX512()) SILIFUZZ_TEST_SKIP();

  RegisterGroupIOBuffer<X86_64> buffer{};
  buffer.register_groups.SetAVX512(true);

  const bool opmask_is_64_bit = HasX86CPUFeature(X86CPUFeatures::kAVX512BW);
  __m512 zmm[32];
  constexpr size_t kNumOpmasks = 8;
  uint64_t opmask[kNumOpmasks];

  FillTestPattern(reinterpret_cast<uint8_t*>(zmm), sizeof(zmm));
  FillTestPattern(reinterpret_cast<uint8_t*>(opmask), sizeof(opmask));
  if (!opmask_is_64_bit) {
    for (size_t i = 0; i < kNumOpmasks; ++i) {
      opmask[i] &= 0xffff;
    }
  }

  SaveAVX512TestDataToRegisterGroupsBuffer(zmm, opmask, opmask_is_64_bit,
                                           buffer);

  uint32_t expected_crc =
      crc32c(0, reinterpret_cast<const uint8_t*>(zmm), sizeof(zmm));
  expected_crc = crc32c(expected_crc, reinterpret_cast<const uint8_t*>(opmask),
                        sizeof(opmask));

  RegisterChecksum<X86_64> register_checksum =
      GetRegisterGroupsChecksum(buffer);
  CHECK_EQ(register_checksum.checksum, expected_crc);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(SaveRegisterGroupsToBuffer, AVX);
  RUN_TEST(SaveRegisterGroupsToBuffer, AVX512);
})
