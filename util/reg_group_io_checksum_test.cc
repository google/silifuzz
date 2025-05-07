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

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/nolibc_gunit.h"
#include "./util/reg_checksum.h"
#include "./util/reg_group_io.h"
#include "./util/reg_group_set.h"
#include "./util/strcat.h"
#include "./util/sve_constants.h"

namespace silifuzz {
namespace {

void FillTestPattern(uint8_t* buffer, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    buffer[i] = i % 251;  // prime.
  }
}

void ChangePattern(uint8_t* buffer, size_t size) {
  for (size_t i = 0; i < size; ++i) {
    buffer[i] += 23;
  }
}

enum class AVXConfig { kDisabled, kAVX, kAVX512 };

RegisterGroupIOBuffer<X86_64> GetTestX86Buffer(AVXConfig avx_config) {
  RegisterGroupIOBuffer<X86_64> buffer{};
  if (avx_config == AVXConfig::kAVX) {
    buffer.register_groups.SetAVX(true);
  } else if (avx_config == AVXConfig::kAVX512) {
    buffer.register_groups.SetAVX512(true);
  }
  FillTestPattern(reinterpret_cast<uint8_t*>(buffer.ymm), sizeof(buffer.ymm));
  FillTestPattern(reinterpret_cast<uint8_t*>(buffer.zmm), sizeof(buffer.zmm));
  return buffer;
}

TEST(RegisterGroupIO, AVXChecksum) {
  InitRegisterGroupIO();
  for (AVXConfig avx_config :
       {AVXConfig::kDisabled, AVXConfig::kAVX, AVXConfig::kAVX512}) {
    LOG_INFO("Testing with AVX config: ", avx_config);
    RegisterGroupIOBuffer<X86_64> buffer = GetTestX86Buffer(avx_config);
    RegisterChecksum<X86_64> initial_checksum =
        GetRegisterGroupsChecksum(buffer);

    ChangePattern(reinterpret_cast<uint8_t*>(buffer.ymm), sizeof(buffer.ymm));
    ChangePattern(reinterpret_cast<uint8_t*>(buffer.zmm), sizeof(buffer.zmm));

    RegisterChecksum<X86_64> empty_checksum{};
    RegisterChecksum<X86_64> final_checksum = GetRegisterGroupsChecksum(buffer);
    if (avx_config == AVXConfig::kDisabled) {
      CHECK(initial_checksum == empty_checksum);
      CHECK(final_checksum == empty_checksum);
    } else {
      CHECK(final_checksum != initial_checksum);
      CHECK(final_checksum != empty_checksum);
    }
  }
}

TEST(RegisterGroupIO, AVXChecksumDetectsErrorOnActiveRegions) {
  InitRegisterGroupIO();
  for (AVXConfig avx_config : {AVXConfig::kAVX, AVXConfig::kAVX512}) {
    LOG_INFO("Testing with AVX config: ", avx_config);
    RegisterGroupIOBuffer<X86_64> buffer = GetTestX86Buffer(avx_config);
    RegisterChecksum<X86_64> initial_checksum =
        GetRegisterGroupsChecksum(buffer);

    // Change of data outside of active regions should not affect the checksum
    // result.
    if (avx_config == AVXConfig::kAVX) {
      ChangePattern(reinterpret_cast<uint8_t*>(buffer.zmm), sizeof(buffer.zmm));
    } else if (avx_config == AVXConfig::kAVX512) {
      ChangePattern(reinterpret_cast<uint8_t*>(buffer.ymm), sizeof(buffer.ymm));
    }
    RegisterChecksum<X86_64> checksum_not_changed =
        GetRegisterGroupsChecksum(buffer);
    CHECK(checksum_not_changed == initial_checksum);

    // Change of data inside of active regions should affect the checksum
    // result.
    if (avx_config == AVXConfig::kAVX) {
      for (size_t i = 0; i < sizeof(buffer.ymm); ++i) {
        uint8_t* ptr = reinterpret_cast<uint8_t*>(buffer.ymm) + i;
        RegisterChecksum<X86_64> new_checksum =
            GetRegisterGroupsChecksum(buffer);
        CHECK_LOG(new_checksum == initial_checksum,
                  StrCat({"before changing ymm[", IntStr(i), "]"}));
        uint8_t tmp = *ptr;
        *ptr = tmp + 33;
        new_checksum = GetRegisterGroupsChecksum(buffer);
        CHECK_LOG(new_checksum != initial_checksum,
                  StrCat({"after changing ymm[", IntStr(i), "]"}));
        *ptr = tmp;
      }
    } else if (avx_config == AVXConfig::kAVX512) {
      for (size_t i = 0; i < sizeof(buffer.zmm); ++i) {
        uint8_t* ptr = reinterpret_cast<uint8_t*>(buffer.zmm) + i;
        RegisterChecksum<X86_64> new_checksum =
            GetRegisterGroupsChecksum(buffer);
        CHECK_LOG(new_checksum == initial_checksum,
                  StrCat({"before changing zmm[", IntStr(i), "]"}));
        uint8_t tmp = *ptr;
        *ptr = tmp + 33;
        new_checksum = GetRegisterGroupsChecksum(buffer);
        CHECK_LOG(new_checksum != initial_checksum,
                  StrCat({"after changing zmm[", IntStr(i), "]"}));
        *ptr = tmp;
      }
    }
  }
}

RegisterGroupIOBuffer<AArch64> GetTestSVEBuffer(uint16_t vl) {
  RegisterGroupIOBuffer<AArch64> buffer{};
  buffer.register_groups.SetSVEVectorWidth(vl);
  FillTestPattern(buffer.z, sizeof(buffer.z));
  FillTestPattern(buffer.p, sizeof(buffer.p));
  FillTestPattern(buffer.ffr, sizeof(buffer.ffr));
  return buffer;
}

TEST(RegisterGroupIO, SVEChecksum) {
  InitRegisterGroupIO();
  for (uint16_t vl = 0; vl <= kSveZRegMaxSizeBytes; vl += 16) {
    LOG_INFO("Testing with vector length: ", vl);
    RegisterGroupIOBuffer<AArch64> buffer = GetTestSVEBuffer(vl);
    RegisterChecksum<AArch64> initial_checksum =
        GetRegisterGroupsChecksum(buffer);

    ChangePattern(buffer.z, SveZRegActiveSizeBytes(vl));
    ChangePattern(buffer.p, SvePRegActiveSizeBytes(vl));
    ChangePattern(buffer.ffr, SveFfrActiveSizeBytes(vl));
    RegisterChecksum<AArch64> empty_checksum{};
    RegisterChecksum<AArch64> final_checksum =
        GetRegisterGroupsChecksum(buffer);
    if (vl == 0) {
      CHECK(initial_checksum == empty_checksum);
      CHECK(final_checksum == empty_checksum);
    } else {
      CHECK(final_checksum != initial_checksum);
      CHECK(final_checksum != empty_checksum);
    }
  }
}

TEST(RegisterGroupIO, SVEChecksumDetectsErrorOnActiveRegions) {
  InitRegisterGroupIO();
  for (uint16_t vl = 16; vl <= kSveZRegMaxSizeBytes; vl += 16) {
    LOG_INFO("Testing with vector length: ", vl);
    RegisterGroupIOBuffer<AArch64> buffer = GetTestSVEBuffer(vl);
    RegisterChecksum<AArch64> initial_checksum =
        GetRegisterGroupsChecksum(buffer);

    // Change of data outside of active regions should not affect the checksum
    // result.
    ChangePattern(buffer.z + SveZRegActiveSizeBytes(vl),
                  sizeof(buffer.z) - SveZRegActiveSizeBytes(vl));
    ChangePattern(buffer.p + SvePRegActiveSizeBytes(vl),
                  sizeof(buffer.p) - SvePRegActiveSizeBytes(vl));
    RegisterChecksum<AArch64> checksum_not_changed =
        GetRegisterGroupsChecksum(buffer);
    CHECK(checksum_not_changed == initial_checksum);

    // Change of data inside of active regions should affect the checksum
    // result.
    for (size_t i = 0; i < SveZRegActiveSizeBytes(vl); ++i) {
      RegisterChecksum<AArch64> new_checksum =
          GetRegisterGroupsChecksum(buffer);
      CHECK_LOG(new_checksum == initial_checksum,
                StrCat({"before changing z[", IntStr(i), "]"}));
      uint8_t tmp = buffer.z[i];
      buffer.z[i] = tmp + 33;
      new_checksum = GetRegisterGroupsChecksum(buffer);
      CHECK_LOG(new_checksum != initial_checksum,
                StrCat({"after changing z[", IntStr(i), "]"}));
      buffer.z[i] = tmp;
    }
    for (size_t i = 0; i < SvePRegActiveSizeBytes(vl); ++i) {
      RegisterChecksum<AArch64> new_checksum =
          GetRegisterGroupsChecksum(buffer);
      CHECK_LOG(new_checksum == initial_checksum,
                StrCat({"before changing p[", IntStr(i), "]"}));
      uint8_t tmp = buffer.p[i];
      buffer.p[i] = tmp + 33;
      new_checksum = GetRegisterGroupsChecksum(buffer);
      CHECK_LOG(new_checksum != initial_checksum,
                StrCat({"after changing p[", IntStr(i), "]"}));
      buffer.p[i] = tmp;
    }
    for (size_t i = 0; i < SveFfrActiveSizeBytes(vl); ++i) {
      RegisterChecksum<AArch64> new_checksum =
          GetRegisterGroupsChecksum(buffer);
      CHECK_LOG(new_checksum == initial_checksum,
                StrCat({"before changing ffr[", IntStr(i), "]"}));
      uint8_t tmp = buffer.ffr[i];
      buffer.ffr[i] = tmp + 33;
      new_checksum = GetRegisterGroupsChecksum(buffer);
      CHECK_LOG(new_checksum != initial_checksum,
                StrCat({"after changing ffr[", IntStr(i), "]"}));
      buffer.ffr[i] = tmp;
    }
  }
}

// ===========================================================================
// Checksum compatibility tests.
//
// Please do not change these tests unless you know what you are doing.

struct AVXChecksumTestCase {
  AVXConfig avx_config;
  uint32_t expected_checksum;
};

// When the buffer contains:
// ymm: all 0xaa
// zmm: all 0xaa
// The checksum of the buffer is expected to be `expected_checksum`.
constexpr AVXChecksumTestCase kAVXChecksumCompatibilityTestCases[] = {
    {AVXConfig::kDisabled, 0x00000000},
    {AVXConfig::kAVX, 0x7D3AB85A},
    {AVXConfig::kAVX512, 0x409DCE97},
};

TEST(RegisterGroupIO, AVXChecksumCompatibility) {
  InitRegisterGroupIO();
  for (const AVXChecksumTestCase& tc : kAVXChecksumCompatibilityTestCases) {
    LOG_INFO("Testing with AVX config: ", tc.avx_config);

    RegisterGroupIOBuffer<X86_64> buffer{};
    if (tc.avx_config == AVXConfig::kAVX) {
      buffer.register_groups.SetAVX(true);
    } else if (tc.avx_config == AVXConfig::kAVX512) {
      buffer.register_groups.SetAVX512(true);
    }

    // Fill the buffer with 0xaa.
    memset(buffer.ymm, 0xaa, sizeof(buffer.ymm));
    memset(buffer.zmm, 0xaa, sizeof(buffer.zmm));

    CHECK_EQ(GetRegisterGroupsChecksum(buffer).checksum, tc.expected_checksum);
  }
}

struct SVEChecksumTestCase {
  uint16_t vl;
  uint32_t expected_checksum;
};

// When the buffer contains:
// z: all zero
// p: all zero
// ffr: all 0xaa in the active region (first `vl` bytes), and all zero
// otherwise.
// The checksum of the buffer is expected to be `expected_checksum`.
constexpr SVEChecksumTestCase kSVEChecksumCompatibilityTestCases[] = {
    {16, 0xAF73FD06},
    {256, 0x92A35BBE},
};

// The first version of the SVE registers checksum is calculated with the
// entire FFR register (a fixed 32-byte region starting with active bytes, and
// followed by 0 paddings). This test makes sure that the checksum
// implementation is compatible with the initial version.
// If the test fails, your code change may have changed how the checksum is
// calculated in a way that breaks the backward compatibility, making the
// existing snapshots invalid. If the change is desired, update the checksum
// result, and let your code reviewers know it's intended.
TEST(RegisterGroupIO, SVEChecksumCompatibility) {
  InitRegisterGroupIO();
  for (const SVEChecksumTestCase& tc : kSVEChecksumCompatibilityTestCases) {
    LOG_INFO("Testing with vector length: ", tc.vl);
    RegisterGroupIOBuffer<AArch64> buffer{};
    buffer.register_groups.SetSVEVectorWidth(tc.vl);

    // Fill the active region of the FFR register with 0xaa, and leave the
    // rest as 0.
    memset(buffer.ffr, 0xaa, SveFfrActiveSizeBytes(tc.vl));

    CHECK_EQ(GetRegisterGroupsChecksum(buffer).checksum, tc.expected_checksum);
  }
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(RegisterGroupIO, AVXChecksum);
  RUN_TEST(RegisterGroupIO, AVXChecksumDetectsErrorOnActiveRegions);
  RUN_TEST(RegisterGroupIO, SVEChecksum);
  RUN_TEST(RegisterGroupIO, SVEChecksumDetectsErrorOnActiveRegions);
  RUN_TEST(RegisterGroupIO, AVXChecksumCompatibility);
  RUN_TEST(RegisterGroupIO, SVEChecksumCompatibility);
})
