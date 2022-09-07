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

#include "./util/platform.h"
#ifdef __x86_64__
#include <immintrin.h>

#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "gtest/gtest.h"
#include "./util/avx.h"

extern "C" void SilifuzzAVXTestHelper(__m512 zmm[32], uint16_t k[8],
                                      void (*func)());

namespace silifuzz {
namespace {

void Fill(void* ptr, size_t n) {
  for (size_t i = 0; i < n; ++i) {
    reinterpret_cast<uint8_t*>(ptr)[i] = i;
  }
}

bool CPUInfoHasAVX512FOnce() {
  std::ifstream proc_cpuinfo("/proc/cpuinfo");
  // Read until we found the first "flags" line
  std::string line;
  const std::string kPrefix = "flags";
  while (proc_cpuinfo.good()) {
    std::getline(proc_cpuinfo, line);
    if (line.substr(0, kPrefix.size()) == kPrefix) break;
  }

  // Loop exited due to read error or EOF.
  if (!proc_cpuinfo.good()) return false;

  // Tokenize the line and look for avx512f
  std::stringstream ss(line);
  std::string token;
  while (ss.good()) {
    std::getline(ss, token, ' ');
    if (token == "avx512f") return true;
  }
  return false;
}

// Returns true iff "avx512f" is found in one of the "flags" lines of
// /proc/cpuinfo.
bool CPUInfoHasAVX512F() {
  static bool cached_result = CPUInfoHasAVX512FOnce();
  return cached_result;
}

TEST(AVX, HasAVX512Registers) {
  CHECK_EQ(HasAVX512Registers(), CPUInfoHasAVX512F());

  // These are the platforms we expect to see AVX512F.
  PlatformId platform = CurrentPlatformId();
  switch (platform) {
    case PlatformId::kIntelSkylake:
    case PlatformId::kIntelCascadelake:
    case PlatformId::kIntelIcelake:
    case PlatformId::kIntelSapphireRapids:
      EXPECT_TRUE(HasAVX512Registers());

      break;
    default:
      EXPECT_FALSE(HasAVX512Registers());
  }
}

TEST(AVX, ClearAVX512OnlyState) {
  // We can only run this test on machines with AVX-512F or above.
  // Treat testing as passing if we cannot run test.
  if (!CPUInfoHasAVX512F()) {
    GTEST_SKIP() << "Test needs AVX-512F to run.";
    return;
  }

  __m512 zmm[32];
  __mmask16 k[8];
  Fill(zmm, sizeof(zmm));
  Fill(k, sizeof(k));

  __m512 zmm_expected[32];
  __mmask16 k_expected[8];
  memcpy(zmm_expected, zmm, sizeof(zmm[0]) * 16);
  memset(&zmm_expected[16], 0, sizeof(zmm[0]) * 16);
  memset(k_expected, 0, sizeof(k));

  SilifuzzAVXTestHelper(zmm, k, ClearAVX512OnlyState);

  EXPECT_EQ(memcmp(zmm, zmm_expected, sizeof(zmm)), 0);
  EXPECT_EQ(memcmp(k, k_expected, sizeof(k)), 0);
}

}  // namespace
}  // namespace silifuzz
#endif  // __x86_64__
