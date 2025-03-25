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

#include "./util/reg_groups.h"

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include <cstring>

#include "./util/arch.h"
#include "./util/byte_io.h"
#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {
namespace {

bool cpuinfo_has_avx;
bool cpuinfo_has_avx512f;
bool cpuinfo_has_xsave;

constexpr size_t kCPUInfoBufferSize = 1 << 20;
char cpuinfo_data[kCPUInfoBufferSize];
size_t cpuinfo_data_size;

// Parse /proc/cpuinfo to search for some flags. Code is kept as simple is
// possible due to constraints in the nolibc environment.
void parse_cpuinfo() {
  // Read a reasonable large chunk of /proc/cpuinfo so that we have at least
  // one line containing flags.
  int fd = open("/proc/cpuinfo", O_RDONLY);
  ssize_t byte_read = Read(fd, cpuinfo_data, kCPUInfoBufferSize);
  CHECK_GT(byte_read, 0);
  cpuinfo_data_size = byte_read;

  // Returns index of the next newline or cpuinfo_data_size if none found.
  auto find_next_newline = [](size_t pos) {
    while (pos < cpuinfo_data_size && cpuinfo_data[pos] != '\n') ++pos;
    return pos;
  };

  // Scan until we find a line starting with 'flags'
  size_t i = 0;
  while (i < cpuinfo_data_size && strncmp(&cpuinfo_data[i], "flags", 5) != 0) {
    i = find_next_newline(i);
    if (i < cpuinfo_data_size) ++i;
  }
  CHECK_LT(i, cpuinfo_data_size);
  CHECK_EQ(strncmp(&cpuinfo_data[i], "flags", 5), 0);

  size_t j = find_next_newline(i);
  CHECK(j < cpuinfo_data_size);

  // Tokenize line using white spaces as delimiter.
  auto is_white_space = [](char c) { return c == ' ' || c == '\t'; };

  while (i < j) {
    while (i < j && is_white_space(cpuinfo_data[i])) ++i;
    size_t token_start = i;
    while (i < j && !is_white_space(cpuinfo_data[i])) ++i;
    size_t token_size = i - token_start;

    if (token_size == 3 && strncmp(&cpuinfo_data[token_start], "avx", 3) == 0) {
      cpuinfo_has_avx = true;
    } else if (token_size == 7 &&
               strncmp(&cpuinfo_data[token_start], "avx512f", 7) == 0) {
      cpuinfo_has_avx512f = true;
    } else if (token_size == 5 &&
               strncmp(&cpuinfo_data[token_start], "xsave", 5) == 0) {
      cpuinfo_has_xsave = true;
    }
  }

  close(fd);
}

// Checks if our results agree with information in /proc/cpuinfo.
TEST(RegisterGroups, CurrentPlatformRegisterGroups) {
  RegisterGroupSet<X86_64> groups = GetCurrentPlatformRegisterGroups();

  // These are always present.
  CHECK(groups.GetGPR() && groups.GetFPRAndSSE());

  parse_cpuinfo();

  const bool has_avx_regs_according_to_cpuinfo =
      cpuinfo_has_xsave && cpuinfo_has_avx;
  CHECK_EQ(groups.GetAVX(), has_avx_regs_according_to_cpuinfo);

  const bool has_avx512_regs_according_to_cpuinfo =
      has_avx_regs_according_to_cpuinfo && cpuinfo_has_avx512f;
  CHECK_EQ(groups.GetAVX512(), has_avx512_regs_according_to_cpuinfo);
}

TEST(RegisterGroups, CurrentPlatformChecksumRegisterGroups) {
  RegisterGroupSet<X86_64> groups = GetCurrentPlatformChecksumRegisterGroups();

  // These should not be in a checksum.
  CHECK(!groups.GetGPR() && !groups.GetFPRAndSSE());

  // If we have AVX512 registers, we should not include AVX registers in a
  // checksum.
  if (groups.GetAVX512()) {
    CHECK(!groups.GetAVX());
  } else if (groups.GetAVX()) {
    RegisterGroupSet<X86_64> avx_only;
    avx_only.SetAVX(true);
    CHECK(groups == avx_only);
  }

  // Clear all known checksum bits to ensure no unexpected bits are set.
  groups.SetAVX(false).SetAVX512(false);
  CHECK(groups.Empty());
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(RegisterGroups, CurrentPlatformRegisterGroups);
  RUN_TEST(RegisterGroups, CurrentPlatformChecksumRegisterGroups);
})
