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

#include "./util/proc_maps_parser.h"

#include <cstring>

#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {
namespace {

const char* kSampleProcMaps =
    R"(456700000000-4567001fd000 r-xp 00000000 00:30 4478                       /tmp/runner_main_nolibc
4567003fc000-45670042a000 rw-p 001fc000 00:30 4478                       /tmp/runner_main_nolibc
456700629000-45670062a000 rw-p 00229000 00:30 4478                       /tmp/runner_main_nolibc
45670062a000-45670064a000 rw-p 00000000 00:00 0                          [heap]
7fc24b71f000-7fc24b741000 rw-p 00000000 00:00 0
7ffff7ff9000-7ffff7ffd000 r--p 00000000 00:00 0                          [vvar]
7ffff7ffd000-7ffff7fff000 r-xp 00000000 00:00 0                          [vdso]
7ffffffde000-7ffffffff000 rw-p 00000000    00:00    0                    [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
)";

constexpr size_t kExpectedNumProcMapsEntries = 9;
static const ProcMapsEntry
    kExpectedProcMapsEntries[kExpectedNumProcMapsEntries] = {
        {0x456700000000, 0x4567001fd000, "/tmp/runner_main_nolibc"},
        {0x4567003fc000, 0x45670042a000, "/tmp/runner_main_nolibc"},
        {0x456700629000, 0x45670062a000, "/tmp/runner_main_nolibc"},
        {0x45670062a000, 0x45670064a000, "[heap]"},
        {0x7fc24b71f000, 0x7fc24b741000, ""},
        {0x7ffff7ff9000, 0x7ffff7ffd000, "[vvar]"},
        {0x7ffff7ffd000, 0x7ffff7fff000, "[vdso]"},
        {0x7ffffffde000, 0x7ffffffff000, "[stack]"},
        {0xffffffffff600000ULL, 0xffffffffff601000ULL, "[vsyscall]"},
};

TEST(ProcMapsParser, BasicTest) {
  const size_t kSampleProcMapsSize = strlen(kSampleProcMaps);
  constexpr size_t kMaxProcMapsEntries = 10;
  ProcMapsEntry proc_maps_entries[kMaxProcMapsEntries];
  const size_t num_proc_maps_entries =
      ParseProcMaps(kSampleProcMaps, kSampleProcMapsSize, proc_maps_entries,
                    kMaxProcMapsEntries);

  CHECK_EQ(num_proc_maps_entries, kExpectedNumProcMapsEntries);
  for (size_t i = 0; i < num_proc_maps_entries; ++i) {
    CHECK_EQ(proc_maps_entries[i].start_address,
             kExpectedProcMapsEntries[i].start_address);
    CHECK_EQ(proc_maps_entries[i].limit_address,
             kExpectedProcMapsEntries[i].limit_address);
    EXPECT_STR_EQ(proc_maps_entries[i].name, kExpectedProcMapsEntries[i].name);
  }
}

// Checks that we do not overflow output buffer.
TEST(ProcMapsParser, BufferTooSmall) {
  const size_t kSampleProcMapsSize = strlen(kSampleProcMaps);
  constexpr size_t kMaxProcMapsEntries = kExpectedNumProcMapsEntries / 2;
  ProcMapsEntry proc_maps_entries[kMaxProcMapsEntries];
  const size_t num_proc_maps_entries =
      ParseProcMaps(kSampleProcMaps, kSampleProcMapsSize, proc_maps_entries,
                    kMaxProcMapsEntries);

  CHECK_EQ(num_proc_maps_entries, kMaxProcMapsEntries);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(ProcMapsParser, BasicTest);
  RUN_TEST(ProcMapsParser, BufferTooSmall);
})
