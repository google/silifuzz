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

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <cstdint>

#include "./util/atoi.h"
#include "./util/checks.h"

namespace silifuzz {
namespace {

// Find the first character inside ['begin', 'end') that causes 'pred' to return
// 0, Returns the location or nullptr if all of the characters in range
// satisfy 'pred'.
const char* SkipWhile(int (*pred)(int), const char* begin, const char* end) {
  for (const char* ptr = begin; ptr < end; ++ptr) {
    if ((*pred)(*ptr) == 0) {
      return ptr;
    }
  }
  return nullptr;
}

}  // namespace

size_t ParseProcMaps(const char* maps, size_t maps_size,
                     ProcMapsEntry* proc_maps_entries,
                     size_t max_proc_maps_entries) {
  size_t num_entries = 0;
  const char* ptr = maps;
  const char* end_of_file = maps + maps_size;
  while (ptr < end_of_file && num_entries < max_proc_maps_entries) {
    auto is_not_end_of_line = [](int c) { return c != '\n' ? 1 : 0; };
    const char* end_of_line = SkipWhile(is_not_end_of_line, ptr, end_of_file);
    CHECK_NE(end_of_line, nullptr);

    // We expect a proc maps line to have the format:
    // "[0-9a-f]+\-[0-9a-f] .*"
    const char* hex1_begin = ptr;
    const char* hex1_end = SkipWhile(isxdigit, hex1_begin, end_of_line);
    CHECK_NE(hex1_end, nullptr);

    CHECK_EQ(*hex1_end, '-');
    const char* hex2_begin = hex1_end + 1;
    CHECK_NE(hex2_begin, nullptr);
    const char* hex2_end = SkipWhile(isxdigit, hex2_begin, end_of_line);
    CHECK_NE(hex2_end, nullptr);

    // Store parsed proc maps entry.
    CHECK_LT(num_entries, max_proc_maps_entries);
    const bool conversion1_okay =
        HexToU64(hex1_begin, hex1_end - hex1_begin,
                 &proc_maps_entries[num_entries].start_address);
    const bool conversion2_okay =
        HexToU64(hex2_begin, hex2_end - hex2_begin,
                 &proc_maps_entries[num_entries].limit_address);
    CHECK(conversion1_okay && conversion2_okay);

    {
      proc_maps_entries[num_entries].name[0] = '\0';
      auto is_not_space = [](int c) { return c != ' ' ? 1 : 0; };
      auto is_space = [](int c) { return c == ' ' ? 1 : 0; };
      const char* p = hex2_end;
      // Skip perms, offset, dev and inode columns. The last one is the name.
      // https://www.kernel.org/doc/Documentation/filesystems/proc.txt
      for (int i = 0; p != nullptr && i < 4; ++i) {
        p = SkipWhile(is_not_space, p + 1, end_of_line);
        if (p != nullptr) {
          p = SkipWhile(is_space, p + 1, end_of_line);
        }
      }
      if (p != nullptr) {
        size_t num_bytes =
            std::min(sizeof(proc_maps_entries[num_entries].name) - 1,
                     static_cast<size_t>(end_of_line - p));
        memcpy(proc_maps_entries[num_entries].name, p, num_bytes);
        proc_maps_entries[num_entries].name[num_bytes] = '\0';
      }
    }
    num_entries++;

    // Advance to next line
    ptr = end_of_line + 1;
  }

  return num_entries;
}

}  // namespace silifuzz
