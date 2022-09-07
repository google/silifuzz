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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_PROC_MAPS_PARSER_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_PROC_MAPS_PARSER_H_

#include <cstddef>
#include <cstdint>

// Utility for parsing /proc/*/maps file. This is intended for use in nolibc
// environment. No memory allocation is performed. Instead, a caller needs
// to manage memory used to store contents of a maps file and the parser
// output.

namespace silifuzz {

// Information about a /proc/*/maps entry.  Currently we only care about its
// memory range. Other fields will be added as necessary.
struct ProcMapsEntry {
  // This entry covers memory range [start_address, limit_address)
  uint64_t start_address;
  uint64_t limit_address;
  char name[128];
};

// Parses a memory image of /proc/*/maps file. 'maps' points to a
// 'maps_size'-byte buffer storing contents of the file. Each line in the file
// is parsed and appended into the array 'proc_maps_entries[]' up to
// 'max_proc_maps_entries'. Returns the number of parsed entries.
//
// We could eliminate the need for a maps file buffer if we changed the
// interface to use an iterator. This is not done to keep things simple as
// there is only one caller for this function and using a statically allocated
// buffer is fine for now.
size_t ParseProcMaps(const char* maps, size_t maps_size,
                     ProcMapsEntry* proc_maps_entries,
                     size_t max_proc_maps_entries);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_PROC_MAPS_PARSER_H_
