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

#include "./snap/exit_sequence.h"

#include <sys/mman.h>
#include <unistd.h>

#include <cstdint>

#include "./util/cache.h"
#include "./util/checks.h"

namespace silifuzz {

void InitSnapExit(void (*reentry_address)()) {
  const size_t kPageSize = getpagesize();
  // Map a page at kSnapExitAddress containing a branch to SnapExitImpl().
  void* snap_exit_page = mmap(reinterpret_cast<void*>(kSnapExitAddress),
                              kPageSize, PROT_READ | PROT_WRITE,
                              MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
  CHECK_NE(snap_exit_page, MAP_FAILED);
  size_t size = WriteSnapExitThunk(reentry_address, snap_exit_page);
  sync_instruction_cache(snap_exit_page, size);
  CHECK_EQ(mprotect(snap_exit_page, kPageSize, PROT_EXEC | PROT_READ), 0);
}

}  // namespace silifuzz
