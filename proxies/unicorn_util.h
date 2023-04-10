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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_UNICORN_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_UNICORN_UTIL_H_

#include "./common/memory_perms.h"
#include "./common/snapshot.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "third_party/unicorn/unicorn.h"

namespace silifuzz {

// Assert that a call to the Unicorn API completed successfully.
#define UNICORN_CHECK(...)                              \
  do {                                                  \
    uc_err __uc_check_err = __VA_ARGS__;                \
    if ((__uc_check_err != UC_ERR_OK)) {                \
      LOG_FATAL(#__VA_ARGS__ " failed with ",           \
                silifuzz::IntStr(__uc_check_err), ": ", \
                uc_strerror(__uc_check_err));           \
    }                                                   \
  } while (0);

// Translate Silifuzz's MemoryPerms into Unicorn's protection flags.
uint32_t MemoryPermsToUnicorn(const MemoryPerms &perms);

// Create a memory mapping or die. Helps avoid error handling in the cases we
// know should succeed unless there is a bug.
void MapMemory(uc_engine *uc, uint64_t addr, uint64_t size, uint32_t prot);
void MapMemory(uc_engine *uc, uint64_t addr, uint64_t size,
               const MemoryPerms &perms);

// Determine where the Snapshot will stop executing.
uint64_t GetExitPoint(const Snapshot &snapshot);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_UNICORN_UTIL_H_
