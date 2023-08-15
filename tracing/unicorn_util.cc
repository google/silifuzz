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

#include "./tracing/unicorn_util.h"

#include <stdint.h>

#include <vector>

#include "./common/memory_perms.h"
#include "./common/snapshot.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "third_party/unicorn/unicorn.h"

namespace silifuzz {

uint32_t MemoryPermsToUnicorn(const MemoryPerms &perms) {
  uint32_t prot = 0;
  if (perms.Has(MemoryPerms::kReadable)) {
    prot |= UC_PROT_READ;
  }
  if (perms.Has(MemoryPerms::kWritable)) {
    prot |= UC_PROT_WRITE;
  }
  if (perms.Has(MemoryPerms::kExecutable)) {
    prot |= UC_PROT_EXEC;
  }
  return prot;
}

uint64_t GetExitPoint(const Snapshot &snapshot) {
  const Snapshot::EndStateList &end_states = snapshot.expected_end_states();
  CHECK(!end_states.empty());
  uint64_t exit_point = end_states[0].endpoint().instruction_address();
  for (const Snapshot::EndState &end_state : end_states) {
    // Note: this should never happen for Snapshots produced with
    // InstructionsToSnapshot, but in theory it could happen for old x86_64
    // Snapshots.
    CHECK_EQ(end_state.endpoint().instruction_address(), exit_point);
  }
  return exit_point;
}

}  // namespace silifuzz
