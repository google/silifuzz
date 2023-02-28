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

#include "./util/cpu_id.h"

#include <atomic>
#include <climits>

#include "third_party/lss/lss/linux_syscall_support.h"

namespace silifuzz {

namespace {
// Stored as the cpu_affinity + 1 to avoid initializing to -1 and adding a
// possible init function to the nolibc environment.
std::atomic<int> cpu_affinity_plus_one;
}  // namespace

// Gets current CPU ID using getcpu syscall.
int GetCPUIdUsingSyscall() {
  unsigned int cpu = 0, node = 0;
  int result = sys_getcpu(&cpu, &node, nullptr);

  // Kernel does not implement sys_getcpu.  This is highly unlikely.
  if (result != 0) {
    return kUnknownCPUId;
  }
  return cpu;
}

int SetCPUAffinity(int cpu_id) {
  // Linux kernel API uses unsigned long type.
  constexpr size_t kULongBits =
      CHAR_BIT * sizeof(unsigned long);  // NOLINT(runtime/int)
  constexpr size_t kCPUSetSizeInLongs =
      (CPU_SETSIZE + kULongBits - 1) / kULongBits;
  unsigned long cpu_set[kCPUSetSizeInLongs] = {};  // NOLINT(runtime/int)

  const size_t idx = cpu_id / kULongBits;
  const int bit = cpu_id % kULongBits;
  cpu_set[idx] |= static_cast<unsigned long>(1) << bit;
  if (sys_sched_setaffinity(0, sizeof(cpu_set), cpu_set)) {
    return errno;
  }
  // Remember the CPU affinity setting so we can give an approximate answer to
  // GetCPUIdNoSyscall.
  cpu_affinity_plus_one.store(cpu_id + 1, std::memory_order_relaxed);
  return 0;
}

// Note: since we only have a single global variable we're recording the
// last affinity set on any thread. This function may not work the way you'd
// expect if called from multiple threads, but we expect it will only be used in
// single-threaded scenarios.
// Ideally we'd store this value in thread-local storage, if nolibc had support.
int GetCPUAffinityNoSyscall() {
  return cpu_affinity_plus_one.load(std::memory_order_relaxed) - 1;
}

}  // namespace silifuzz
