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

#include "./runner/runner_util.h"

#include <fcntl.h>
#include <linux/audit.h>
#include <linux/bpf_common.h>
#include <linux/filter.h>
#include <linux/seccomp.h>  // SECCOMP constants.
#include <signal.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "./common/snapshot_enums.h"
#include "./util/byte_io.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/proc_maps_parser.h"
#include "./util/ucontext/ucontext.h"
#include "./util/x86_traps.h"

namespace silifuzz {
namespace {

// Returns true iff [start_1, limit_1) overlaps with [start_2, limit_2).
bool RangesOverlap(uint64_t start_1, uint64_t limit_1, uint64_t start_2,
                   uint64_t limit_2) {
  DCHECK_LE(start_1, limit_1);
  DCHECK_LE(start_2, limit_2);
  const uint64_t max_start = std::max(start_1, start_2);
  const uint64_t min_limit = std::min(limit_1, limit_2);
  return min_limit > max_start;
}

}  // namespace

size_t ReadProcMapsEntries(ProcMapsEntry* proc_maps_entries,
                           size_t max_proc_maps_entries) {
  // Read /proc/self/maps into memory. We use stack to hold this file
  // with a sufficiently large buffer so we will not grow the stack region
  // beyond what is recorded in /proc/self/maps now.
  constexpr size_t kMaxProcMapsSize = (1 << 20);
  char proc_maps_buffer[kMaxProcMapsSize];
  int fd = open("/proc/self/maps", O_RDONLY);
  CHECK_GE(fd, 0);
  const size_t proc_maps_size = Read(fd, proc_maps_buffer, kMaxProcMapsSize);
  if (proc_maps_size == kMaxProcMapsSize) {
    LOG_FATAL("/proc/self/maps too large.");
  }
  CHECK_EQ(close(fd), 0);
  return ParseProcMaps(proc_maps_buffer, proc_maps_size, proc_maps_entries,
                       max_proc_maps_entries);
}

bool SnapOverlapsWithProcMapsEntries(const Snap& snap,
                                     const ProcMapsEntry* proc_maps_entries,
                                     size_t num_proc_maps_entries) {
  for (const auto& memory_mapping : snap.memory_mappings) {
    const uint64_t start_address = memory_mapping.start_address;
    const uint64_t limit_address = start_address + memory_mapping.num_bytes;
    DCHECK_LE(start_address, limit_address);
    // Check that there is no memory conflicts with existing memory ranges
    // in proc_maps_entries.
    for (size_t i = 0; i < num_proc_maps_entries; ++i) {
      if (RangesOverlap(start_address, limit_address,
                        proc_maps_entries[i].start_address,
                        proc_maps_entries[i].limit_address)) {
        LOG_ERROR("Snapshot ", snap.id, " overlaps with proc maps entry at ",
                  HexStr(proc_maps_entries[i].start_address));
        return true;
      }
    }
  }
  return false;
}

void LogToStdout(const char* data) { Write(STDOUT_FILENO, data, strlen(data)); }

#define ALLOW_SYSCALL(name)                                              \
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)), \
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SYS_##name, 0, 1),             \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)

#if defined(__x86_64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define AUDIT_ARCH_CURRENT AUDIT_ARCH_AARCH64
#else
#error "Unsupported architecture"
#endif

#define VALIDATE_ARCH()                                                    \
  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch)), \
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, AUDIT_ARCH_CURRENT, 1, 0),       \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL)

void EnterSeccompStrictMode(bool allow_kill_syscall) {
  CHECK_EQ(close(STDIN_FILENO), 0);
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    LOG_FATAL("prctl(PR_SET_NO_NEW_PRIVS) failed: ", ErrnoStr(errno));
  }

  // The below program is roughly this in pseudocode
  // k := seccomp_data.arch
  // if (k == AUDIT_ARCH_CURRENT) goto 1;
  // return SECCOMP_KILL
  // 1:
  //  k := seccomp_data.nr
  //  if (k != __NR_write) goto 2
  //  return SECCOMP_ALLOW
  // 2:
  //  <check exit_group>
  // 3:
  //  <check kill>
  // return SECCOMP_KILL
  if (allow_kill_syscall) {
    struct sock_filter kWriteExitKillFilter[] = {
        VALIDATE_ARCH(),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(exit_group),
        ALLOW_SYSCALL(kill),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
    };
    struct sock_fprog filterprog = {
        .len = sizeof(kWriteExitKillFilter) / sizeof(kWriteExitKillFilter[0]),
        .filter = kWriteExitKillFilter};
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (uintptr_t)&filterprog, 0,
              0) < 0) {
      LOG_FATAL("prctl(SECCOMP_MODE_FILTER): ", ErrnoStr(errno));
    }
  } else {
    struct sock_filter kWriteExitFilter[] = {
        VALIDATE_ARCH(),
        ALLOW_SYSCALL(write),
        ALLOW_SYSCALL(exit_group),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_KILL),
    };
    struct sock_fprog filterprog = {
        .len = sizeof(kWriteExitFilter) / sizeof(kWriteExitFilter[0]),
        .filter = kWriteExitFilter};
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (uintptr_t)&filterprog, 0,
              0) < 0) {
      LOG_FATAL("prctl(SECCOMP_MODE_FILTER): ", ErrnoStr(errno));
    }
  }
}

}  // namespace silifuzz
