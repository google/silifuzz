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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_X86_SEGMENT_BASE_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_X86_SEGMENT_BASE_H_
// Convenience functions for manipulating segement registers.
#include <asm/prctl.h>

#include <cerrno>
#include <cstdint>

#include "absl/base/attributes.h"
#include "third_party/lss/lss/linux_syscall_support.h"
#include "./util/checks.h"
#include "./util/itoa.h"

#ifdef MEMORY_SANITIZER
#include <sanitizer/msan_interface.h>
#endif

namespace silifuzz {

// Get the fs base register.
ABSL_ATTRIBUTE_ALWAYS_INLINE inline uint64_t GetFSBase() {
  uint64_t address;
  int64_t result = sys_arch_prctl(ARCH_GET_FS, &address);
  // fs_base is used by libc as the self-thread pointer. If we are manipulating
  // fs_base, the current value may be invalid for thread local access.
  // It is not safe to call other functions that may reference thread locals.
  // Use ASS_LOG_FATAL and hope that the error message is printed before a
  // bad fs_base causing a crash.
  if (result != 0) {
    ASS_LOG_FATAL("Failed to get fs base, ", ErrnoStr(errno));
  }
#if defined(MEMORY_SANITIZER)
  __msan_unpoison(&address, sizeof(address));
#endif
  return address;
}

// These function have always_inline attribute as they may be used in situations
// where it can be dangerous for the runtime dynamic linker to do symbol lookup.

// Set the fs base register to 'address'.
ABSL_ATTRIBUTE_ALWAYS_INLINE inline void SetFSBase(uint64_t address) {
  int64_t result =
      sys_arch_prctl(ARCH_SET_FS, reinterpret_cast<void*>(address));
  if (result != 0) {
    // See long comment in GetFSBase above for details of error reporting.
    ASS_LOG_FATAL("Failed to set fs base, ", ErrnoStr(errno));
  }
}

// Get the gs base register.
ABSL_ATTRIBUTE_ALWAYS_INLINE inline uint64_t GetGSBase() {
  uint64_t address;
  int64_t result = sys_arch_prctl(ARCH_GET_GS, &address);
  if (result != 0) {
    // See long comment in GetFSBase above for details of error reporting.
    ASS_LOG_FATAL("Failed to get gs base, ", ErrnoStr(errno));
  }
#if defined(MEMORY_SANITIZER)
  __msan_unpoison(&address, sizeof(address));
#endif
  return address;
}

// Set the gs base register to 'address'.
ABSL_ATTRIBUTE_ALWAYS_INLINE inline void SetGSBase(uint64_t address) {
  int64_t result =
      sys_arch_prctl(ARCH_SET_GS, reinterpret_cast<void*>(address));
  if (result != 0) {
    // See long comment in GetFSBase above for details of error reporting.
    ASS_LOG_FATAL("Failed to set gs base, ", ErrnoStr(errno));
  }
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_X86_SEGMENT_BASE_H_
