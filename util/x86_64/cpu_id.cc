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

#include <stdint.h>

#include <atomic>

#include "./util/x86_cpuid.h"

namespace silifuzz {

// Fall back to these if no special instructions are available to
// get CPUID quickly.
extern int GetCPUIdUsingSyscall();
extern int GetCPUAffinityNoSyscall();

namespace {

// wrapper functions that choose the actual implementation the first time
// GetCPUId*() are called.
int InitializeGetCPUId();
int InitializeGetCPUIdNoSyscall();

// Function pointers to the best implementation of GetCPUID*() that
// we can use on the current platform. These are initialized when
// one of GetCPUID() and GetCPUIDNoSyscall() is called the first time.
typedef int (*GetCPUIDFunctionPtr)();
std::atomic<GetCPUIDFunctionPtr> get_cpuid_impl = InitializeGetCPUId;
std::atomic<GetCPUIDFunctionPtr> get_cpuid_no_syscall_impl =
    InitializeGetCPUIdNoSyscall;

int GetCPUIdUsingRDTSCP() {
  uint32_t ecx;
  asm volatile("rdtscp" : "=c"(ecx) : /* no input*/ : "%eax", "%edx");
  // Lower 12 bits contain CPU ID.
  return ecx & 0xfff;
}

int GetCPUIdUsingRDPID() {
  uint64_t tsc_aux;
  asm volatile("rdpid %0" : "=r"(tsc_aux) : /* no input*/);
  // Lower 12 bits contain CPU ID.
  return tsc_aux & 0xfff;
}

// Initializes implementation function pointers for both GetCPUID() and
// GetCPUIDNoSyscall().
void InitializeCommon() {
  X86CPUIDResult res;

  // Prefer RDPID over RDTSCP if available.
  X86CPUID(0x7U, &res);
  constexpr uint32_t kRDPIDBit = 1U << 22;
  if ((res.ecx & kRDPIDBit) != 0) {
    // Data races are benign as writes to function pointers are idempotent.
    // We can use atomic::exchange if we ever use a thread sanitizer.
    get_cpuid_impl.store(GetCPUIdUsingRDPID);
    get_cpuid_no_syscall_impl.store(GetCPUIdUsingRDPID);
    return;
  }

  X86CPUID(0x80000001U, &res);
  constexpr uint32_t kRDTSCPBit = 1U << 27;
  if ((res.edx & kRDTSCPBit) != 0) {
    get_cpuid_impl.store(GetCPUIdUsingRDTSCP);
    get_cpuid_no_syscall_impl.store(GetCPUIdUsingRDTSCP);
    return;
  }

  // No special instructions available, use slow methods.
  get_cpuid_impl.store(GetCPUIdUsingSyscall);
  get_cpuid_no_syscall_impl.store(GetCPUAffinityNoSyscall);
}

int InitializeGetCPUId() {
  InitializeCommon();
  return (*get_cpuid_impl.load(std::memory_order_relaxed))();
}

int InitializeGetCPUIdNoSyscall() {
  InitializeCommon();
  return (*get_cpuid_no_syscall_impl.load(std::memory_order_relaxed))();
}

}  // namespace

int GetCPUId() { return (*get_cpuid_impl.load(std::memory_order_relaxed))(); }

int GetCPUIdNoSyscall() {
  return (*get_cpuid_no_syscall_impl.load(std::memory_order_relaxed))();
}

}  // namespace silifuzz
