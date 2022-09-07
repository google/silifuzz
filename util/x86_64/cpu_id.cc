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

#include "./util/x86_cpuid.h"

namespace silifuzz {
namespace {

enum RDTSCPState {
  kUnknownRDTSCP = 0,
  kNoRDTSCP = 1,
  kYesRDTSCP = 2,
};

std::atomic<RDTSCPState> has_rdtscp;

inline bool HasRDTSCPImpl() {
  X86CPUIDResult res;
  X86CPUID(0x80000001U, &res);
  constexpr uint32_t kRDTSCPBit = 1U << 27;
  return (res.edx & kRDTSCPBit) != 0;
}

bool HasRDTSCP() {
  RDTSCPState state = has_rdtscp.load(std::memory_order_relaxed);
  if (state == kUnknownRDTSCP) {
    state = HasRDTSCPImpl() ? kYesRDTSCP : kNoRDTSCP;
    has_rdtscp.store(state, std::memory_order_relaxed);
  }
  return state == kYesRDTSCP;
}

// The Linux kernel fills in TSC auxiliary MSR with CPU core ID information,
// which is readable using RDTSCP instruction.
inline int GetCPUIdUsingRDTSCP() {
  uint32_t ecx;
  asm volatile("rdtscp" : "=c"(ecx) : /* no input*/ : "%eax", "%edx");
  // Lower 12 bits contain CPU ID.
  return ecx & 0xfff;
}

}  // namespace

extern int GetCPUIdUsingSyscall();

int GetCPUId() {
  if (HasRDTSCP()) {
    return GetCPUIdUsingRDTSCP();
  } else {
    return GetCPUIdUsingSyscall();
  }
}

int GetCPUIdNoSyscall() {
  if (HasRDTSCP()) {
    return GetCPUIdUsingRDTSCP();
  } else {
    return kUnknownCPUId;
  }
}

}  // namespace silifuzz
