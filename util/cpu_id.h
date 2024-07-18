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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_CPU_ID_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_CPU_ID_H_

namespace silifuzz {

// No preference for choice of CPU.
inline constexpr int kAnyCPUId = -1;

// CPU ID information not available.
inline constexpr int kUnknownCPUId = -1;

// Returns the current CPU Id or kUnknownCPUId if that cannot be determined.
int GetCPUId();

// Returns the current CPU Id if it can be done without syscalls.
// Otherwise returns kUnknownCPUId.
int GetCPUIdNoSyscall();

// Sets CPU of the current thread to the one with given Id . Returns 0 if
// successful or an error number from sched_setaffinity().
int SetCPUAffinity(int cpu_id);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_CPU_ID_H_
