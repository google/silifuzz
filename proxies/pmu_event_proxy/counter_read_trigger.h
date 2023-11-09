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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_COUNTER_READ_TRIGGER_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_COUNTER_READ_TRIGGER_H_

// This is broken out as a separate compilation unit instead of a part of
// perf_event_fuzzer.cc because a lint-tool complains about one of the arch
// specialized templates being unused.

#include <cstdint>
#include <string>

#include "./util/arch.h"

namespace silifuzz {

// Information about counter read trigger code sequence. The sequence is put
// before and after input to fuzzer. It generates a data breakpoint event.
struct CounterReadTrigger {
  // Instruction bytes to put in front and after an input.
  std::string code;

  // This is the location recorded for the breakpoint event, relative to
  // beginning of 'code' above. Depending on architecture, this either points to
  // or after the instruction causing the data breakpoint.
  off_t breakpoint_code_offset;

  // This is the address of the data breakpoint. 'code' stores a bytes to
  // this location to generate a data breakpoint event.
  uintptr_t breakpoint_data_address;
};

// Returns a CounterReadTrigger struct for 'Arch'.
template <typename Arch>
CounterReadTrigger GetCounterReadTrigger();

template <>
CounterReadTrigger GetCounterReadTrigger<X86_64>();

template <>
CounterReadTrigger GetCounterReadTrigger<AArch64>();

}  // namespace silifuzz

#endif  // TTHIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_COUNTER_READ_TRIGGER_H_
