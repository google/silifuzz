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

#include "./proxies/pmu_event_proxy/counter_read_trigger.h"

#include <cstdint>
#include <string>

#include "./util/arch.h"

namespace silifuzz {

template <>
CounterReadTrigger GetCounterReadTrigger<X86_64>() {
  // movb $0, 0x10000000.
  // The address is the beginning of data1 region of a proxy. On the x86, this
  // is normally used as a stack page.
  constexpr char kInsnBytes[] = {0xc6, 0x04, 0x25, 0x00,
                                 0x00, 0x00, 0x10, 0x00};

  return {
      .code = std::string(kInsnBytes, sizeof(kInsnBytes)),
      // For x86, the breakpoint address is after the instruction causing a
      // breakpoint.
      .breakpoint_code_offset = sizeof(kInsnBytes),
      .breakpoint_data_address = 0x10000000,
  };
}

template <>
CounterReadTrigger GetCounterReadTrigger<AArch64>() {
  // This stores a zero byte at the bottom of stack.
  constexpr uint32_t kInsns[] = {
      0xd2a04008,  // mov x8, #0x2000000
      0x3900011f,  // strb wzr, [x8]
      0xaa1f03e0,  // mov x8, xzr
  };

  return {
      .code =
          std::string(reinterpret_cast<const char*>(kInsns), sizeof(kInsns)),
      // For aarch64 the breakpoint address is at the instruction causing a
      // breakpoint.
      .breakpoint_code_offset = sizeof(uint32_t),
      .breakpoint_data_address = 0x2000000,
  };
}

}  // namespace silifuzz
