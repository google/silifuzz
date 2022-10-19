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

// This file defines bits of configuration shared by all parts of the
// fuzzing pipeline including proxies, fuzz_filter_tool and the fix tool.
// See https://github.com/google/silifuzz/blob/main/doc/proxy_architecture.md

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_PROXY_CONFIG_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_PROXY_CONFIG_H_

#include <cstddef>
#include <cstdint>

namespace silifuzz {

// FuzzingConfig describes desired Snapshot execution environment. Currently,
// this is limited to the memory regions where code and data can be placed.
// Can include things like "default GPR value" in the future.
struct FuzzingConfig {
  // CODE region [start;limit).
  // Size of the CODE region (i.e. limit-start) must be a power of 2.
  uint64_t code_range_start;
  uint64_t code_range_limit;

  // DATA1 region [start;limit)
  // Both DATA regions must be page-granular.
  uint64_t data1_range_start;
  uint64_t data1_range_limit;

  // DATA2 region [start;limit)
  uint64_t data2_range_start;
  uint64_t data2_range_limit;
};

constexpr FuzzingConfig DEFAULT_X86_64_FUZZING_CONFIG = {
    .code_range_start = 0x30000000,
    .code_range_limit = 0xB0000000,
    .data1_range_start = 0x10000,
    .data1_range_limit = 0x20010000,
    .data2_range_start = 0x1000010000,
    .data2_range_limit = 0x1020010000,
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_PROXY_CONFIG_H_
