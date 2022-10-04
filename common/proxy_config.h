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

// Memory page size.
constexpr inline size_t kPageSize = 4096;

// Code region.
// The proxy code will map just a single page inside this region.
constexpr uint64_t kCodeAddr = 0x30000000;
constexpr uint64_t kCodeLimit = 0xB0000000;
static_assert((kCodeLimit - kCodeAddr & (kCodeLimit - kCodeAddr - 1)) == 0,
              "Size of the code region must a power of 2");

// Memory region 1.
constexpr uint64_t kMem1Addr = 0x10000;
constexpr uint64_t kMem1Limit = kMem1Addr + 0x20000000;

// Memory region 2.
constexpr uint64_t kMem2Addr = 0x1000010000;
constexpr uint64_t kMem2Limit = kMem2Addr + 0x20000000;

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_PROXY_CONFIG_H_
