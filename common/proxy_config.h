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

// A memory region spanning [start_address;start_address+num_bytes).
struct MemoryRange {
  uint64_t start_address;
  uint64_t num_bytes;
};

// FuzzingConfig describes desired Snapshot execution environment. Currently,
// this is limited to the memory regions where code and data can be placed.
// Can include things like "default GPR value" in the future.
struct FuzzingConfig_X86_64 {
  // The start_address address must be page aligned.
  // The num_bytes must be a power of 2.
  MemoryRange code_range;

  // The start_address address must be page aligned.
  // The num_bytes must be a multiple of page size.
  MemoryRange data1_range;

  // Constraints for start_address and num_bytes are same as data1.
  MemoryRange data2_range;
};

constexpr FuzzingConfig_X86_64 DEFAULT_X86_64_FUZZING_CONFIG = {
    .code_range =
        {
            .start_address = 0x30000000,
            .num_bytes = 0x80000000,  // 2 GB
        },
    .data1_range =
        {
            .start_address = 0x10000,
            .num_bytes = 0x20000000,  // 512 MB
        },
    .data2_range =
        {
            .start_address = 0x1000010000,
            .num_bytes = 0x20000000,  // 512 MB
        },
};

// Inheritance doesn't play well with designated initializers, so we're
// manually duplicating parts of the config rather than inheriting from a base
// config.
// Even if the configs had identical fields, we'd probally want to keep the
// types separate so type checking could catch config confusion.
struct FuzzingConfig_AArch64 {
  MemoryRange code_range;

  // AArch64 currently has a separate stack. We may want to re-evaluate this in
  // the future. For now, however, this simplifies the proxy because the
  // Snapshot either includes each memory mapping in its entirety or completely
  // omits it.
  MemoryRange stack_range;

  MemoryRange data1_range;
  MemoryRange data2_range;
};

constexpr FuzzingConfig_AArch64 DEFAULT_AARCH64_FUZZING_CONFIG = {
    .code_range =
        {
            .start_address = 0x30000000,
            .num_bytes = 0x80000000,  // 2 GB
        },
    .stack_range =
        {
            .start_address = 0x2000000,
            .num_bytes = 0x1000,
        },

    .data1_range =
        {
            .start_address = 0x700000000,
            .num_bytes = 0x400000,  // 4 MB
        },
    .data2_range =
        {
            .start_address = 0x100700000000,
            .num_bytes = 0x400000,  // 4 MB
        },
};

// This config is used to accommodate proxies with limited physical memory.
constexpr FuzzingConfig_AArch64 LIMITED_MEMORY_AARCH64_FUZZING_CONFIG = {
    .code_range =
        {
            .start_address = 0x30000000,
            .num_bytes = 0x80000000,  // 2 GB
        },
    .stack_range =
        {
            .start_address = 0x2000000,
            .num_bytes = 0x1000,
        },

    .data1_range =
        {
            .start_address = 0x700000000,
            .num_bytes = 0x8000,  // 16 KB
        },
    .data2_range =
        {
            .start_address = 0x100700000000,
            .num_bytes = 0x8000,  // 16 KB
        },
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_PROXY_CONFIG_H_
