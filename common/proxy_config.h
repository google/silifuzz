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

#include "./util/arch.h"

namespace silifuzz {

// A memory region spanning [start_address;start_address+num_bytes).
struct MemoryRange {
  uint64_t start_address;
  uint64_t num_bytes;
};

template <typename Arch>
struct FuzzingConfig;

// This is usually the fuzzing config you should use.
// Note: static qualifier is needed because const templates are not implicitly
// static, unlike non-templated consts.
template <typename Arch>
static constexpr FuzzingConfig<Arch> DEFAULT_FUZZING_CONFIG;

// The fuzzing config to use for proxies with limited memory.
template <typename Arch>
static constexpr FuzzingConfig<Arch> LIMITED_MEMORY_FUZZING_CONFIG;

// FuzzingConfig describes desired Snapshot execution environment. Currently,
// this is limited to the memory regions where code and data can be placed.
// Can include things like "default GPR value" in the future.
template <>
struct FuzzingConfig<X86_64> {
  // The start_address address must be page aligned.
  // The num_bytes must be a power of 2.
  MemoryRange code_range;

  // The start_address address must be page aligned.
  // The num_bytes must be a multiple of page size.
  MemoryRange data1_range;

  // Constraints for start_address and num_bytes are same as data1.
  MemoryRange data2_range;
};

template <>
static constexpr FuzzingConfig<X86_64> DEFAULT_FUZZING_CONFIG<X86_64> = {
    .code_range =
        {
            .start_address = 0x3000'0000,
            .num_bytes = 0x8000'0000,  // 2 GB
        },
    .data1_range =
        {
            .start_address = 0x1'0000,
            .num_bytes = 0x2000'0000,  // 512 MB
        },
    .data2_range =
        {
            .start_address = 0x10'0001'0000,
            .num_bytes = 0x2000'0000,  // 512 MB
        },
};

// Inheritance doesn't play well with designated initializers, so we're
// manually duplicating parts of the config rather than inheriting from a base
// config.
// Even if the configs had identical fields, we'd probally want to keep the
// types separate so type checking could catch config confusion.
template <>
struct FuzzingConfig<AArch64> {
  MemoryRange code_range;

  // AArch64 currently has a separate stack. We may want to re-evaluate this in
  // the future. For now, however, this simplifies the proxy because the
  // Snapshot either includes each memory mapping in its entirety or completely
  // omits it.
  MemoryRange stack_range;

  MemoryRange data1_range;
  MemoryRange data2_range;
  bool sve_instructions_allowed;
};

template <>
static constexpr FuzzingConfig<AArch64> DEFAULT_FUZZING_CONFIG<AArch64> = {
    .code_range =
        {
            .start_address = 0x3000'0000,
            .num_bytes = 0x8000'0000,  // 2 GB
        },
    .stack_range =
        {
            .start_address = 0x200'0000,
            .num_bytes = 0x1000,
        },

    .data1_range =
        {
            .start_address = 0x7'0000'0000,
            .num_bytes = 0x40'0000,  // 4 MB
        },
    .data2_range =
        {
            .start_address = 0x1007'0000'0000,
            .num_bytes = 0x40'0000,  // 4 MB
        },
    .sve_instructions_allowed = false,
};

// This config is used to accommodate proxies with limited physical memory.
template <>
static constexpr FuzzingConfig<AArch64> LIMITED_MEMORY_FUZZING_CONFIG<AArch64> =
    {
        .code_range =
            {
                .start_address = 0x3000'0000,
                .num_bytes = 0x8000'0000,  // 2 GB
            },
        .stack_range =
            {
                .start_address = 0x200'0000,
                .num_bytes = 0x1000,
            },

        .data1_range =
            {
                .start_address = 0x7'0000'0000,
                .num_bytes = 0x4000,  // 16 KB
            },
        .data2_range =
            {
                .start_address = 0x1007'0000'0000,
                .num_bytes = 0x4000,  // 16 KB
            },
        .sve_instructions_allowed = false,
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_PROXY_CONFIG_H_
