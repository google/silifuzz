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

#ifndef THIRD_PARTY_SILIFUZZ_TRACING_DEFAULT_DISASSEMBLER_H_
#define THIRD_PARTY_SILIFUZZ_TRACING_DEFAULT_DISASSEMBLER_H_

#include "./tracing/capstone_disassembler.h"
#include "./tracing/xed_disassembler.h"
#include "./util/arch.h"

namespace silifuzz {
namespace disassembler_internal {

// A helper type since we cannot specialize a using statement directly.
template <typename Arch>
struct Default;

template <>
struct Default<X86_64> {
  using Type = XedDisassembler;
};

template <>
struct Default<AArch64> {
  using Type = CapstoneDisassembler<AArch64>;
};

}  // namespace disassembler_internal

template <typename Arch>
using DefaultDisassembler = typename disassembler_internal::Default<Arch>::Type;

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_DEFAULT_DISASSEMBLER_H_
