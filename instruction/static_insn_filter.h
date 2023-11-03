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

#ifndef THIRD_PARTY_SILIFUZZ_INSTRUCTION_STATIC_INSN_FILTER_H_
#define THIRD_PARTY_SILIFUZZ_INSTRUCTION_STATIC_INSN_FILTER_H_

#include "absl/strings/string_view.h"
#include "./util/arch.h"

namespace silifuzz {

template <typename Arch>
struct InstructionFilterConfig;

template <typename Arch>
static constexpr InstructionFilterConfig<Arch>
    DEFAULT_INSTRUCTION_FILTER_CONFIG;

template <>
struct InstructionFilterConfig<X86_64> {};

template <>
static constexpr InstructionFilterConfig<X86_64>
    DEFAULT_INSTRUCTION_FILTER_CONFIG<X86_64> = {};

template <>
struct InstructionFilterConfig<AArch64> {
  bool sve_instructions_allowed;
};

template <>
static constexpr InstructionFilterConfig<AArch64>
    DEFAULT_INSTRUCTION_FILTER_CONFIG<AArch64> = {
        .sve_instructions_allowed = false,
};

// Accept or reject this instruction sequence using simple static analysis.
// Returns true if the static analysis believes `code` is OK.
// Static analysis can be imprecise, so this function is biased towards
// filtering out obvious problems and letting everything else through.
// Static analysis should be lightweight compared to the full making process and
// works fine even with a host / target mismatch - such as fuzzing aarch64 qemu
// on a x86_64 host.
// Some architectures may not filter any instruction sequence at this stage and
// always return true.
template <typename Arch>
bool StaticInstructionFilter(absl::string_view code,
                             const InstructionFilterConfig<Arch>& config =
                                 DEFAULT_INSTRUCTION_FILTER_CONFIG<Arch>);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_INSTRUCTION_STATIC_INSN_FILTER_H_
