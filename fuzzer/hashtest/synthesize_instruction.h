// Copyright 2024 The Silifuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_SYNTHESIZE_INSTRUCTION_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_SYNTHESIZE_INSTRUCTION_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "./fuzzer/hashtest/candidate.h"
#include "./fuzzer/hashtest/register_info.h"
#include "./fuzzer/hashtest/synthesize_base.h"

namespace silifuzz {

// Synthesize a randomized instruction based on `candidate`.
// Used temp and entropy registers will be removed from `rpool`.
[[nodiscard]] bool SynthesizeTestInstruction(
    const InstructionCandidate& candidate, RegisterPool& rpool, Rng& rng,
    unsigned int effective_op_width, std::vector<RegisterID>& needs_init,
    std::vector<unsigned int>& is_written, uint8_t* ibuf, size_t& ibuf_len);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_SYNTHESIZE_INSTRUCTION_H_
