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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_SYNTHESIZE_TEST_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_SYNTHESIZE_TEST_H_

#include <cstddef>
#include <cstdint>

#include "./fuzzer/hashtest/instruction_pool.h"
#include "./fuzzer/hashtest/synthesize_base.h"

namespace silifuzz {

// Generate a single iteration of a randomized hash function.
// A single iteration will update all of the entropy registers.
// The full test will iterate the loop body an arbitrary number of times.
// Every time the loop body is iterated, random inputs will be passed into test
// instructions, and the outputs will be folded back into the entropy pool.
// Because of how the loop body is designed, it should be possible to detect if
// data corruption occured during any of the iterations with high probability,
// no matter how many iterations are executed.
// The caller is responsible for setting up the initial entropy pools and
// generating instructions to iterate the loop body multiple times.
void SynthesizeLoopBody(Rng& rng, const InstructionPool& ipool,
                        const RegisterPool& rpool, InstructionBlock& block);

// Generate an instruction that decrements the GP register `dst` in place.
void SynthesizeGPRegDec(unsigned int dst, InstructionBlock& block);

// Generate a branch that will be taken if the flags indicate a value is greater
// than zero. Intended to build do-while loops that count down to zero.
// `offset` is the branch offset from the _begining_ of the instruction, not the
// end. This is different than how x86 encodes branch displacements.
void SynthesizeJnle(int32_t offset, InstructionBlock& block);

// Synthesize a return instruction.
void SynthesizeReturn(InstructionBlock& block);

// Synthesize `count` breakpoint traps. Useful for padding executable data.
void SynthesizeBreakpointTraps(size_t count, InstructionBlock& block);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_SYNTHESIZE_TEST_H_
