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
#include <vector>

#include "./fuzzer/hashtest/candidate.h"
#include "./fuzzer/hashtest/register_info.h"
#include "./fuzzer/hashtest/synthesize_base.h"

namespace silifuzz {

// A set of instructions we can use for generating tests, grouped by which
// register bank they affect.
struct InstructionPool {
  // x86 instructions will write to, at most, one register bank.
  // Some instructions may also write to the flags register.

  // Instruction does not appear to read or write registers.
  std::vector<InstructionCandidate> no_effect;
  // Instruction sets the flag bits but does not read from a register bank.
  std::vector<InstructionCandidate> flag_manipulation;
  // Instruction sets flags and reads from a register bank.
  std::vector<InstructionCandidate> compare;
  // Instructions writes to the GP register bank, may also write flags.
  std::vector<InstructionCandidate> greg;
  // Instructions writes to the vector register bank.
  std::vector<InstructionCandidate> vreg;
  // Instructions writes to the mask register bank.
  std::vector<InstructionCandidate> mreg;
  // Instructions writes to the x87/MMX register bank.
  std::vector<InstructionCandidate> mmxreg;

  void Add(const InstructionCandidate& candidate) {
    if (candidate.reg_written.gp) {
      greg.push_back(candidate);
    } else if (candidate.reg_written.vec) {
      vreg.push_back(candidate);
    } else if (candidate.reg_written.mask) {
      mreg.push_back(candidate);
    } else if (candidate.reg_written.mmx) {
      mmxreg.push_back(candidate);
    } else if (candidate.fixed_reg.written.flags) {
      if (candidate.reg_read.Total() > 0) {
        compare.push_back(candidate);
      } else {
        flag_manipulation.push_back(candidate);
      }
    } else {
      no_effect.push_back(candidate);
    }
  }
};

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

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_SYNTHESIZE_TEST_H_
