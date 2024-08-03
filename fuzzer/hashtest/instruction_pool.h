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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_INSTRUCTION_POOL_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_INSTRUCTION_POOL_H_

#include <vector>

#include "./fuzzer/hashtest/candidate.h"
#include "./fuzzer/hashtest/synthesize_base.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

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

void GenerateInstructionPool(Rng& rng, xed_chip_enum_t chip,
                             InstructionPool& ipool, bool verbose = false);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_INSTRUCTION_POOL_H_
