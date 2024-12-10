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

#include "./fuzzer/hashtest/synthesize_snapshot.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/raw_insns_util.h"
#include "./common/snapshot.h"
#include "./fuzzer/hashtest/instruction_pool.h"
#include "./fuzzer/hashtest/synthesize_base.h"
#include "./fuzzer/hashtest/synthesize_shuffle.h"
#include "./fuzzer/hashtest/synthesize_test.h"
#include "./fuzzer/hashtest/version.h"
#include "./runner/make_snapshot.h"
#include "./runner/runner_provider.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/ucontext/ucontext_types.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

namespace {

uint64_t& GetGPReg(unsigned int index, UContext<X86_64>& ucontext) {
  // Indexes are designed to map to the XED register enum.
  // To map to the UContext field, we map the XED register first to make the
  // case statement easier to verify.
  xed_reg_enum_t reg = static_cast<xed_reg_enum_t>(XED_REG_GPR64_FIRST + index);
  switch (reg) {
    case XED_REG_RAX:
      return ucontext.gregs.rax;
    case XED_REG_RCX:
      return ucontext.gregs.rcx;
    case XED_REG_RDX:
      return ucontext.gregs.rdx;
    case XED_REG_RBX:
      return ucontext.gregs.rbx;
    case XED_REG_RSP:
      return ucontext.gregs.rsp;
    case XED_REG_RBP:
      return ucontext.gregs.rbp;
    case XED_REG_RSI:
      return ucontext.gregs.rsi;
    case XED_REG_RDI:
      return ucontext.gregs.rdi;
    case XED_REG_R8:
      return ucontext.gregs.r8;
    case XED_REG_R9:
      return ucontext.gregs.r9;
    case XED_REG_R10:
      return ucontext.gregs.r10;
    case XED_REG_R11:
      return ucontext.gregs.r11;
    case XED_REG_R12:
      return ucontext.gregs.r12;
    case XED_REG_R13:
      return ucontext.gregs.r13;
    case XED_REG_R14:
      return ucontext.gregs.r14;
    case XED_REG_R15:
      return ucontext.gregs.r15;
    default:
      LOG_FATAL("Unimplemented register: ", xed_reg_enum_t2str(reg));
  }
}

void SetGPReg(unsigned int index, UContext<X86_64>& ucontext, uint64_t value) {
  GetGPReg(index, ucontext) = value;
}

void RandomizeGPReg(unsigned int index, UContext<X86_64>& ucontext, Rng& rng) {
  // Relies on rng producing 64 bits of entropy.
  SetGPReg(index, ucontext, rng());
}

__uint128_t& GetVecReg(unsigned int index, UContext<X86_64>& ucontext) {
  return ucontext.fpregs.xmm[index];
}

void SetVecReg(unsigned int index, UContext<X86_64>& ucontext,
               __uint128_t value) {
  GetVecReg(index, ucontext) = value;
}

// Note: only randomizes XMM, effectively.
void RandomizeVecReg(unsigned int index, UContext<X86_64>& ucontext, Rng& rng) {
  SetVecReg(index, ucontext, (static_cast<__uint128_t>(rng()) << 64) | rng());
}

__uint128_t& GetSTReg(unsigned int index, UContext<X86_64>& ucontext) {
  return ucontext.fpregs.st[index];
}

void SetSTReg(unsigned int index, UContext<X86_64>& ucontext,
              __uint128_t value) {
  GetSTReg(index, ucontext) = value;
}

void RandomizeSTReg(unsigned int index, UContext<X86_64>& ucontext, Rng& rng) {
  // 80-bit random value.
  __uint128_t value =
      (static_cast<__uint128_t>(static_cast<uint16_t>(rng())) << 64) | rng();
  SetSTReg(index, ucontext, value);
}

}  // namespace

absl::StatusOr<Snapshot> CreateSnapshot(Rng& rng, const RegisterPool& rpool,
                                        size_t iteration_count,
                                        const InstructionBlock& block,
                                        bool make) {
  absl::string_view view = block.View();
  std::string id = InstructionsToSnapshotId(view);
  UContext<X86_64> ucontext = GenerateUContextForInstructions<X86_64>(view);

  // Initialize the loop counter.
  SetGPReg(kLoopIndex, ucontext, iteration_count);

  // Randomize the entropy pools.
  for (size_t i = 0; i < rpool.entropy.gp.size(); i++) {
    if (rpool.entropy.gp.test(i)) {
      RandomizeGPReg(i, ucontext, rng);
    }
  }
  // Note: the UContext only contains the lowest 128 bits of each vector
  // register. This means the upper part of the entropy pool will start zeroed,
  // and the test will need to iterate a few times to permute and mix the pool
  // and get rid of the zeros.
  for (size_t i = 0; i < rpool.entropy.vec.size(); i++) {
    if (rpool.entropy.vec.test(i)) {
      RandomizeVecReg(i, ucontext, rng);
    }
  }
  // Note: the UContext does not contain mask registers so we need to initialize
  // them elsewhere.
  for (size_t i = 0; i < rpool.entropy.mmx.size(); i++) {
    if (rpool.entropy.mmx.test(i)) {
      RandomizeSTReg(i, ucontext, rng);
    }
  }

  // TODO(ncbray): randomize FP rounding mode, etc.

  ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot snapshot,
                             InstructionsToSnapshot(view, ucontext));
  // Note: the Snapshot ID doesn't encapsulate the initial register state.
  snapshot.set_id(id);
  snapshot.set_metadata(
      Snapshot::Metadata(Snapshot::Metadata::Origin::kUseString,
                         absl::StrCat("HashTestV", kHashTestVersionMajor, ".",
                                      kHashTestVersionMinor)));

  if (make) {
    return MakeSnapshot(snapshot, MakingConfig::Default(RunnerLocation()));
  } else {
    return snapshot;
  }
}

absl::StatusOr<Snapshot> SynthesizeTestSnapshot(Rng& rng, xed_chip_enum_t chip,
                                                const InstructionPool& ipool,
                                                bool make) {
  RegisterPool rpool{};
  InitRegisterLayout(chip, rpool);

  // Synthesize the body first, so we know how many instructions it contains.
  InstructionBlock body{};
  SynthesizeLoopBody(rng, ipool, rpool, body);

  // Decrement the loop counter at the end of the loop body.
  SynthesizeGPRegDec(kLoopIndex, body);

  InstructionBlock block{};

  // Preamble
  if (rpool.mask_width > 0) {
    // Initialize the mask entropy pool.
    // Cannot initialize these registers with a snapshot, so do it explicitly
    // with instructions.
    for (size_t i = 0; i < rpool.entropy.mask.size(); i++) {
      if (rpool.entropy.mask.test(i)) {
        // Use RAX as a temp register to hold
        unsigned int tmp = 0;
        SynthesizeMaskRegConstInit(rng(), i, tmp, rpool, block);
      }
    }
  }

  size_t header_instruction_count = block.num_instructions;

  // Still need to add back edge.
  size_t body_instruction_count = body.num_instructions + 1;

  // Calculate how many times we can iterate without exceeding the target
  // instruction count.
  size_t target_instruction_count = 1000;
  size_t iteration_count =
      (target_instruction_count - header_instruction_count) /
      body_instruction_count;

  // Add the body.
  block.Append(body);

  // Using JNLE so that the loop will abort if an SDC causes us to miss zero
  // or jump to a negative index.
  SynthesizeJnle(-(int32_t)body.bytes.size(), block);

  return CreateSnapshot(rng, rpool, iteration_count, block, make);
}

}  // namespace silifuzz
