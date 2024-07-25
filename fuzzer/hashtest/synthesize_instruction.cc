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

#include "./fuzzer/hashtest/synthesize_instruction.h"

#include <bitset>
#include <cstddef>
#include <cstdint>
#include <random>
#include <utility>
#include <vector>

#include "./fuzzer/hashtest/candidate.h"
#include "./fuzzer/hashtest/debugging.h"
#include "./fuzzer/hashtest/rand_util.h"
#include "./fuzzer/hashtest/register_info.h"
#include "./fuzzer/hashtest/synthesize_base.h"
#include "./fuzzer/hashtest/xed_operand_util.h"
#include "./instruction/xed_util.h"
#include "./util/checks.h"

namespace silifuzz {

namespace {

// Internal helper for PrepareFixedRegisters.
template <size_t N>
void PrepareFixedRegisters(RegisterBank bank, const std::bitset<N>& read,
                           const std::bitset<N>& written, std::bitset<N>& tmp,
                           std::vector<RegisterID>& needs_init,
                           std::vector<unsigned int>& is_written) {
  for (size_t i = 0; i < N; i++) {
    if (read.test(i) || written.test(i)) {
      // Validate the register is in the tmp set.
      CHECK(tmp.test(i));
      tmp[i] = false;
    }
    if (read.test(i)) {
      needs_init.push_back(
          RegisterID{.bank = bank, .index = static_cast<unsigned int>(i)});
    }
    if (written.test(i)) {
      is_written.push_back(i);
    }
  }
}

// Remove the fixed registers from the temp set and generate lists of fixed
// registers that may be read and written by the instruction.
void PrepareFixedRegisters(const RegisterReadWrite& fixed_reg,
                           RegisterMask& tmp,
                           std::vector<RegisterID>& needs_init,
                           std::vector<unsigned int>& is_written) {
  PrepareFixedRegisters(RegisterBank::kGP, fixed_reg.read.gp,
                        fixed_reg.written.gp, tmp.gp, needs_init, is_written);
  PrepareFixedRegisters(RegisterBank::kVec, fixed_reg.read.vec,
                        fixed_reg.written.vec, tmp.vec, needs_init, is_written);
  PrepareFixedRegisters(RegisterBank::kMask, fixed_reg.read.mask,
                        fixed_reg.written.mask, tmp.mask, needs_init,
                        is_written);
  PrepareFixedRegisters(RegisterBank::kMMX, fixed_reg.read.mmx,
                        fixed_reg.written.mmx, tmp.mmx, needs_init, is_written);
}

template <size_t N>
unsigned int HandleOperand(RegisterBank bank, Rng& rng, std::bitset<N>& tmp,
                           std::bitset<N>& entropy, bool read, bool written,
                           std::vector<RegisterID>& needs_init,
                           std::vector<unsigned int>& is_written) {
  if (written) {
    // Write to temp registers.
    unsigned int index = PopRandomBit(rng, tmp);
    if (read) {
      needs_init.push_back(RegisterID{.bank = bank, .index = index});
    }
    is_written.push_back(index);
    return index;
  } else {
    // Read directly from entropy.
    return PopRandomBit(rng, entropy);
  }
}

}  // namespace

[[nodiscard]] bool SynthesizeTestInstruction(
    const InstructionCandidate& candidate, RegisterPool& rpool, Rng& rng,
    unsigned int effective_op_width, std::vector<RegisterID>& needs_init,
    std::vector<unsigned int>& reg_is_written, uint8_t* ibuf,
    size_t& ibuf_len) {
  const RegisterBank mode = candidate.OutputMode();
  const xed_inst_t* instruction = candidate.instruction;

  // Use a writemask ~1/3rd of the time.
  // On one hand we want to test writemasks, on the other hand they
  // discard output bits.
  bool use_writemask =
      candidate.writemask && std::bernoulli_distribution(0.333)(rng);
  // Zero half the time.
  // Note: it appears that masked writes to mask registers must always be
  // zeroing, although the disassembly doesn't include a {z}.
  bool zero_writemask =
      use_writemask &&
      (std::bernoulli_distribution(0.5)(rng) || mode == RegisterBank::kMask);

  // Remove the fixed registers from the tmp bitmask.
  PrepareFixedRegisters(candidate.fixed_reg, rpool.tmp, needs_init,
                        reg_is_written);

  InstructionBuilder builder(xed_inst_iclass(instruction), effective_op_width);

  // Generate each operand
  for (size_t operand_index = 0;
       operand_index < xed_inst_noperands(instruction); ++operand_index) {
    const xed_operand_t* const operand =
        xed_inst_operand(instruction, operand_index);

    if (OperandIsRegister(operand)) {
      bool written = xed_operand_written(operand);
      bool read = xed_operand_read(operand) ||
                  xed_operand_conditional_write(operand) ||
                  (written && use_writemask && !zero_writemask);

      if (OperandIsExplicit(operand)) {
        xed_encoder_operand_t op = {.type = XED_ENCODER_OPERAND_TYPE_INVALID};

        if (OperandIsGPRegister(operand)) {
          // Explicit general purpose register.
          CHECK(!written || mode == RegisterBank::kGP);
          unsigned int index = HandleOperand(
              RegisterBank::kGP, rng, rpool.tmp.gp, rpool.entropy.gp, read,
              written, needs_init, reg_is_written);
          op =
              GPRegOperand(index, OperandBitWidth(operand, effective_op_width));
        } else if (OperandIsVectorRegister(operand)) {
          // Explicit vector register.
          CHECK(!written || mode == RegisterBank::kVec);
          unsigned int index = HandleOperand(
              RegisterBank::kVec, rng, rpool.tmp.vec, rpool.entropy.vec, read,
              written, needs_init, reg_is_written);
          op = VecRegOperand(index, VectorWidth(operand));
        } else if (OperandIsMaskRegister(operand)) {
          // Explicit mask register.
          if (OperandIsWritemask(operand)) {
            CHECK(!written);
            if (use_writemask) {
              unsigned int index = PopRandomBit(rng, rpool.entropy.mask);
              op = MaskRegOperand(index);
            } else {
              // When k0 is used as writemask, this means "ignore writemask".
              op = MaskRegOperand(0);
            }
          } else {
            CHECK(!written || mode == RegisterBank::kMask);
            unsigned int index = HandleOperand(
                RegisterBank::kMask, rng, rpool.tmp.mask, rpool.entropy.mask,
                read, written, needs_init, reg_is_written);
            op = MaskRegOperand(index);
          }
        } else if (OperandIsMMXRegister(operand)) {
          // Explicit MMX register.
          CHECK(!written || mode == RegisterBank::kMMX);
          unsigned int index = HandleOperand(
              RegisterBank::kMMX, rng, rpool.tmp.mmx, rpool.entropy.mmx, read,
              written, needs_init, reg_is_written);
          op = MMXRegOperand(index);
        } else {
          DieBecauseOperand(instruction, operand);
        }
        builder.AddOperands(std::move(op));
      } else if (OperandIsFlagRegister(operand)) {
        // Nothing needed, this is XED explicitly annotating flag access.
        CHECK(OperandIsSuppressed(operand));
      } else if (OperandIsImplicit(operand) || OperandIsSuppressed(operand)) {
        // Note: we're handling suppressed operands here so that we can validate
        // they are not anything unexpected. They will not affect the encoded
        // instruction, supressed operands cannot be affected in any way.
        xed_encoder_operand_t op = {.type = XED_ENCODER_OPERAND_TYPE_INVALID};
        if (xed_operand_type(operand) == XED_OPERAND_TYPE_REG) {
          // A fixed register.
          op = xed_reg(xed_operand_reg(operand));
        } else if (xed_operand_type(operand) == XED_OPERAND_TYPE_NT_LOOKUP_FN) {
          // A fixed GP register of variable width.
          xed_nonterminal_enum_t name = xed_operand_nonterminal_name(operand);
          RegisterID reg_id = XedNonterminalToRegisterID(name);
          CHECK(reg_id.bank == RegisterBank::kGP);
          op = GPRegOperand(reg_id.index,
                            OperandBitWidth(operand, effective_op_width));
        } else {
          DieBecauseOperand(instruction, operand);
        }
        // Implicit operands must be emitted, suppressed must not.
        if (OperandIsImplicit(operand)) {
          builder.AddOperands(std::move(op));
        }
      } else {
        DieBecauseOperand(instruction, operand);
      }
    } else if (OperandIsImmediate(operand)) {
      // Note: IMM1 only used for memory ops?
      CHECK_EQ(xed_operand_name(operand), XED_OPERAND_IMM0);
      if (OperandIsExplicit(operand)) {
        // Note: XED appears to truncate out-of-range immediates, so we don't
        // bother doing it here.
        // TODO(ncbray): bias towards "interesting" intermediates such as 0, 1,
        // -1, etc?
        builder.AddOperands(
            xed_simm0(rng(), OperandBitWidth(operand, effective_op_width)));
      } else if (OperandIsImplicit(operand)) {
        // Implicit immediates appear to always be 1?
        builder.AddOperands(xed_simm0(1, 8));
      } else {
        // A supressed immediate doesn't make sense?
        DieBecauseOperand(instruction, operand);
      }
    } else {
      DieBecauseOperand(instruction, operand);
    }
  }

  if (zero_writemask) {
    builder.AddOperands(xed_other(XED_OPERAND_ZEROING, 1));
  }

  return builder.Encode(ibuf, ibuf_len);
}

}  // namespace silifuzz
