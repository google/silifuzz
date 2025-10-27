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

#include "./fuzzer/hashtest/testgeneration/synthesize_shuffle.h"

#include <cstddef>
#include <cstdint>
#include <random>

#include "./fuzzer/hashtest/testgeneration/rand_util.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_base.h"
#include "./fuzzer/hashtest/testgeneration/weighted_choose_one.h"
#include "./instruction/xed_util.h"
#include "./util/checks.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

void SynthesizeGPRegConstInit(uint64_t value, unsigned int dst,
                              InstructionBlock& block) {
  InstructionBuilder builder(XED_ICLASS_MOV, 64U);
  builder.AddOperands(GPRegOperand(dst, 64), xed_imm0(value, 64));
  Emit(builder, block);
}

void SynthesizeGPRegMov(unsigned int src, unsigned int dst,
                        InstructionBlock& block) {
  InstructionBuilder builder(XED_ICLASS_MOV, 64U);
  builder.AddOperands(GPRegOperand(dst, 64), GPRegOperand(src, 64));
  Emit(builder, block);
}

void SynthesizeGPRegPermute(Rng& rng, unsigned int dst,
                            InstructionBlock& block) {
  WeightedChooseOne(
      rng,
      // Rotate left.
      WeightedChoice{
          2,
          [&] {
            InstructionBuilder builder(XED_ICLASS_ROL, 64U);
            std::uniform_int_distribution<unsigned int> dist(1, 63);
            builder.AddOperands(GPRegOperand(dst, 64), xed_imm0(dist(rng), 8));
            Emit(builder, block);
          },
      },
      // Rotate right.
      WeightedChoice{
          2,
          [&] {
            InstructionBuilder builder(XED_ICLASS_ROR, 64U);
            std::uniform_int_distribution<unsigned int> dist(1, 63);
            builder.AddOperands(GPRegOperand(dst, 64), xed_imm0(dist(rng), 8));
            Emit(builder, block);
          },
      },
      // Byte swap.
      // There is only one way to BSWAP, so it should be rarer than
      // parameterizable permutations. It is also its own inverse.
      WeightedChoice{
          1,
          [&] {
            InstructionBuilder builder(XED_ICLASS_BSWAP, 64U);
            builder.AddOperands(GPRegOperand(dst, 64));
            Emit(builder, block);
          },
      });
}

void SynthesizeGPRegMix(Rng& rng, unsigned int src, unsigned int dst,
                        InstructionBlock& block) {
  WeightedChooseOne(
      rng,
      // XOR
      WeightedChoice{
          1,
          [&] {
            InstructionBuilder builder(XED_ICLASS_XOR, 64U);
            builder.AddOperands(GPRegOperand(dst, 64), GPRegOperand(src, 64));
            Emit(builder, block);
          },
      },
      // ADD
      WeightedChoice{
          1,
          [&] {
            InstructionBuilder builder(XED_ICLASS_ADD, 64U);
            builder.AddOperands(GPRegOperand(dst, 64), GPRegOperand(src, 64));
            Emit(builder, block);
          },
      },
      // SUB
      WeightedChoice{
          1,
          [&] {
            InstructionBuilder builder(XED_ICLASS_SUB, 64U);
            builder.AddOperands(GPRegOperand(dst, 64), GPRegOperand(src, 64));
            Emit(builder, block);
          },
      });
}

void SynthesizeVecRegMov(unsigned int src, unsigned int dst,
                         RegisterPool& rpool, InstructionBlock& block) {
  // Instructions that operate on 512-bit registers take writemasks, and
  // instructions that take writemasks care about element width.
  xed_iclass_enum_t iclass =
      rpool.vec_width >= 512 ? XED_ICLASS_VMOVDQA64 : XED_ICLASS_VMOVDQA;
  InstructionBuilder builder(iclass, 64U);
  builder.AddOperands(VecRegOperand(dst, rpool.vec_width));
  if (rpool.vec_width >= 512) {
    builder.AddOperands(MaskRegOperand(0));
  }
  builder.AddOperands(VecRegOperand(src, rpool.vec_width));
  Emit(builder, block);
}

void SynthesizeVecRegPermute(Rng& rng, unsigned int src, unsigned int dst,
                             RegisterPool& rpool, InstructionBlock& block) {
  // There are a variety of ways to permute vector registers. For simplicity and
  // performance, we're currently restricting our choices to permutations that
  // can be implemented with a single instruction. These instructions encode the
  // permutation mask in the instruction itself, and that immediate is 8 bits.
  // As a consequence, there are limits to the type of permutations that can be
  // expressed. Specifically, permutations cannot cross "lanes". For example, if
  // we are permuting 32-bit chunks of the vector register, the chunks must stay
  // within a 128-bit lane / subsection of the vector register. 64-bit chunks
  // must stay withing 256-bit lanes, and 128-bit chunks can be shuffled
  // anywhere in a 512-bit register. Although each permutation operation is
  // somewhat limited, over time the entropy will flow through several
  // permuation operations of different sizes and get scattered across the
  // registers.
  // TODO(ncbray): byte-level permutations. This will require materializing a
  // larger permutation mask into a register.
  // Since all the permutations are chosen randomly, there is no guarentee that
  // the composition of the permutations will not have a subcycle (in other
  // words there is no guarantee that one bit flip in the entropy pool can flow
  // to any other bit). For the simplest example, we may not generate a
  // permutation that allows data to cross between the upper and lower halves of
  // a 512-bit register. Or we may generate a two permutations that can cross
  // the halves of the 512-bit register, but cancel each other out. With a
  // sufficient number of random permutations, however, this scenario is
  // unlikely. If it occurs, it may reduce the sensitivity of the test but is
  // but only by a modest amount (?).
  // TODO(ncbray): guarentee permutations will fully cycle the entropy.
  // One limitation of the current implementation is that bits within each
  // 32-bit chunk will not be permuted.
  // TODO(ncbray): register rotate (requires temp register to combine shifts)
  WeightedChooseOne(
      rng,
      // For each 512-bit subsection of the full vector register,
      // divide the subsection into 4 128-bit chunks and permute
      // them. Each subsection is permuted in the same way.
      WeightedChoice{
          rpool.vec_width >= 512 ? 1 : 0,
          [&]() {
            CHECK_GE(rpool.vec_width, 512);
            InstructionBuilder builder(XED_ICLASS_VSHUFI64X2, 64U);
            builder.AddOperands(VecRegOperand(dst, rpool.vec_width),
                                MaskRegOperand(0),
                                VecRegOperand(src, rpool.vec_width),
                                VecRegOperand(src, rpool.vec_width),
                                xed_imm0(RandomPermutationMask<2>(rng), 8));
            Emit(builder, block);
          },
      },
      // For each 256-bit subsection of the full vector register,
      // divide the subsection into 4 64-bit chunks and permute
      // them. Each subsection is permuted in the same way.
      WeightedChoice{
          rpool.vec_width >= 256 ? 1 : 0,
          [&]() {
            CHECK_GE(rpool.vec_width, 256);
            InstructionBuilder builder(XED_ICLASS_VPERMQ, 64U);
            builder.AddOperands(VecRegOperand(dst, rpool.vec_width));
            if (rpool.vec_width >= 512) {
              builder.AddOperands(MaskRegOperand(0));
            }
            builder.AddOperands(VecRegOperand(src, rpool.vec_width),
                                xed_imm0(RandomPermutationMask<2>(rng), 8));
            Emit(builder, block);
          },
      },
      // For each 128-bit subsection of the full vector register,
      // divide the subsection into 4 32-bit chunks and permute
      // them. Each subsection is permuted in the same way.
      WeightedChoice{
          1,
          [&]() {
            CHECK_GE(rpool.vec_width, 128);
            InstructionBuilder builder(XED_ICLASS_VPSHUFD, 64U);
            builder.AddOperands(VecRegOperand(dst, rpool.vec_width));
            if (rpool.vec_width >= 512) {
              builder.AddOperands(MaskRegOperand(0));
            }
            builder.AddOperands(VecRegOperand(src, rpool.vec_width),
                                xed_imm0(RandomPermutationMask<2>(rng), 8));
            Emit(builder, block);
          },
      });
}

void SynthesizeVecRegMix(Rng& rng, unsigned int a, unsigned int b,
                         unsigned int dst, RegisterPool& rpool,
                         InstructionBlock& block) {
  // Randomize the order of arguments passed to the mixing instructions.
  SometimesSwap(rng, a, b);

  WeightedChooseOne(
      rng,
      // ADD / SUB
      WeightedChoice{
          2,
          [&] {
            xed_iclass_enum_t iclass =
                ChooseRandomElement(rng, {
                                             XED_ICLASS_VPADDB,
                                             XED_ICLASS_VPADDW,
                                             XED_ICLASS_VPADDD,
                                             XED_ICLASS_VPADDQ,
                                             XED_ICLASS_VPSUBB,
                                             XED_ICLASS_VPSUBW,
                                             XED_ICLASS_VPSUBD,
                                             XED_ICLASS_VPSUBQ,
                                         });
            InstructionBuilder builder(iclass, 64U);
            builder.AddOperands(VecRegOperand(dst, rpool.vec_width));
            if (rpool.vec_width >= 512) {
              // Must use EVEX encoding.
              builder.AddOperands(MaskRegOperand(0));
            }
            builder.AddOperands(VecRegOperand(a, rpool.vec_width),
                                VecRegOperand(b, rpool.vec_width));
            Emit(builder, block);
          },
      },
      // XOR
      WeightedChoice{
          1,
          [&] {
            // The XOR opcode cares about element width when write masks
            // are used, so we have a different opcode for 512-bit registers.
            xed_iclass_enum_t iclass =
                rpool.vec_width >= 512
                    ? ChooseRandomElement(
                          rng, {XED_ICLASS_VPXORD, XED_ICLASS_VPXORQ})
                    : XED_ICLASS_VPXOR;
            InstructionBuilder builder(iclass, 64U);
            builder.AddOperands(VecRegOperand(dst, rpool.vec_width));
            if (rpool.vec_width >= 512) {
              builder.AddOperands(MaskRegOperand(0));
            }
            builder.AddOperands(VecRegOperand(a, rpool.vec_width),
                                VecRegOperand(b, rpool.vec_width));
            Emit(builder, block);
          },
      });
}

xed_iclass_enum_t MaskRegMovIClass(size_t mask_width) {
  switch (mask_width) {
    case 64:
      return XED_ICLASS_KMOVQ;
    case 32:
      return XED_ICLASS_KMOVD;
    case 16:
      return XED_ICLASS_KMOVW;
    default:
      LOG_FATAL("Width out of range.");
  }
}

xed_iclass_enum_t MaskRegAddIClass(size_t mask_width) {
  switch (mask_width) {
    case 64:
      return XED_ICLASS_KADDQ;
    case 32:
      return XED_ICLASS_KADDD;
    case 16:
      return XED_ICLASS_KADDW;
    default:
      LOG_FATAL("Width out of range.");
  }
}

xed_iclass_enum_t MaskRegOrIClass(size_t mask_width) {
  switch (mask_width) {
    case 64:
      return XED_ICLASS_KORQ;
    case 32:
      return XED_ICLASS_KORD;
    case 16:
      return XED_ICLASS_KORW;
    default:
      LOG_FATAL("Width out of range.");
  }
}

xed_iclass_enum_t MaskRegXorIClass(size_t mask_width) {
  switch (mask_width) {
    case 64:
      return XED_ICLASS_KXORQ;
    case 32:
      return XED_ICLASS_KXORD;
    case 16:
      return XED_ICLASS_KXORW;
    default:
      LOG_FATAL("Width out of range.");
  }
}

xed_iclass_enum_t MaskRegShiftLeftIClass(size_t mask_width) {
  switch (mask_width) {
    case 64:
      return XED_ICLASS_KSHIFTLQ;
    case 32:
      return XED_ICLASS_KSHIFTLD;
    case 16:
      return XED_ICLASS_KSHIFTLW;
    default:
      LOG_FATAL("Width out of range.");
  }
}

xed_iclass_enum_t MaskRegShiftRightIClass(size_t mask_width) {
  switch (mask_width) {
    case 64:
      return XED_ICLASS_KSHIFTRQ;
    case 32:
      return XED_ICLASS_KSHIFTRD;
    case 16:
      return XED_ICLASS_KSHIFTRW;
    default:
      LOG_FATAL("Width out of range.");
  }
}

void SynthesizeMaskRegConstInit(uint64_t value, unsigned int dst,
                                unsigned int tmp, RegisterPool& rpool,
                                InstructionBlock& block) {
  {
    InstructionBuilder builder(XED_ICLASS_MOV, rpool.mask_width);
    builder.AddOperands(GPRegOperand(tmp, rpool.mask_width),
                        xed_imm0(value, rpool.mask_width));
    Emit(builder, block);
  }
  {
    xed_iclass_enum_t iclass = MaskRegMovIClass(rpool.mask_width);
    InstructionBuilder builder(iclass, rpool.mask_width);
    builder.AddOperands(MaskRegOperand(dst),
                        GPRegOperand(tmp, rpool.mask_width));
    Emit(builder, block);
  }
}

void SynthesizeMaskRegMov(unsigned int src, unsigned int dst,
                          RegisterPool& rpool, InstructionBlock& block) {
  xed_iclass_enum_t iclass = MaskRegMovIClass(rpool.mask_width);
  InstructionBuilder builder(iclass, 64U);
  builder.AddOperands(MaskRegOperand(dst), MaskRegOperand(src));
  Emit(builder, block);
}

void SynthesizeMaskRegPermute(Rng& rng, unsigned int src, unsigned int dst,
                              RegisterPool& rpool, InstructionBlock& block) {
  // Choose a random shift amount.
  std::uniform_int_distribution<unsigned int> dist(1, rpool.mask_width - 1);
  unsigned int shift = dist(rng);

  // Choose a random temp register.
  unsigned int tmp = PopRandomBit(rng, rpool.tmp.mask);

  // Synthesize a register rotate with two shifts and a combine.
  {
    InstructionBuilder builder(MaskRegShiftLeftIClass(rpool.mask_width),
                               rpool.mask_width);
    builder.AddOperands(MaskRegOperand(tmp), MaskRegOperand(src),
                        xed_imm0(shift, 8));
    Emit(builder, block);
  }
  {
    InstructionBuilder builder(MaskRegShiftRightIClass(rpool.mask_width),
                               rpool.mask_width);
    builder.AddOperands(MaskRegOperand(dst), MaskRegOperand(src),
                        xed_imm0(rpool.mask_width - shift, 8));
    Emit(builder, block);
  }
  {
    InstructionBuilder builder(MaskRegOrIClass(rpool.mask_width),
                               rpool.mask_width);
    builder.AddOperands(MaskRegOperand(dst), MaskRegOperand(tmp),
                        MaskRegOperand(dst));
    Emit(builder, block);
  }
  rpool.tmp.mask[tmp] = true;
}

void SynthesizeMaskRegMix(Rng& rng, unsigned int a, unsigned int b,
                          unsigned int dst, RegisterPool& rpool,
                          InstructionBlock& block) {
  // Randomize the order of arguments passed to the mixing instructions.
  SometimesSwap(rng, a, b);

  WeightedChooseOne(
      rng,
      // Add
      WeightedChoice{
          1,
          [&] {
            InstructionBuilder builder(MaskRegAddIClass(rpool.mask_width),
                                       rpool.mask_width);
            builder.AddOperands(MaskRegOperand(dst), MaskRegOperand(a),
                                MaskRegOperand(b));
            Emit(builder, block);
          },
      },
      // Xor
      WeightedChoice{
          1,
          [&] {
            InstructionBuilder builder(MaskRegXorIClass(rpool.mask_width),
                                       rpool.mask_width);
            builder.AddOperands(MaskRegOperand(dst), MaskRegOperand(a),
                                MaskRegOperand(b));
            Emit(builder, block);
          },
      });
}

void SynthesizeMMXRegMov(unsigned int src, unsigned int dst,
                         InstructionBlock& block) {
  InstructionBuilder builder(XED_ICLASS_MOVQ, 64U);
  builder.AddOperands(MMXRegOperand(dst), MMXRegOperand(src));
  Emit(builder, block);
}

void SynthesizeMMXRegPermute(Rng& rng, unsigned int dst, unsigned int tmp,
                             bool tmp_is_copy_of_dst, InstructionBlock& block) {
  // Synthesize a register rotate with two shifts and a combine.
  std::uniform_int_distribution<unsigned int> dist(1, 63);
  unsigned int shift = dist(rng);

  // In some cases dst and tmp will already hold the same value and we don't
  // need to do a copy.
  if (!tmp_is_copy_of_dst) {
    SynthesizeMMXRegMov(dst, tmp, block);
  }

  // Shift left.
  {
    InstructionBuilder builder(XED_ICLASS_PSLLQ, 64U);
    builder.AddOperands(MMXRegOperand(dst), xed_imm0(shift, 8));
    Emit(builder, block);
  }
  // Shift right.
  {
    InstructionBuilder builder(XED_ICLASS_PSRLQ, 64U);
    builder.AddOperands(MMXRegOperand(tmp), xed_imm0(64 - shift, 8));
    Emit(builder, block);
  }
  // Combine shifts into rotate.
  {
    InstructionBuilder builder(XED_ICLASS_POR, 64U);
    builder.AddOperands(MMXRegOperand(dst), MMXRegOperand(tmp));
    Emit(builder, block);
  }
}

void SynthesizeMMXRegMix(Rng& rng, unsigned int src, unsigned int dst,
                         InstructionBlock& block) {
  WeightedChooseOne(
      rng,
      // ADD/ SUB
      WeightedChoice{
          2,
          [&] {
            xed_iclass_enum_t iclass =
                ChooseRandomElement(rng, {
                                             XED_ICLASS_PADDB,
                                             XED_ICLASS_PADDW,
                                             XED_ICLASS_PADDD,
                                             XED_ICLASS_PSUBB,
                                             XED_ICLASS_PSUBW,
                                             XED_ICLASS_PSUBD,
                                         });
            InstructionBuilder builder(iclass, 64U);
            builder.AddOperands(MMXRegOperand(dst), MMXRegOperand(src));
            Emit(builder, block);
          },
      },
      // XOR
      WeightedChoice{
          1,
          [&] {
            InstructionBuilder builder(XED_ICLASS_PXOR, 64U);
            builder.AddOperands(MMXRegOperand(dst), MMXRegOperand(src));
            Emit(builder, block);
          },
      });
}

}  // namespace silifuzz
