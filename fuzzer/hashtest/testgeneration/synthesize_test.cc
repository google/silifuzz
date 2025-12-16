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

#include "./fuzzer/hashtest/testgeneration/synthesize_test.h"

#include <algorithm>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#include "absl/types/span.h"
#include "./fuzzer/hashtest/testgeneration/candidate.h"
#include "./fuzzer/hashtest/testgeneration/instruction_pool.h"
#include "./fuzzer/hashtest/testgeneration/rand_util.h"
#include "./fuzzer/hashtest/testgeneration/register_info.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_base.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_instruction.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_shuffle.h"
#include "./instruction/xed_util.h"
#include "./util/checks.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

namespace {

const InstructionCandidate& ChooseRandomCandidate(std::mt19937_64& rng,
                                                  const InstructionPool* ipool,
                                                  RegisterBank bank) {
  switch (bank) {
    case RegisterBank::kGP:
      return ChooseRandomElement(rng, ipool->greg);
    case RegisterBank::kVec:
      return ChooseRandomElement(rng, ipool->vreg);
    case RegisterBank::kMask:
      return ChooseRandomElement(rng, ipool->mreg);
    case RegisterBank::kMMX:
      return ChooseRandomElement(rng, ipool->mmxreg);
    default:
      LOG(FATAL) << "Unknown register bank: " << static_cast<int>(bank);
  }
}

// Synthesize a series of MOV instructions that will copy entropy values into
// registers that will be used by the test instruction. Test instructions will
// need to have specific registers initialized with values if:
// 1) the register is read and modified. We do not want test instruction to
// write directly to the entropy pool.
// 2) the register is a fixed input register. The entropy pool was placed in
// registers that will never be fixed inputs or outputs, so a test instruction
// with a fixed input cannot read directly from the entropy pool.
void SynthesizeInits(std::mt19937_64& rng,
                     const std::vector<RegisterID>& needs_init,
                     RegisterPool& rpool, InstructionBlock& block) {
  // Initialize tmp registers that are read from.
  for (RegisterID reg : needs_init) {
    switch (reg.bank) {
      case RegisterBank::kGP:
        SynthesizeGPRegMov(PopRandomBit(rng, rpool.entropy.gp), reg.index,
                           block);
        break;
      case RegisterBank::kVec:
        SynthesizeVecRegMov(PopRandomBit(rng, rpool.entropy.vec), reg.index,
                            rpool, block);
        break;
      case RegisterBank::kMask:
        SynthesizeMaskRegMov(PopRandomBit(rng, rpool.entropy.mask), reg.index,
                             rpool, block);
        break;
      case RegisterBank::kMMX:
        SynthesizeMMXRegMov(PopRandomBit(rng, rpool.entropy.mmx), reg.index,
                            block);
        break;
      default:
        LOG_FATAL("Unimplemented bank: ", static_cast<int>(reg.bank));
        break;
    }
  }
}

// Collect data that the test instruction has written to temp registers.
// `entropy_mixin` will be used as the initial seed, all of the registers in
// `is_written` will be mixed in, and the result will be written to
// `entropy_output`.
// The output collection sequences tend to be fairly formulaic, so we try to
// make random choices in the few situations that we have choices.
void SynthesizeOutputCollection(std::mt19937_64& rng, RegisterID entropy_output,
                                RegisterID entropy_mixin,
                                const std::vector<unsigned int>& is_written,
                                RegisterPool& rpool, InstructionBlock& block) {
  // Validate the output and mixin registers.
  CHECK(entropy_output.bank == entropy_mixin.bank);
  CHECK(entropy_output.index != entropy_mixin.index);

  // Validate the registers modified by the test instruction.
  for (unsigned int index : is_written) {
    RegisterID id{.bank = entropy_output.bank, .index = index};

    // Check the output is disjoint.
    CHECK_NE(index, entropy_output.index)
        << static_cast<int>(id.bank) << " " << id.index;
    CHECK_NE(index, entropy_mixin.index)
        << static_cast<int>(id.bank) << " " << id.index;

    // Written registers should have been removed from the tmp set.
    CHECK(!rpool.tmp.Get(id)) << static_cast<int>(id.bank) << " " << id.index;
    // The entropy pool should not have been written to.
    CHECK(!rpool.entropy.Get(id))
        << static_cast<int>(id.bank) << " " << id.index;
  }

  // Synthesize the output collection.
  // We need to do this slightly differently for each register bank because the
  // instructions we use have different notions of sources and destinations. For
  // instance, GP register instructions will almost always need to modify one of
  // their input registers, but vector register instructions will have a
  // destination that is separate from their inputs.
  switch (entropy_output.bank) {
    case RegisterBank::kGP: {
      // The instructions we use for GP registers will modify the destination
      // register in place.
      // Copy the mixin into the destination.
      SynthesizeGPRegMov(entropy_mixin.index, entropy_output.index, block);
      for (unsigned int index : is_written) {
        // For each output, permute the destination register and mix in the
        // output.
        SynthesizeGPRegPermute(rng, entropy_output.index, block);
        SynthesizeGPRegMix(rng, index, entropy_output.index, block);
      }
      break;
    }
    case RegisterBank::kVec: {
      unsigned int src = entropy_mixin.index;
      for (unsigned int index : is_written) {
        unsigned int permuted = PopRandomBit(rng, rpool.tmp.vec);
        SynthesizeVecRegPermute(rng, src, permuted, rpool, block);

        // Write to the final output register on the final iteration, otherwise
        // write to a temp register.
        unsigned int dst = index == is_written.back()
                               ? entropy_output.index
                               : PopRandomBit(rng, rpool.tmp.vec);
        SynthesizeVecRegMix(rng, permuted, index, dst, rpool, block);

        // Free the intermediate register.
        rpool.tmp.vec[permuted] = true;

        // The output is not the new input.
        src = dst;
      }
      break;
    }
    case RegisterBank::kMask: {
      unsigned int src = entropy_mixin.index;
      for (unsigned int index : is_written) {
        unsigned int permuted = PopRandomBit(rng, rpool.tmp.mask);
        SynthesizeMaskRegPermute(rng, src, permuted, rpool, block);
        // Give back src if it's a temp register.
        if (src != entropy_mixin.index) {
          rpool.tmp.mask[src] = true;
        }

        // Write to the final output register on the final iteration, otherwise
        // write to a temp register.
        unsigned int dst = index == is_written.back()
                               ? entropy_output.index
                               : PopRandomBit(rng, rpool.tmp.mask);
        SynthesizeMaskRegMix(rng, permuted, index, dst, rpool, block);

        // Free the intermediate register.
        rpool.tmp.mask[permuted] = true;

        // The output is not the new input.
        src = dst;
      }
      break;
    }
    case RegisterBank::kMMX: {
      // The instructions we use for MMX registers will modify the destination
      // register in place.
      // Move the mix value into the output register.
      SynthesizeMMXRegMov(entropy_mixin.index, entropy_output.index, block);
      bool first = true;
      for (unsigned int index : is_written) {
        SynthesizeMMXRegPermute(rng, entropy_output.index, entropy_mixin.index,
                                first, block);
        first = false;
        SynthesizeMMXRegMix(rng, index, entropy_output.index, block);
      }
      break;
    }
    default:
      LOG(FATAL) << "Unknown output mode: "
                 << static_cast<int>(entropy_output.bank);
  }
}

// Choose a random effective op with that is supported by the instruction
// candidate.
unsigned int RandomEffectiveOpWidth(std::mt19937_64& rng,
                                    const InstructionCandidate& candidate) {
  std::vector<unsigned int> possible_widths;
  if (candidate.width_16) {
    possible_widths.push_back(16);
  }
  if (candidate.width_32) {
    possible_widths.push_back(32);
  }
  if (candidate.width_64) {
    possible_widths.push_back(64);
  }
  if (possible_widths.empty()) {
    // This parameter shouldn't affect the encoding?
    return 32;
  }
  size_t index =
      std::uniform_int_distribution<size_t>(0, possible_widths.size() - 1)(rng);
  return possible_widths[index];
}

// Push the flags register onto the stack and pop it back into the destination
// register.
void SynthesizeFlagSave(unsigned int dst, bool mask_trap_flag,
                        InstructionBlock& block) {
  {
    InstructionBuilder builder(XED_ICLASS_PUSHFQ, 64U);
    Emit(builder, block);
  }
  {
    InstructionBuilder builder(XED_ICLASS_POP, 64U);
    builder.AddOperands(GPRegOperand(dst, 64));
    Emit(builder, block);
  }
  if (mask_trap_flag) {
    // Mask the trap bit.
    // This prevents a test from producing different results when it is being
    // traced, or not.
    // It does cost 7 bytes / 1 instruction, however.
    // TODO(ncbray): the trap bit is still unmasked on the stack. When running
    // inside Silifuzz, the unmasked flag value on the stack will be overwritten
    // by the exit sequence. In the standalone hashtest runner, the contents of
    // the stack are not checked. If we ever start using the stack for other
    // purposes, however, the serendipity of the exit sequence erasing the trap
    // bit may be lost. It would be more reliable to mask the stack memory
    // directly rather than masking the value after it was loaded from memory.
    // Adding an instruction that explicitly operates on memory could
    // theoretically affect the microarchitecture in an unexpected way, so
    // making this change would require an emperical reevaluation of hashtest
    // effectiveness. So TODO, for now.
    InstructionBuilder builder(XED_ICLASS_AND, 64U);
    builder.AddOperands(GPRegOperand(dst, 64));
    builder.AddOperands(xed_simm0(~(1 << 8), 32));
    Emit(builder, block);
  }
}

// Synthesize a test instruction, the necessary initialization instructions to
// make it work correctly, and the output collection instruction to fold the
// results back into the entropy pool.
void SynthesizeTestStep(std::mt19937_64& rng,
                        const InstructionCandidate& candidate,
                        const RegisterPool& original_rpool,
                        RegisterID entropy_output, RegisterID entropy_mixin,
                        const SynthesisConfig& config,
                        InstructionBlock& block) {
  RegisterPool rpool = original_rpool;

  // The entropy output should not be in the register pool because it is dead
  // and the value in the register should not be used for any purpose.
  CHECK(!rpool.entropy.Get(entropy_output));

  // Reserve mix register.
  // This is needed for the test to function correctly, for subtle reasons.
  // It guarantees whatever values are produced by the test instruction are not
  // correlated with the mix register. The lack of correlation ensures that
  // mixing the mix register with the result values does not reduce the entropy.
  rpool.entropy.Clear(entropy_mixin);

  // Encode the test instruction.
  // This will tell us what registers were read from and what registers were
  // modified.
  std::vector<RegisterID> reg_needs_init;
  std::vector<unsigned int> reg_is_written;
  uint8_t ibuf[16];
  size_t actual_len = sizeof(ibuf);
  // Note that we are encoding the instruction, but not emitting it, yet.
  CHECK(SynthesizeTestInstruction(
      candidate, rpool, rng, RandomEffectiveOpWidth(rng, candidate),
      reg_needs_init, reg_is_written, ibuf, actual_len));

  // Initialize the input registers.
  // Randomize the order we initialize the registers.
  std::shuffle(reg_needs_init.begin(), reg_needs_init.end(), rng);
  SynthesizeInits(rng, reg_needs_init, rpool, block);

  // Emit the test instruction.
  block.EmitInstruction(ibuf, actual_len);

  // Note that flags need to be saved immediately after the test instruction,
  // otherwise other instructions can modify the flags.
  if (candidate.fixed_reg.written.flags &&
      candidate.OutputMode() == RegisterBank::kGP) {
    // Don't capture the flags all the time.
    // It has a ~16 byte / 5 instruction cost (capture + mixing into entropy).
    if (std::bernoulli_distribution(config.flag_capture_rate)(rng)) {
      unsigned int tmp = PopRandomBit(rng, rpool.tmp.gp);
      SynthesizeFlagSave(tmp, config.mask_trap_flag, block);
      reg_is_written.push_back(tmp);
    }
  }

  // Gather the output registers.
  CHECK(!reg_is_written.empty());
  // Randomize the order we gather the output registers.
  std::shuffle(reg_is_written.begin(), reg_is_written.end(), rng);
  SynthesizeOutputCollection(rng, entropy_output, entropy_mixin, reg_is_written,
                             rpool, block);
}

struct TestRegisters {
  RegisterID dead;
  RegisterID mix;
};

// For each register bank, we want to update each entropy register at least once
// every iteration of the test loop. We also want to "cycle" the entropy through
// the entropy registers to ensure each test instruction sees different input
// values each iteration and is mixing it output values with different entropy
// each iteration. Since each encoded instruction will have fixed inputs and
// outputs, the entropy values need to be rotated through the registers. To this
// end we designate "dead" and "mix" registers. A "dead" register is the
// register that will be filled with entropy by a particular test step. It is
// assumed the dead register does not have valid entropy, and it will not be
// used as an input in the test step. A "mix" register is raw entropy that will
// be mixed with the outputs of the test instruction to produce the new value of
// the dead register. The mix register's entropy is considered to have been
// consumed, and it then becomes the new dead register. The test loop body
// starts with one register designated as dead. A sequence of test steps will
// generate a value for the dead register and create a new dead register. When
// the test reaches the end of the loop body, each entropy register will have
// been updated and the dead register will be the same as when the loop started.
// Each register bank will have its own cycle of dead and mix registers. We
// randomly interleave these cycles to create the overall test. Some
// instructions can read from one bank and write to another, hence the need to
// interleave the cycles and update all the banks each iteration of the test
// loop.
template <size_t N>
std::vector<TestRegisters> GenerateRegisterSchedule(
    std::mt19937_64& rng, RegisterBank bank, const std::bitset<N>& entropy) {
  std::vector<TestRegisters> schedule;
  if (entropy.any()) {
    std::bitset<N> entropy_copy = entropy;
    RegisterID dead =
        RegisterID{.bank = bank, .index = PopRandomBit(rng, entropy_copy)};
    RegisterID first_dead = dead;

    while (entropy_copy.any()) {
      RegisterID mix =
          RegisterID{.bank = bank, .index = PopRandomBit(rng, entropy_copy)};
      schedule.push_back(TestRegisters{.dead = dead, .mix = mix});
      dead = mix;
    }
    // Close the loop so that each entropy register is updated.
    CHECK_NE(dead.index, first_dead.index);
    schedule.push_back(TestRegisters{.dead = dead, .mix = first_dead});
  }
  return schedule;
}

}  // namespace

void SynthesizeGPRegDec(unsigned int dst, InstructionBlock& block) {
  InstructionBuilder builder(XED_ICLASS_DEC, 64U);
  builder.AddOperands(GPRegOperand(dst, 64));
  Emit(builder, block);
}

// Generate a "TEST" instruction that does a bitwise AND between a register and
// a bitmask and sets flags.
static void SynthesizeTest(unsigned int src, uint8_t mask,
                           InstructionBlock& block) {
  InstructionBuilder builder(XED_ICLASS_TEST, 8U);
  builder.AddOperands(GPRegOperand(src, 8));
  builder.AddOperands(xed_imm0(mask, 8));
  Emit(builder, block);
}

// Generate an unconditional branch instruction.
// `offset` is from the _end_ of the instruction. The intended use is jumping
// past a subsequent block of instructions. This results in an inconsistency for
// how we generate jump instructions - it's simplest if backward jump offsets
// are relative to the beginning of the instruction, and forward jump offsets
// are relative to the end of the instruction. In theory all of the
// Synthesize[jump]() functions could have a flag indicating where the offset
// should be relative to, but there are no use cases for that, yet. Instead we
// name functions that calculate the offset relative to the end of the
// instruction as "SynthesizeForward*".
static void SynthesizeForwardJmp(int32_t offset, InstructionBlock& block) {
  InstructionBuilder builder(XED_ICLASS_JMP, 64U);
  // The branch displacement is relative to the end of the instruction so that
  // the caller doesn't need to know the size of the instruction that is
  // generated.
  builder.AddOperands(xed_relbr(offset, 32));
  Emit(builder, block);
}

static void SynthesizeForwardJz(int32_t offset, InstructionBlock& block) {
  InstructionBuilder builder(XED_ICLASS_JZ, 64U);
  // The branch displacement is relative to the end of the instruction so that
  // the caller doesn't need to know the size of the instruction that is
  // generated.
  builder.AddOperands(xed_relbr(offset, 32));
  Emit(builder, block);
}

static void SynthesizeForwardJnz(int32_t offset, InstructionBlock& block) {
  InstructionBuilder builder(XED_ICLASS_JNZ, 64U);
  // The branch displacement is relative to the end of the instruction so that
  // the caller doesn't need to know the size of the instruction that is
  // generated.
  builder.AddOperands(xed_relbr(offset, 32));
  Emit(builder, block);
}

void SynthesizeBackwardJnle(int32_t offset, InstructionBlock& block) {
  // TODO(ncbray): emit instruction immediate when possible?
  InstructionBuilder builder(XED_ICLASS_JNLE, 64U);
  // We know this instruction will be 6 bytes.
  constexpr int32_t kInstructionSize = 6;
  // The branch displacement is relative to the end of the instruction so that
  // the caller doesn't need to know the size of the instruction that is
  // generated.
  builder.AddOperands(xed_relbr(offset - kInstructionSize, 32));
  size_t prev_bytes = block.bytes.size();
  Emit(builder, block);
  CHECK_EQ(block.bytes.size(), prev_bytes + kInstructionSize);
}

void SynthesizeReturn(InstructionBlock& block) {
  InstructionBuilder builder(XED_ICLASS_RET_NEAR, 64U);
  Emit(builder, block);
}

void SynthesizeBreakpointTraps(size_t count, InstructionBlock& block) {
  for (size_t i = 0; i < count; ++i) {
    block.bytes.push_back(0xCC);
    block.num_instructions++;
  }
}

// Forward declaration.
static size_t SynthesizeBlock(std::mt19937_64& rng,
                              absl::Span<const TestRegisters> schedule,
                              size_t duplication_budget,
                              RegisterPool& dead_pool,
                              const SynthesisConfig& config,
                              InstructionBlock& block);

// Randomly select the number of instructions to duplicate, up to the maximum
// budget.
static size_t PartitionDuplicationBudget(std::mt19937_64& rng,
                                         size_t duplication_budget) {
  return std::uniform_int_distribution<size_t>(0, duplication_budget)(rng);
}

static size_t SynthesizeBranch(std::mt19937_64& rng,
                               absl::Span<const TestRegisters> schedule,
                               size_t duplication_budget,
                               RegisterPool& dead_pool,
                               const SynthesisConfig& config,
                               InstructionBlock& block) {
  // Save which register we're testing before we mutate the dead pool.
  unsigned int test_reg = ChooseRandomBit(rng, dead_pool.entropy.gp);

  // Split the remaining duplication target randomly between each side of the
  // branch.
  size_t a_duplication_budget =
      PartitionDuplicationBudget(rng, duplication_budget);
  size_t b_duplication_budget = duplication_budget - a_duplication_budget;

  RegisterPool dead_pool_copy = dead_pool;
  InstructionBlock a_block;
  size_t a_max_instructions = SynthesizeBlock(
      rng, schedule, a_duplication_budget, dead_pool_copy, config, a_block);

  InstructionBlock b_block;
  size_t b_max_instructions = SynthesizeBlock(
      rng, schedule, b_duplication_budget, dead_pool, config, b_block);

  // After the first block is executed, jump past the second block.
  // This means execution will merge to the same place after we execute either
  // of the blocks.
  SynthesizeForwardJmp(b_block.bytes.size(), a_block);
  a_max_instructions += 1;

  // Create branch point.
  // A higher bit count in the mask makes the branch more predictable (less
  // likely all the bits are zero). Predictable branches improve performance,
  // but an extremely predictable branch is effectively a no-op.
  int branch_test_bits = config.branch_test_bits;
  CHECK_LE(branch_test_bits, 8);

  // Sample without replacement guarantees exactly `count` bits are set.
  constexpr uint8_t kByteBits[] = {0, 1, 2, 3, 4, 5, 6, 7};
  uint8_t bits[8];
  std::sample(std::begin(kByteBits), std::end(kByteBits), std::begin(bits),
              branch_test_bits, rng);

  // Construct the mask.
  uint8_t mask = 0;
  for (int i = 0; i < branch_test_bits; ++i) {
    mask |= 1 << bits[i];
  }

  // Generate a test + conditional branch to split the control flow.
  SynthesizeTest(test_reg, mask, block);
  // Conditionally jump past the first block to the second block. Otherwise,
  // fall through to the first block.
  if (RandomBool(rng)) {
    SynthesizeForwardJz(a_block.bytes.size(), block);
  } else {
    SynthesizeForwardJnz(a_block.bytes.size(), block);
  }

  block.Append(a_block);
  block.Append(b_block);
  return std::max(a_max_instructions, b_max_instructions) + 2;
}

// Split the schedule in two at a random offset, and randomly allocate the
// duplication target between each of the parts. Generate each part of the
// schedules independently, and then concatenate the resulting instructions.
// Block splitting is necessary in the cases where the duplication budget is
// lower than the schedule length - adding branch around the entire schedule
// would add too many instructions. Block splitting can also be useful even when
// there is sufficient budget - in encourages shorter and nested branches.
// Note that splitting does not change anything in of itself. It helps define
// different regions of the test schedule that can have different randomized
// branch structures applied to them.
static size_t SynthesizeSplit(std::mt19937_64& rng,
                              absl::Span<const TestRegisters> schedule,
                              size_t duplication_budget,
                              RegisterPool& dead_pool,
                              const SynthesisConfig& config,
                              InstructionBlock& block) {
  CHECK_GT(schedule.size(), 1);

  size_t split_point =
      std::uniform_int_distribution<size_t>(1, schedule.size() - 1)(rng);

  // Split the remaining duplication target randomly between each side of the
  // branch.
  size_t a_duplication_budget =
      PartitionDuplicationBudget(rng, duplication_budget);
  size_t b_duplication_budget = duplication_budget - a_duplication_budget;

  size_t max_instructions =
      SynthesizeBlock(rng, schedule.subspan(0, split_point),
                      a_duplication_budget, dead_pool, config, block);
  max_instructions +=
      SynthesizeBlock(rng, schedule.subspan(split_point), b_duplication_budget,
                      dead_pool, config, block);
  return max_instructions;
}

// Generate straight-line code.
static size_t SynthesizeBasicBlock(std::mt19937_64& rng,
                                   absl::Span<const TestRegisters> schedule,
                                   RegisterPool& dead_pool,
                                   const SynthesisConfig& config,
                                   InstructionBlock& block) {
  size_t existing_instructions = block.num_instructions;
  for (const TestRegisters& step : schedule) {
    // Generate the test instruction + setup + output collection.
    SynthesizeTestStep(rng,
                       ChooseRandomCandidate(rng, config.ipool, step.mix.bank),
                       dead_pool, step.dead, step.mix, config, block);
    // The mix register has been consumed, and is now dead.
    dead_pool.entropy.Set(step.mix, false, true);
    // The old dead register now has entropy.
    dead_pool.entropy.Set(step.dead, true, true);
  }
  return block.num_instructions - existing_instructions;
}

static size_t SynthesizeBlock(std::mt19937_64& rng,
                              absl::Span<const TestRegisters> schedule,
                              size_t duplication_budget,
                              RegisterPool& dead_pool,
                              const SynthesisConfig& config,
                              InstructionBlock& block) {
  CHECK(!schedule.empty());

  constexpr float p_branch = 0.5;

  // If duplication_budget is zero, no more branches can be added. Generate
  // a basic block.
  if (duplication_budget == 0) {
    return SynthesizeBasicBlock(rng, schedule, dead_pool, config, block);
  }

  // Cannot branch if duplication_budget < schedule.size().
  // Cannot split if schedule.size() < 2.
  // Must split if duplication_budget > 0 and not branching.
  if ((duplication_budget >= schedule.size() &&
       std::bernoulli_distribution(p_branch)(rng)) ||
      schedule.size() == 1) {
    duplication_budget -= schedule.size();
    return SynthesizeBranch(rng, schedule, duplication_budget, dead_pool,
                            config, block);
  } else {
    return SynthesizeSplit(rng, schedule, duplication_budget, dead_pool, config,
                           block);
  }
}

size_t SynthesizeLoopBody(std::mt19937_64& rng, const RegisterPool& rpool,
                          const SynthesisConfig& config,
                          InstructionBlock& block) {
  std::vector<TestRegisters> greg_schedule =
      GenerateRegisterSchedule(rng, RegisterBank::kGP, rpool.entropy.gp);
  std::vector<TestRegisters> vreg_schedule =
      GenerateRegisterSchedule(rng, RegisterBank::kVec, rpool.entropy.vec);
  std::vector<TestRegisters> mreg_schedule =
      GenerateRegisterSchedule(rng, RegisterBank::kMask, rpool.entropy.mask);
  std::vector<TestRegisters> mmxreg_schedule =
      GenerateRegisterSchedule(rng, RegisterBank::kMMX, rpool.entropy.mmx);

  // Remove the initial dead registers from the entropy pool.
  // This ensures the dead registers will not be read from.
  RegisterPool dead_pool = rpool;
  if (!greg_schedule.empty()) {
    dead_pool.entropy.Clear(greg_schedule[0].dead);
  }
  if (!vreg_schedule.empty()) {
    dead_pool.entropy.Clear(vreg_schedule[0].dead);
  }
  if (!mreg_schedule.empty()) {
    dead_pool.entropy.Clear(mreg_schedule[0].dead);
  }
  if (!mmxreg_schedule.empty()) {
    dead_pool.entropy.Clear(mmxreg_schedule[0].dead);
  }

  // We want to interleave the schedules for each register bank into a global
  // schedule. We cannot reorder the schedule for any of the banks, since that
  // would break the dead/mix structure. To do a pure interleaving, we first
  // create a list of the register banks, weighted by the length of the bank's
  // schedule. Then we shuffle that list to randomize the order we pull from
  // each bank.
  std::vector<RegisterBank> output_modes;
  output_modes.reserve(greg_schedule.size() + vreg_schedule.size() +
                       mreg_schedule.size() + mmxreg_schedule.size());
  for (size_t i = 0; i < greg_schedule.size(); ++i) {
    output_modes.push_back(RegisterBank::kGP);
  }
  for (size_t i = 0; i < vreg_schedule.size(); ++i) {
    output_modes.push_back(RegisterBank::kVec);
  }
  for (size_t i = 0; i < mreg_schedule.size(); ++i) {
    output_modes.push_back(RegisterBank::kMask);
  }
  for (size_t i = 0; i < mmxreg_schedule.size(); ++i) {
    output_modes.push_back(RegisterBank::kMMX);
  }
  std::shuffle(output_modes.begin(), output_modes.end(), rng);

  // Interleave the schedules.
  std::vector<TestRegisters> schedule;
  schedule.reserve(output_modes.size());
  size_t current_greg = 0;
  size_t current_vreg = 0;
  size_t current_mreg = 0;
  size_t current_mmxreg = 0;
  for (RegisterBank mode : output_modes) {
    switch (mode) {
      case RegisterBank::kGP: {
        schedule.push_back(greg_schedule[current_greg]);
        current_greg++;
        break;
      }
      case RegisterBank::kVec: {
        schedule.push_back(vreg_schedule[current_vreg]);
        current_vreg++;
        break;
      }
      case RegisterBank::kMask: {
        schedule.push_back(mreg_schedule[current_mreg]);
        current_mreg++;
        break;
      }
      case RegisterBank::kMMX: {
        schedule.push_back(mmxreg_schedule[current_mmxreg]);
        current_mmxreg++;
        break;
      }
      default:
        LOG(FATAL) << "Unknown output mode: " << static_cast<int>(mode);
    }
  }

  // Choose the number of tests in the test schedule that can be duplicated by
  // adding branches.
  size_t min_duplication =
      static_cast<size_t>(schedule.size() * config.min_duplication_rate);
  size_t max_duplication =
      static_cast<size_t>(schedule.size() * config.max_duplication_rate);
  size_t duplication_budget =
      std::uniform_int_distribution<int>(min_duplication, max_duplication)(rng);

  // Generate the instructions in the loop body.
  return SynthesizeBlock(rng, schedule, duplication_budget, dead_pool, config,
                         block);
}

}  // namespace silifuzz
