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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_ARCH_FEATURE_GENERATOR_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_ARCH_FEATURE_GENERATOR_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <type_traits>

#include "./proxies/user_features.h"
#include "./tracing/extension_registers.h"
#include "./util/arch.h"
#include "./util/bitops.h"
#include "./util/checks.h"

namespace silifuzz {

// Used to assign IDs to each feature domain.
struct ArchFeatureDomains {
  uint32_t op = 0;
  uint32_t op_pair = 1;
  uint32_t reg_toggle_zero_one = 2;
  uint32_t reg_toggle_one_zero = 3;
  uint32_t reg_difference = 4;
  uint32_t op_reg_toggle_zero_one = 5;
  uint32_t op_reg_toggle_one_zero = 6;
  uint32_t mem_difference = 7;
};

constexpr ArchFeatureDomains kDefaultArchFeatureDomains;

// Emit a feature if bitmap == 1 for each bit.
template <typename T>
inline std::enable_if_t<!std::is_pointer<T>::value, uint64_t>
EmitSetBitFeatures(uint64_t domain, uint64_t base, const T &bitmap,
                   UserFeatures &user_features) {
  ForEachSetBit(bitmap, [&](size_t index) {
    user_features.EmitFeature(domain, base + index);
  });
  return base + NumBits<T>();
}

// Preprocess the ExtUContext so that it can be treated as a bitset that
// contains the active register state. This includes clearing out aliased
// registers, register groups information, and inactive regions (should be all
// zero already because all ExtUContext are zero-initialized).
template <typename Arch>
inline void PrepareToEmit(ExtUContext<Arch> &uctx);

template <>
inline void PrepareToEmit(ExtUContext<X86_64> &uctx) {
  // XMM registers are aliased to YMM and ZMM registers.
  if (uctx.HasERegs()) {
    memset(uctx.fpregs.xmm, 0, sizeof(uctx.fpregs.xmm));
  }
  // Aliased AVX registers (YMM and ZMM) can be double saved if
  // AVX512 is enabled. Clear out YMM in the case.
  // TODO(herooutman): Avoid double saving YMM and ZMM.
  if (uctx.eregs.register_groups.GetAVX512()) {
    memset(uctx.eregs.ymm, 0, sizeof(uctx.eregs.ymm));
  }
  uctx.eregs.register_groups = {};
}

template <>
inline void PrepareToEmit(ExtUContext<AArch64> &uctx) {
  if (uctx.HasERegs()) {
    memset(uctx.fpregs.v, 0, sizeof(uctx.fpregs.v));
  }
  uctx.eregs.register_groups = {};
}

// Emit a feature if a^b == 1 for each bit.
template <typename T>
inline std::enable_if_t<!std::is_pointer<T>::value, uint64_t>
EmitDiffBitFeatures(uint64_t domain, uint64_t base, const T &a, const T &b,
                    UserFeatures &user_features) {
  ForEachDiffBit(a, b, [&](size_t index, bool value) {
    user_features.EmitFeature(domain, base + index);
  });
  return base + NumBits<T>();
}

// Emit a feature if a^b == 1 for each bit, but emit to zero_one_domain if
// b == 1 and one_zero_domain if b == 0.
template <typename T>
inline std::enable_if_t<!std::is_pointer<T>::value, uint64_t>
EmitToggleBitFeatures(uint64_t zero_one_domain, uint64_t one_zero_domain,
                      uint64_t base, const T &a, const T &b,
                      UserFeatures &user_features) {
  ForEachDiffBit(a, b, [&](size_t index, bool value) {
    user_features.EmitFeature(value ? zero_one_domain : one_zero_domain,
                              base + index);
  });
  return base + NumBits<T>();
}

// Use this instruction ID to indicate than the disassembler failed to make
// sense of the instruction. This isn't considered a hard failure since
// disassemblers may be buggy, but any coverage related to the instruction ID
// will be lost for this particular instruction.
inline constexpr uint32_t kInvalidInstructionId =
    std::numeric_limits<uint32_t>::max();

// A class that takes information derived from tracing an instruction snippet
// and turns it into user features to guide Centipede's search for interesting
// tests.
template <typename Arch>
class ArchFeatureGenerator {
 private:
  // An internal bookkeeping structure for tracking formation associated with
  // different instruction IDs.
  struct OpInfo {
    // How many times was this type of instruction executed?
    size_t count;
    // Which register bits has this instruction toggled from zero to one?
    ExtUContext<Arch> zero_one;
    // Which register bits has this instruction toggled from one to zero?
    ExtUContext<Arch> one_zero;
  };

 public:
  ArchFeatureGenerator(ArchFeatureDomains domains)
      : num_instruction_ids_(0), op_info_(nullptr), domains_(domains) {}

  ArchFeatureGenerator() : ArchFeatureGenerator(kDefaultArchFeatureDomains) {}

  ~ArchFeatureGenerator() { delete[] op_info_; }

  // Disallow copy and move.
  ArchFeatureGenerator(const ArchFeatureGenerator &) = delete;
  ArchFeatureGenerator(ArchFeatureGenerator &&) = delete;
  ArchFeatureGenerator &operator=(const ArchFeatureGenerator &) = delete;
  ArchFeatureGenerator &operator=(ArchFeatureGenerator &&) = delete;

  // Called before processing any inputs. Potentially does setup work that we
  // do not want to do per input for efficiency reasons and / or do not want to
  // influence coverage.
  // `num_instruction_ids` indicates the dissaembler will generate instruction
  // IDs in the range [0, num_instruction_ids). What an instruction ID indicates
  // is somewhat arbitrary and depends on the disassembler - at minimum it
  // should differentiate between different instructions, but it may
  // differentiate between different instruction encodings.
  void BeforeBatch(uint32_t num_instruction_ids) {
    CHECK_EQ(op_info_, nullptr);
    num_instruction_ids_ = num_instruction_ids;
    op_info_ = new OpInfo[num_instruction_ids_];
  }

  // Called before processing each input.
  // `features` is the user feature array that will be read by Centipede's
  // runner.
  template <size_t N>
  void BeforeInput(user_feature_t (&features)[N]) {
    user_features_.Reset(features);
    current_memory_feature_ = 0;
  }

  // Called after the tracer has been set up, but before executing.
  // Records the initial state before execution. Inactive regions of
  // `current_registers` need to be zeroed out before calling this function.
  void BeforeExecution(ExtUContext<Arch> &current_registers) {
    prev_instruction_id_ = kInvalidInstructionId;
    initial_registers_ = current_registers;
    prev_registers_ = current_registers;
    ClearBits(zero_one_);
    ClearBits(one_zero_);
    memset(op_info_, 0, sizeof(OpInfo) * num_instruction_ids_);
  }

  // Called after each instruction has been executed.
  // `current_registers` is the register state after the instruction has
  // executed. Inactive regions of `current_registers` need to be zeroed out
  // before calling this function. May emit user features.
  void AfterInstruction(uint32_t instruction_id,
                        ExtUContext<Arch> &current_registers) {
    if (instruction_id != kInvalidInstructionId) {
      CHECK_LT(instruction_id, num_instruction_ids_);
      op_info_[instruction_id].count++;

      // Defer (instruction X toggle) features because they can be fairly high
      // volume unless deduped.
      AccumulateToggle(prev_registers_, current_registers,
                       op_info_[instruction_id].zero_one,
                       op_info_[instruction_id].one_zero);

      if (prev_instruction_id_ != kInvalidInstructionId) {
        // Emit (instruction X instruction) feature eagerly because it's sparse
        // and low volume.
        user_features_.EmitFeature(
            domains_.op_pair,
            prev_instruction_id_ * num_instruction_ids_ + instruction_id);
      }
    }

    // Defer emitting the simple toggle coverage.
    // The can ~halve the number of features we emit by eliminating redundancy.
    AccumulateToggle(prev_registers_, current_registers, zero_one_, one_zero_);

    // Prepare for the next instruction.
    prev_instruction_id_ = instruction_id;
    prev_registers_ = current_registers;
  }

  // Called after the instruction snippet has stopped executing.
  // Will emit user features based on information that we accumulated during
  // execution.
  void AfterExecution() {
    PrepareToEmit(zero_one_);
    PrepareToEmit(one_zero_);
    // Did the register bit toggle at any point during the execution?
    EmitSetBitFeatures(domains_.reg_toggle_zero_one, 0, zero_one_,
                       user_features_);
    EmitSetBitFeatures(domains_.reg_toggle_one_zero, 0, one_zero_,
                       user_features_);

    PrepareToEmit(initial_registers_);
    PrepareToEmit(prev_registers_);
    // Is the final register bit different from the initial register bit?
    EmitDiffBitFeatures(domains_.reg_difference, 0, initial_registers_,
                        prev_registers_, user_features_);

    // Emit per-op features.
    for (size_t instruction_id = 0; instruction_id < num_instruction_ids_;
         ++instruction_id) {
      if (op_info_[instruction_id].count > 0) {
        user_features_.EmitFeature(domains_.op, instruction_id);
        PrepareToEmit(op_info_[instruction_id].zero_one);
        PrepareToEmit(op_info_[instruction_id].one_zero);
        EmitSetBitFeatures(
            domains_.op_reg_toggle_zero_one,
            instruction_id * NumBits(op_info_[instruction_id].zero_one),
            op_info_[instruction_id].zero_one, user_features_);
        EmitSetBitFeatures(
            domains_.op_reg_toggle_one_zero,
            instruction_id * NumBits(op_info_[instruction_id].one_zero),
            op_info_[instruction_id].one_zero, user_features_);
      }
    }
  }

  // Emit features for bits set in the final memory state.
  // After each execution, the client should always call this function for the
  // same memory pages in the same order.
  // Note: the type of this function parameter must be declared carefully to
  // avoid type decay. Fixed-sized array parameters can silently decay to
  // pointers and cause problems for the templated bit iterators.
  // TODO(ncbray): make this a hashed domain with a specified address.
  template <size_t N>
  void FinalMemory(uint8_t (&page)[N]) {
    current_memory_feature_ = EmitSetBitFeatures(
        domains_.mem_difference, current_memory_feature_, page, user_features_);
  }

  void EmitFeature(uint32_t domain, uint32_t feature) {
    user_features_.EmitFeature(domain, feature);
  }

 private:
  // IDs assigned to each feature domain.
  ArchFeatureDomains domains_;

  // Raw user features.
  UserFeatures user_features_;

  // Per-instruction-ID information.
  uint32_t num_instruction_ids_;
  OpInfo *op_info_;

  // Initial register state.
  ExtUContext<Arch> initial_registers_;

  // The last register state we were given.
  ExtUContext<Arch> prev_registers_;

  // Register bit toggles.
  ExtUContext<Arch> zero_one_;
  ExtUContext<Arch> one_zero_;

  // Information about the previous instruction.
  uint32_t prev_instruction_id_;

  // Remember how many memory features have been emitted, so far.
  uint64_t current_memory_feature_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_ARCH_FEATURE_GENERATOR_H_
