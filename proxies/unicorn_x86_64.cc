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

#include <cstddef>
#include <cstdint>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./common/proxy_config.h"
#include "./instruction/default_disassembler.h"
#include "./proxies/arch_feature_generator.h"
#include "./proxies/user_features.h"
#include "./tracing/tracer.h"
#include "./tracing/unicorn_tracer.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

namespace {

// This array lives in an ELF segment that the Centipede runner will read from.
USER_FEATURE_ARRAY static user_feature_t features[100000];

constexpr int kMaxX86InsnLength = 15;

// This proxy will be run on a batch of inputs to amortize the cost of creating
// the process. The number of inputs in a batch is controlled by the caller. We
// want to execute some operations on a per-batch basis rather than a per-input
// basis for two reasons.
// First, performance. Speed matters for fuzzing.
// Second, coverage. Anything we do per-input will generate branch coverage,
// path coverage, etc. In theory it should be the same for every input and
// therefore will be ignored, but it consumes memory, adds noise in the coverage
// report, etc.
// In general, we should try to do work per-batch rather than per-input when it
// is possible.
class BatchState {
 public:
  BatchState() { feature_gen.BeforeBatch(disasm.NumInstructionIDs()); }

  DefaultDisassembler<X86_64> disasm;
  ArchFeatureGenerator<X86_64> feature_gen;
};

BatchState *batch;

void BeforeBatch() {
  CHECK_EQ(batch, nullptr);
  batch = new BatchState();
}

absl::Status RunInstructions(absl::string_view instructions,
                             const FuzzingConfig<X86_64> &fuzzing_config,
                             size_t max_inst_executed) {
  DefaultDisassembler<X86_64> &disasm = batch->disasm;
  ArchFeatureGenerator<X86_64> &feature_gen = batch->feature_gen;

  TracerConfig<X86_64> tracer_config{};
  UnicornTracer<X86_64> tracer;
  RETURN_IF_NOT_OK(
      tracer.InitSnippet(instructions, tracer_config, fuzzing_config));

  feature_gen.BeforeInput(features);

  // Unicorn generates callbacks before the instruction executes and not after.
  // We need to do a little extra work to synthesize a callback after every
  // instruction.
  uint32_t instruction_id = kInvalidInstructionId;
  bool instruction_pending = false;

  UContext<X86_64> registers;
  auto after_instruction = [&](TracerControl<X86_64> &control) {
    if (instruction_pending) {
      control.GetRegisters(registers);
      feature_gen.AfterInstruction(instruction_id, registers);
      instruction_pending = false;
    }
  };

  bool instructions_are_in_range = true;

  tracer.SetBeforeExecutionCallback([&](TracerControl<X86_64> &control) {
    control.GetRegisters(registers);
    feature_gen.BeforeExecution(registers);
  });

  tracer.SetBeforeInstructionCallback([&](TracerControl<X86_64> &control) {
    after_instruction(control);

    // Read the next instruction.
    // 16 bytes should hold any x86-64 instruction. The actual limit should
    // be 15 bytes, but keep things as nice powers of two.
    uint8_t insn[16];
    uint64_t address = control.GetInstructionPointer();
    // Sometimes Unicorn will invoke this function with an invalid max_size
    // when it has absolutely no idea what the instruction does. (AVX512 for
    // example.) It appears to be some sort of error code gone wrong?
    control.ReadMemory(address, insn, kMaxX86InsnLength);

    // Decompile the next instruction.
    if (disasm.Disassemble(address, insn, kMaxX86InsnLength)) {
      instruction_id = disasm.InstructionID();
      CHECK_LT(instruction_id, disasm.NumInstructionIDs());
      // If an instruction doesn't entirely lie within the code snippet,
      // we're likely executing an incomplete instruction that includes
      // bytes immediately after the snippet. We try to filter out this
      // case because it can make the snippet hard to disassemble.
      instructions_are_in_range &=
          control.InstructionIsInRange(address, disasm.InstructionSize());
    } else {
      instruction_id = kInvalidInstructionId;
    }

    instruction_pending = true;
  });

  tracer.SetAfterExecutionCallback([&](TracerControl<X86_64> &control) {
    // Flush the last instruction.
    after_instruction(control);

    feature_gen.AfterExecution();

    // Emit features for memory bits that are different from the initial state.
    // The initial state is zero, so we can skip the diff.
    // (The initial stack state is not entirely zero, but close enough.)
    constexpr size_t kMemBytesPerChunk = 8192;
    uint8_t mem[kMemBytesPerChunk];

    // Data 1
    control.ReadMemory(fuzzing_config.data1_range.start_address, mem,
                       kMemBytesPerChunk);
    feature_gen.FinalMemory(mem);

    // Data 2
    control.ReadMemory(fuzzing_config.data2_range.start_address, mem,
                       kMemBytesPerChunk);
    feature_gen.FinalMemory(mem);
  });

  // Stop at an arbitrary instruction count to avoid infinite loops.
  absl::Status status = tracer.Run(max_inst_executed);
  if (!instructions_are_in_range) {
    return absl::OutOfRangeError(
        "Instructions are not entirely contained in code.");
  }
  return status;
}

}  // namespace

}  // namespace silifuzz

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  silifuzz::BeforeBatch();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const size_t max_inst_executed = 1000;
  absl::Status status = silifuzz::RunInstructions(
      absl::string_view(reinterpret_cast<const char *>(data), size),
      silifuzz::DEFAULT_FUZZING_CONFIG<silifuzz::X86_64>, max_inst_executed);
  if (!status.ok()) {
    LOG_ERROR(status.message());
    return -1;
  }
  return 0;
}
