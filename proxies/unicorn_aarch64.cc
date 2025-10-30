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

#include <sys/types.h>

#include <cstddef>
#include <cstdint>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./common/proxy_config.h"
#include "./instruction/default_disassembler.h"
#include "./proxies/arch_feature_generator.h"
#include "./proxies/user_features.h"
#include "./tracing/extension_registers.h"
#include "./tracing/tracer.h"
#include "./tracing/unicorn_tracer.h"
#include "./util/arch.h"
#include "./util/checks.h"

namespace silifuzz {

namespace {

// This array lives in an ELF segment that the Centipede runner will read from.
// In practice, over 25k user features have been observed.
USER_FEATURE_ARRAY static user_feature_t features[100000];

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

  DefaultDisassembler<AArch64> disasm;
  ArchFeatureGenerator<AArch64> feature_gen;
};

BatchState* batch;

void BeforeBatch() {
  CHECK_EQ(batch, nullptr);
  batch = new BatchState();
}

absl::Status RunAArch64Instructions(
    absl::string_view instructions,
    const FuzzingConfig<AArch64>& fuzzing_config, size_t max_inst_executed) {
  // Require at least one instruction.
  if (instructions.size() < 4) {
    return absl::InvalidArgumentError("Input too short");
  }

  // Details to sort out later:
  // TODO(ncbray) why do atomic ops using the initial stack pointer not fault?
  // 1000000: 787f63fc ldumaxlh    wzr, w28, [sp]

  DefaultDisassembler<AArch64>& disasm = batch->disasm;
  ArchFeatureGenerator<AArch64>& feature_gen = batch->feature_gen;

  TracerConfig<AArch64> tracer_config{.unicorn_force_a72 = true};
  UnicornTracer<AArch64> tracer;
  RETURN_IF_NOT_OK(
      tracer.InitSnippet(instructions, tracer_config, fuzzing_config));

  feature_gen.BeforeInput(features);

  // Unicorn generates callbacks before the instruction executes and not after.
  // We need to do a little extra work to synthesize a callback after every
  // instruction.
  uint32_t instruction_id = kInvalidInstructionId;
  bool instruction_pending = false;

  // Zero initialize the registers. Since the GetRegisters() call below
  // doesn't write to `eregs`, this is necessary to ensure that the `eregs` is
  // initialized and does not contain garbage when counting bit-diff and
  // bit-toggle features.
  ExtUContext<AArch64> registers{};
  auto after_instruction = [&](TracerControl<AArch64>& control) {
    if (instruction_pending) {
      control.GetRegisters(registers);
      feature_gen.AfterInstruction(instruction_id, registers);
      instruction_pending = false;
    }
  };

  tracer.SetBeforeExecutionCallback([&](TracerControl<AArch64>& control) {
    control.GetRegisters(registers);
    feature_gen.BeforeExecution(registers);
  });

  tracer.SetBeforeInstructionCallback([&](TracerControl<AArch64>& control) {
    after_instruction(control);

    // Read the next instruction.
    uint8_t insn[4];
    uint64_t address = control.GetInstructionPointer();
    control.ReadMemory(address, insn, sizeof(insn));

    // Decompile the next instruction.
    if (disasm.Disassemble(address, insn, sizeof(insn))) {
      instruction_id = disasm.InstructionID();
      CHECK_LT(instruction_id, disasm.NumInstructionIDs());
    } else {
      instruction_id = kInvalidInstructionId;
    }

    instruction_pending = true;
  });

  tracer.SetAfterExecutionCallback([&](TracerControl<AArch64>& control) {
    // Flush the last instruction.
    after_instruction(control);

    feature_gen.AfterExecution();

    // Emit features for memory bits that are different from the initial state.
    // The initial state is zero, so we can skip the diff.
    // (The initial stack state is not entirely zero, but close enough.)
    constexpr size_t kMemBytesPerChunk = 4096;
    uint8_t mem[kMemBytesPerChunk];

    // Stack
    control.ReadMemory(fuzzing_config.stack_range.start_address, mem,
                       kMemBytesPerChunk);
    feature_gen.FinalMemory(mem);

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
  return tracer.Run(max_inst_executed);
}

}  // namespace

}  // namespace silifuzz

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
  silifuzz::BeforeBatch();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const size_t max_inst_executed = 0x1000;
  absl::Status status = silifuzz::RunAArch64Instructions(
      absl::string_view(reinterpret_cast<const char*>(data), size),
      silifuzz::DEFAULT_FUZZING_CONFIG<silifuzz::AArch64>, max_inst_executed);
  if (!status.ok()) {
    LOG_ERROR(status.message());
    return -1;
  }
  return 0;
}
