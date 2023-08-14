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
#include "./proxies/arch_feature_generator.h"
#include "./tracing/capstone_disassembler.h"
#include "./tracing/unicorn_tracer.h"
#include "./util/arch.h"
#include "./util/checks.h"

namespace silifuzz {

namespace {

// This array lives in an ELF segment that the Centipede runner will read from.
// In practice, over 25k user features have been observed.
USER_FEATURE_ARRAY static user_feature_t features[100000];

class BatchState {
 public:
  BatchState() { feature_gen.BeforeBatch(disasm.NumInstructionIDs()); }

  CapstoneDisassembler<AArch64> disasm;
  ArchFeatureGenerator<AArch64> feature_gen;
};

BatchState *batch;

void BeforeBatch() {
  CHECK_EQ(batch, nullptr);
  batch = new BatchState();
}

absl::Status RunAArch64Instructions(
    absl::string_view instructions,
    const FuzzingConfig<AArch64> &fuzzing_config, size_t max_inst_executed) {
  // Require at least one instruction.
  if (instructions.size() < 4) {
    return absl::InvalidArgumentError("Input too short");
  }

  // Details to sort out later:
  // TODO(ncbray) why do atomic ops using the initial stack pointer not fault?
  // 1000000: 787f63fc ldumaxlh    wzr, w28, [sp]

  CapstoneDisassembler<AArch64> &disasm = batch->disasm;
  ArchFeatureGenerator<AArch64> &feature_gen = batch->feature_gen;

  UnicornTracer<AArch64> tracer;
  RETURN_IF_NOT_OK(tracer.InitSnippet(instructions, fuzzing_config));

  feature_gen.BeforeInput(features);

  UContext<AArch64> registers;
  tracer.GetRegisters(registers);
  feature_gen.BeforeExecution(registers);

  // QEMU generates callbacks before the instruction executes and not after.
  // We need to do a little extra work to synthesize a callback after every
  // instruction.
  uint32_t instruction_id = kInvalidInstructionId;
  bool instruction_pending = false;

  auto after_instruction = [&]() {
    if (instruction_pending) {
      tracer.GetRegisters(registers);
      feature_gen.AfterInstruction(instruction_id, registers);
      instruction_pending = false;
    }
  };

  tracer.SetInstructionCallback(
      [&](UnicornTracer<AArch64> *tracer, uint64_t address, size_t max_size) {
        after_instruction();

        // Read the next instruction.
        uint8_t insn[4];
        CHECK_LE(max_size, sizeof(insn));
        tracer->ReadMemory(address, insn, max_size);

        // Decompile the next instruction.
        if (disasm.Disassemble(address, insn, max_size)) {
          instruction_id = disasm.InstructionID();
          CHECK_LT(instruction_id, disasm.NumInstructionIDs());
        } else {
          instruction_id = kInvalidInstructionId;
        }

        instruction_pending = true;
      });

  // Stop at an arbitrary instruction count to avoid infinite loops.
  absl::Status status = tracer.Run(max_inst_executed);

  // Flush the last instruction.
  after_instruction();

  feature_gen.AfterExecution();

  // Emit features for memory bits that are different from the initial state.
  // The initial state is zero, so we can skip the diff.
  // (The inital stack state is not entirely zero, but close enough.)
  constexpr size_t kMemBytesPerChunk = 4096;
  uint8_t mem[kMemBytesPerChunk];

  // Stack
  tracer.ReadMemory(fuzzing_config.stack_range.start_address, mem,
                    kMemBytesPerChunk);
  feature_gen.FinalMemory(mem);

  // Data 1
  tracer.ReadMemory(fuzzing_config.data1_range.start_address, mem,
                    kMemBytesPerChunk);
  feature_gen.FinalMemory(mem);

  // Data 2
  tracer.ReadMemory(fuzzing_config.data2_range.start_address, mem,
                    kMemBytesPerChunk);
  feature_gen.FinalMemory(mem);

  return status;
}

}  // namespace

}  // namespace silifuzz

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  silifuzz::BeforeBatch();
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  const size_t max_inst_executed = 0x1000;
  absl::Status status = silifuzz::RunAArch64Instructions(
      absl::string_view(reinterpret_cast<const char *>(data), size),
      silifuzz::DEFAULT_FUZZING_CONFIG<silifuzz::AArch64>, max_inst_executed);
  if (!status.ok()) {
    LOG_ERROR(status.message());
    return -1;
  }
  return 0;
}
