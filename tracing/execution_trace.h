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

#ifndef THIRD_PARTY_SILIFUZZ_TRACING_EXECUTION_TRACE_H_
#define THIRD_PARTY_SILIFUZZ_TRACING_EXECUTION_TRACE_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "absl/status/status.h"
#include "./instruction/disassembler.h"
#include "./tracing/tracer.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

template <typename Arch>
inline uint64_t MaxInstructionLength();

template <>
inline uint64_t MaxInstructionLength<X86_64>() {
  return 15;
}

template <>
inline uint64_t MaxInstructionLength<AArch64>() {
  return 4;
}

// Information for a single instruction in an execution trace.
template <typename Arch>
struct InstructionInfo {
  // Address of the instruction.
  uint64_t address;

  // The ID of the instruction, according to the disassembler.
  uint32_t instruction_id;

  // The size of the instruction in bytes.
  uint8_t size;

  // Is this the type of instruction that can branch?
  // This is type information and it does not indicate if the instruction
  // actually branches.
  bool can_branch;

  // Can this type of instruction read from memory?
  bool can_load;

  // Can this type of instruction write to memory?
  bool can_store;

  // Did this instruction play a role in producing the final end state?
  // The exact definition of this field depends on the kind of fault injection
  // performed, but at the time of writing this means that the instruction
  // cannot be skipped without changing the end state of the trace.
  // This field likely belongs in its own data structure because it is concerned
  // with fault injection rather than tracing - but putting it here simplifies
  // the APIs.
  bool critical;

  // The raw bytes of the instruction, in case we need to disassemble it again.
  // The longest valid instruction on x86 is 15 bytes, so 16 bytes should hold
  // all possible instructions on all arches.
  uint8_t bytes[16];

  // The architectural state after the instruction has executed.
  UContext<Arch> ucontext;
};

// A trace of all instructions in a test.
// Assumes that the trace exits normally and does not fault.
// This is intended to be a reusable, fixed-sized buffer for instruction
// information. It is expected this will almost always be generated with
// CaptureTrace. Afterwards it is expected that most clients will access its
// contents with the ForEach method.
template <typename Arch>
class ExecutionTrace {
 public:
  ExecutionTrace(size_t max_instructions)
      : info_(max_instructions), num_instructions_(0) {}

  void Reset() { num_instructions_ = 0; }

  // The address the trace starts at.
  uint64_t EntryAddress() const {
    // first_ is initialized indirectly.
    // The first time LastContext() is called (when there are no instructions,
    // yet), it will return a reference to first_. The initial state will be
    // written to first_, and the instruction pointer of the initial state will
    // be the entry point of the test.
    return first_.gregs.GetInstructionPointer();
  }

  // The architectural state immediately before the trace begins.
  UContext<Arch>& FirstContext() { return first_; }

  // The architectural state immediately after the end of the trace.
  UContext<Arch>& LastContext() { return PrevContext(num_instructions_); }

  InstructionInfo<Arch>& Info(size_t i) {
    CHECK_LT(i, num_instructions_);
    return info_[i];
  }

  // Allocate a struct to store data about the next instruction.
  InstructionInfo<Arch>& NextInfo() {
    CHECK(num_instructions_ < info_.size());
    InstructionInfo<Arch>& tmp = info_[num_instructions_];
    num_instructions_++;
    memset(&tmp, 0, sizeof(tmp));
    return tmp;
  }

  // The number of instructions currently in the trace.
  size_t NumInstructions() const { return num_instructions_; }

  // The maximum number of instruction that can be stored in this trace.
  size_t MaxInstructions() const { return info_.size(); }

  // For each instruction invoke the callback with the following arguments:
  // The index of the instruction in the trace.
  // The register context before the instruction was executed.
  // Information about the instruction and its execution.
  template <typename F>
  void ForEach(F&& f) {
    for (size_t i = 0; i < num_instructions_; ++i) {
      f(i, PrevContext(i), info_[i]);
    }
  }

 private:
  std::vector<InstructionInfo<Arch>> info_;
  size_t num_instructions_;
  UContext<Arch> first_;

  UContext<Arch>& PrevContext(size_t i) {
    CHECK_LE(i, num_instructions_);
    if (i == 0) {
      return first_;
    } else {
      return info_[i - 1].ucontext;
    }
  }
};

// Run the tracer and record each instruction.
// `execution_trace` is an output parameter rather than a return value so that
// it can be reused multiple times without being reallocated. When
// `memory_checksum` output parameter is provided with a non-null pointer, it
// will calculate the memory checksum of the final state, and store it there.
template <typename Disassembler, typename Arch>
absl::Status CaptureTrace(Tracer<Arch>& tracer, Disassembler& disasm,
                          ExecutionTrace<Arch>& execution_trace,
                          uint32_t* memory_checksum = nullptr) {
  // In theory the entry point should also be the page start, but be cautious
  // and force page alignment in case we add a preamble later.
  bool insn_out_of_bounds = false;
  execution_trace.Reset();
  tracer.SetBeforeInstructionCallback([&](TracerControl<Arch>& control) {
    // The instruction hasn't executed yet, capture the previous state.
    control.GetRegisters(execution_trace.LastContext());

    InstructionInfo<Arch>& info = execution_trace.NextInfo();
    DisassembleCurrentInstruction(control, disasm, info.bytes);
    const uint64_t address = control.GetInstructionPointer();
    if (!control.InstructionIsInRange(address, disasm.InstructionSize())) {
      control.Stop();
      insn_out_of_bounds = true;
    }

    info.address = address;
    info.instruction_id = disasm.InstructionID();
    info.size = disasm.InstructionSize();
    info.can_branch = disasm.CanBranch();
    info.can_load = disasm.CanLoad();
    info.can_store = disasm.CanStore();
  });
  // Capture the final state.
  tracer.SetAfterExecutionCallback([&](TracerControl<Arch>& control) -> void {
    control.GetRegisters(execution_trace.LastContext());
    if (memory_checksum != nullptr) {
      *memory_checksum = control.PartialChecksumOfMutableMemory();
    }
  });
  absl::Status result = tracer.Run(execution_trace.MaxInstructions());
  if (result.ok() && insn_out_of_bounds) {
    // It is unlikely this will happen, but it may if a native tracer jumps to
    // an executable page in the runner.
    result = absl::OutOfRangeError("instruction fetch was out of bounds");
  }
  return result;
}

template <typename Arch>
void DisassembleCurrentInstruction(TracerControl<Arch>& tracer,
                                   Disassembler& disasm, uint8_t* buf) {
  const uint64_t addr = tracer.GetInstructionPointer();
  const uint64_t max_size = MaxInstructionLength<Arch>();
  tracer.ReadMemory(addr, buf, max_size);
  disasm.Disassemble(addr, buf, max_size);
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_EXECUTION_TRACE_H_
