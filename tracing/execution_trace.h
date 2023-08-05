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
#include "./util/checks.h"
#include "./util/page_util.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {

// Information for a single instruction in an execution trace.
template <typename Arch>
struct InstructionInfo {
  // Address of the instruction.
  uint64_t address;

  // The ID of the instruction, according to the disassembler.
  uint32_t instruction_id;

  // The size of the instruction in bytes.
  uint8_t size;

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
// it can be reused multiple times without being reallocated.
template <typename Tracer, typename Disassembler, typename Arch>
absl::Status CaptureTrace(Tracer& tracer, Disassembler& disas,
                          ExecutionTrace<Arch>& execution_trace) {
  // In theory the entry point should also be the page start, but be cautious
  // and force page alignment in case we add a preamble later.
  const uint64_t code_page_start =
      RoundDownToPageAlignment(tracer.GetCurrentInstructionPointer());
  bool insn_out_of_bounds = false;
  execution_trace.Reset();
  tracer.SetInstructionCallback([&](Tracer* tracer, uint64_t address,
                                    size_t max_size) {
    // The instruction hasn't executed yet, capture the previous state.
    tracer->GetRegisters(execution_trace.LastContext());

    InstructionInfo<Arch>& info = execution_trace.NextInfo();

    // Fetch the instruction.
    // Be careful and only fetch memory inside the expected executable page.
    // This could be a rogue jump that will end in a fault. If execution does
    // fault by going out of bounds, it doesn't matter that we didn't read
    // exactly the same memory as the tracer tried to.
    if (address >= code_page_start && address - code_page_start < kPageSize) {
      max_size = std::min(max_size, kPageSize - (address - code_page_start));
      tracer->ReadMemory(address, info.bytes, max_size);
    } else {
      tracer->Stop();
      insn_out_of_bounds = true;
    }

    // Disassemble the instruction
    disas.Disassemble(address, info.bytes, max_size);

    info.address = address;
    info.instruction_id = disas.InstructionID();
    info.size = disas.InstructionSize();
  });
  absl::Status result = tracer.Run(execution_trace.MaxInstructions());
  // Capture the final state.
  tracer.GetRegisters(execution_trace.LastContext());
  if (result.ok() && insn_out_of_bounds) {
    // It is unlikely this will happen, but it may if a native tracer jumps to
    // an executable page in the runner.
    result = absl::OutOfRangeError("instruction fetch was out of bounds");
  }
  return result;
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_EXECUTION_TRACE_H_
