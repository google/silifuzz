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

#include "./snap/exit_sequence.h"

#include <sys/mman.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>

#include "./util/cache.h"
#include "./util/checks.h"
#include "./util/mem_util.h"

namespace silifuzz {

namespace {

// instruction templates.

// jmp *(%rip)
// The 64-bit jump target address is placed after this instruction.
// Padded with a two-byte NOP in front to ensure the address operand
// is 8-aligned.
// https://www.felixcloutier.com/x86/nop
constexpr uint8_t kJumpInsnBytes[] = {0x66, 0x90, 0xff, 0x25,
                                      0x00, 0x00, 0x00, 0x00};

// call *(%rip), like above but for call.
constexpr uint8_t kCallnsnBytes[] = {0xff, 0x15, 0x00, 0x00, 0x00, 0x00};

// Writes code sequence that performs a jump or a call to 'target'. The
// code is written in 'buffer'. If 'is_call' is true, generates a call
// sequence, otherwise generates jump sequence.
size_t WriteJumpOrCall(bool is_call, uint64_t target, void* buffer) {
  // The code sequence consists of a pc relative indirect jump/call followed by
  // a 64-bit target. This allows us to reach anywhere in the address space.
  const uint8_t* insn;
  size_t insn_size;
  if (is_call) {
    insn = kCallnsnBytes;
    insn_size = sizeof(kCallnsnBytes);
  } else {
    insn = kJumpInsnBytes;
    insn_size = sizeof(kJumpInsnBytes);
  }
  uint8_t* bytes = reinterpret_cast<uint8_t*>(buffer);
  MemCopy(bytes, insn, insn_size);
  MemCopy(bytes + insn_size, &target, sizeof(target));
  return insn_size + sizeof(target);
}

}  // namespace

size_t WriteSnapExitThunk(void (*reentry_address)(), void* buffer) {
  return WriteJumpOrCall(false /* is_call */,
                         reinterpret_cast<uint64_t>(reentry_address), buffer);
}

size_t WriteSnapExitSequence(void* buffer) {
  return WriteJumpOrCall(true /* is_call */, kSnapExitAddress, buffer);
}

uint64_t FixUpReturnAddress(uint64_t return_address) {
  return return_address - sizeof(kCallnsnBytes);
}

}  // namespace silifuzz
