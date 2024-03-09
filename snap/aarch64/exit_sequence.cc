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

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "./util/arch.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

namespace {

// Smashes x0 because we need a scratch register to contain the thunk address.
// Smashes x30 because we need to record the PC with a branch linked.
// Saves x0 and x30 in the stack redzone before smashing the registers.
// Note we need to materialize the thunk address into a register because all the
// branch instructions that take an immediate are relative.
// Note the thunk address materialization can be encoded in a single instruction
// because the non-zero bits are in exactly the right place.
constexpr uint32_t kExitSequence[] = {
    0xa93f7be0,  // stp x0, x30, [sp, #-16]
    0xd2b579a0,  // mov x0, #0xabcd0000
    0xd63f0000,  // blr x0
};

// Jumps to an 8-byte address immediately after the instruction sequence.
// This is a little sketchy because the raw address will be in executable
// memory, but doing it this way means we don't need to break the constant
// materialization down into four separate instructions.
// Smashes x0, which was already smashed by the exit sequence.
// Preserves x30 so we know the PC on exit.
constexpr uint32_t kExitThunk[] = {
    0x58000040,  // ldr x0, 10 <Thunk+0x8>
    0xd61f0000,  // br x0
                 // LSW of address
                 // MSW of address
};

}  // namespace

template <>
size_t GetSnapExitSequenceSize<AArch64>() {
  return sizeof(kExitSequence);
}

template <>
size_t WriteSnapExitThunk<AArch64>(void (*reentry_address)(), void* buffer) {
  uint8_t* bytes = reinterpret_cast<uint8_t*>(buffer);

  // The instructions.
  memcpy(bytes, kExitThunk, sizeof(kExitThunk));

  // PC-relative data.
  memcpy(bytes + sizeof(kExitThunk), &reentry_address, sizeof(reentry_address));

  return sizeof(kExitThunk) + sizeof(reentry_address);
}

template <>
size_t WriteSnapExitSequence<AArch64>(void* buffer) {
  memcpy(buffer, kExitSequence, sizeof(kExitSequence));
  return sizeof(kExitSequence);
}

template <>
uint64_t FixUpReturnAddress<AArch64>(uint64_t return_address) {
  return return_address - sizeof(kExitSequence);
}

template <>
size_t ExitSequenceStackBytesSize<AArch64>() {
  return sizeof(uint64_t) * 2;
}

template <>
void WriteExitSequenceStackBytes(const GRegSet<AArch64>& gregs, void* buffer) {
  uint8_t* bytes = reinterpret_cast<uint8_t*>(buffer);
  memcpy(bytes, &gregs.x[0], sizeof(gregs.x[0]));
  memcpy(bytes + sizeof(gregs.x[0]), &gregs.x[30], sizeof(gregs.x[30]));
}

}  // namespace silifuzz
