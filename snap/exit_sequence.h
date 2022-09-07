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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_EXIT_SEQUENCE_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_EXIT_SEQUENCE_H_

#include <cstddef>
#include <cstdint>

namespace silifuzz {

// A pre-defined address for transfer control from a Snap back to the runner.
// This address does not change in different runner binaries so that we can
// directly generate jumps to this address in Snaps.
// REQUIRES: page size aligned.
constexpr inline uint64_t kSnapExitAddress = 0xABCD0000;

// Size of Snap exit sequence.
#if defined(__x86_64__)
// On x86_64, 14 bytes are required to hold a PC-relative indirect call followed
// by a 64-bit target address.
constexpr inline size_t kSnapExitSequenceSize = 14;
#elif defined(__aarch64__)
constexpr inline size_t kSnapExitSequenceSize = 12;
#else
#error "Unsupported architecture".
#endif

// Writes a snap exit sequence in 'buffer', which has capacity of at least
// kSnapExitSequenceSize bytes.
// This function is thread-safe.
// Returns the number of bytes written, which should be kSnapExitSequenceSize.
size_t WriteSnapExitSequence(void* buffer);

// Writes an instruction sequence into `buffer` that jumps to `reentry_address`.
// This function is thread-safe.
size_t WriteSnapExitThunk(void (*reentry_address)(), void* buffer);

// Initializes Snap exit handling. This sets up the exit point at
// kSnapExitAddress by mapping an executable page there and writing a branch
// to `reentry_address`.
//
// REQUIRES: Called once only.
void InitSnapExit(void (*reentry_address)());

// Reconstruct exiting %rip:
//
// The exiting call left a return address on the stack but it was the address
// after the call instruction. To get the correct address we need to do
// subtract the size of call instruction.
uint64_t FixUpReturnAddress(uint64_t return_address);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_EXIT_SEQUENCE_H_
