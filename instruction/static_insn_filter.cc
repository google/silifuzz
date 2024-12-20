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

#include "./instruction/static_insn_filter.h"

#include <cassert>
#include <cstdint>

#include "absl/strings/string_view.h"
#include "./util/arch.h"
#include "./util/bit_matcher.h"

namespace silifuzz {

template <>
bool StaticInstructionFilter<X86_64>(
    absl::string_view code, const InstructionFilterConfig<X86_64>& config) {
  // It's difficult to reliably disassemble x86_64 instructions, so for now we
  // don't try.
  return true;
}

// aarch64 filter
namespace {
// See the ARM ARM (Architecture Reference Manual) for the details of
// instruction encoding:  https://developer.arm.com/documentation/ddi0487/latest
// Start here: C4.1 A64 instruction set encoding

// In general, we need to ban PAC until we can control the PAC keys for the
// runner and set them to known constants. Otherwise the PAC instructions
// are effectively non-deterministic.

constexpr BitMatcher<uint32_t> kBannedInstructions[] = {
    //
    // The following instructions are things that can pass through the fuzzing
    // and making processes, and then cause a problem in the runner. If they are
    // not filtered, the runner will not be reliable.
    //
    // See: C4.1.66 Loads and Stores
    // Should cover STLXR, STLXRB, STLXRH, and STLXP but not LDAXR, STR, etc.
    // Bit 22 => 0, this is a store.
    // Bit 21 => X, cover both store register and store pair.
    // Store exclusive can succeed or fail in a non-deterministic manner.
    // Its exact behavior can depend on a variety of factors, such as another
    // snapshot doing a load exclusive or store exclusive to the same address.
    // It may also depend on if the address is in the cache or not or if context
    // is swapped out between executing the load and the store.
    {
        .mask = 0b0011'1111'1100'0000'0000'0000'0000'0000,
        .bits = 0b0000'1000'0000'0000'0000'0000'0000'0000,
    },
    // C4.1.66 Loads and Stores
    // Load/store register (pac)
    // Filter out PAC memory ops
    // Older versions of QEMU also treat these loads and stores as if they were
    // normal loads and stores, so they behave differently in the making
    // process.
    {
        .mask = 0b0011'1011'0010'0000'0000'0100'0000'0000,
        .bits = 0b0011'1000'0010'0000'0000'0100'0000'0000,
        // Note that if we do enable PAC support, unallocated encodings should
        // be filtered out:
        // size (bits 30:31) != 11 is "unallocated"
        // V (bit 26) != 0 is "unallocated"
    },
    // C4.1.66 Branches, Exception Generating and System instructions
    // Unconditional branch (register)
    // Filter out PAC branches
    // This should cover:
    // BRAA, BRAAZ, BRAB, BRABZ
    // BLRAA, BLRAAZ, BLRAB, BLRABZ
    // RETAA, RETAB
    // ERETAA, ERETAB
    // op2 != 11111 is unallocated, so we ignore those bits.
    // top four bits of op3 != 0 are unallocated so we ignore them.
    // PAC variations are op3 == 000010 and 000011, so we ignore the last bit.
    // opc can also be ignored because op3 consistently indicates PAC for all
    // allocated variations of op3.
    {
        .mask = 0b1111'1110'0000'0000'0000'1000'0000'0000,
        .bits = 0b1101'0110'0000'0000'0000'1000'0000'0000,
    },
    // C4.1.66 Branches, Exception Generating and System instructions
    // Hints
    // Should cover zero argument AUT* and PAC*
    // CRm = 00x1, op2=xxx
    {
        .mask = 0b1111'1111'1111'1111'1111'1101'0001'1111,
        .bits = 0b1101'0101'0000'0011'0010'0001'0001'1111,
    },
    // C4.1.68 Data Processing -- Register
    // Data-processing (1 source)
    // Should cover single argument AUT* and PAC*
    // opcode2 = xxxx1 covers the PAC instructions because there is a large
    // amount of unallocated instructions in this part of the instruction space.
    {
        .mask = 0b0101'1111'1110'0001'0000'0000'0000'0000,
        .bits = 0b0101'1010'1100'0001'0000'0000'0000'0000,
    },
    // C4.1.66 Branches, Exception Generating and System instructions
    // Hints
    // WFE is problematic because it can cause a snapshot to wait in userspace
    // for an event that no one is explicitly sending. Empirically, this can
    // cause some corpuses to run 2-3 orders of magnitude slower. It may also
    // cause some proxies to deadlock.
    {
        .mask = 0b1111'1111'1111'1111'1111'1111'1111'1111,
        .bits = 0b1101'0101'0000'0011'0010'0000'0101'1111,
    },
    // C4.1.66 Branches, Exception Generating and System instructions
    // Hints
    // WFI is problematic because it either will wait for an interrupt or it
    // will trap into the kernel. Waiting will cause some proxies to deadlock,
    // trapping will cause some corupses to run 1-2 orders of magnitude slower.
    // This entry is not colapsed with WFE because these instructions behave
    // slightly differently because Linux traps WFI and makes it a no-op and we
    // may want to experiment with unbanning WFI.
    {
        .mask = 0b1111'1111'1111'1111'1111'1111'1111'1111,
        .bits = 0b1101'0101'0000'0011'0010'0000'0111'1111,
    },
    // C4.1.66 Branches, Exception Generating and System instructions
    // System instructions with register argument
    // This should cover WFET and WFIT, which are WFE and WFI with timeouts and
    // are banned for the same reason as WFE and WFI.
    // These are the only instructions in this space, so ban the whole space.
    {
        .mask = 0b1111'1111'1111'1111'1111'0000'0000'0000,
        .bits = 0b1101'0101'0000'0011'0001'0000'0000'0000,
    },
    //
    // The following parts of the instruction space either do not have specified
    // instructions or contain instructions that should always fault.
    //
    // C4.1.1 Reserved
    // UDF will always fault
    {
        .mask = 0b1001'1110'0000'0000'0000'0000'0000'0000,
        .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
    },
    // C4.1 A64 instruction set encoding
    // op1 = 0001 is "unallocated"
    {
        .mask = 0b0001'1110'0000'0000'0000'0000'0000'0000,
        .bits = 0b0000'0010'0000'0000'0000'0000'0000'0000,
    },
    // C4.1 A64 instruction set encoding
    // op1 = 0011 is "unallocated"
    {
        .mask = 0b0001'1110'0000'0000'0000'0000'0000'0000,
        .bits = 0b0000'0110'0000'0000'0000'0000'0000'0000,
    },
    //
    // The following parts of the instruction space do not have specified
    // instructions but more complicated and don't cover as much of the space as
    // the previous section.
    //
    // C4.1.67 Loads and Stores
    // Atomic memory operations
    // The allocated / unallocated boundary for atomics is complicated, but we
    // want to cut out the big chunks of unallocated space to increase the
    // probability that atomic instructions can be disassembled. This is because
    // QEMU is currently accepting unaligned atomics but the hardware is not.
    // In addition, both QEMU and the hardware are accepting malformed atomic
    // instructions, which makes it difficult to disassemble and disagnose that
    // it was a misaligned atomic.
    {
        // V = 0, o3 = 1, opc = 11x is unallocated
        .mask = 0b0011'1111'0010'0000'1110'1100'0000'0000,
        .bits = 0b0011'1000'0010'0000'1110'0000'0000'0000,
    },
    {
        // V = 0, A = 0, o3 = 1, opc = 110 is unallocated
        .mask = 0b0011'1111'1010'0000'1111'1100'0000'0000,
        .bits = 0b0011'1000'0010'0000'1100'0000'0000'0000,
    },
    {
        // V = 1 is unallocated
        .mask = 0b0011'1111'0010'0000'0000'1100'0000'0000,
        .bits = 0b0011'1100'0010'0000'0000'0000'0000'0000,
    },
    // C4.1.78 SVE Memory - Contiguous Load
    // SVE contiguous non-fault load (scalar plus immediate)
    // Non-faulting memory operations mean that the making process will not know
    // all the memory pages a test may touch. When a test containing a
    // non-faulting instruction is added to a corpus, another test may contain
    // the page the non-faulting instruction is trying to access. This means
    // that a test containing a non-faulting instruction can behave differently
    // depending on the presense of other tests in the corpus. In effect, this
    // instruction can snoop on the state of the page table in a way the making
    // process cannot detect.
    {
        .mask = 0b1111'1110'0001'0000'1110'0000'0000'0000,
        .bits = 0b1010'0100'0001'0000'1010'0000'0000'0000,
    },
    // C4.1.77 SVE Memory - 32-bit Gather and Unsized Contiguous
    // SVE 32-bit gather load halfwords (scalar plus 32-bit scaled offsets)
    // "First fault" loads have similar problems to non-faulting loads because
    // any load after the first one will not explicitly fault.
    {
        .mask = 0b1111'1111'1010'0000'1010'0000'0000'0000,
        .bits = 0b1000'0100'1010'0000'0010'0000'0000'0000,
    },
    // C4.1.77 SVE Memory - 32-bit Gather and Unsized Contiguous
    // SVE 32-bit gather load words (scalar plus 32-bit scaled offsets)
    {
        .mask = 0b1111'1111'1010'0000'1010'0000'0000'0000,
        .bits = 0b1000'0101'0010'0000'0010'0000'0000'0000,
    },
    // C4.1.77 SVE Memory - 32-bit Gather and Unsized Contiguous
    // SVE 32-bit gather load (scalar plus 32-bit unscaled offsets)
    // This is a bit complicated to define because if bits 24 and 23 are both 1,
    // this would be a prefetch. So we define the three masks around this case.
    // Note: mask covers op=10 u=0 even though it is unallocated.
    {
        .mask = 0b1111'1111'1010'0000'1010'0000'0000'0000,
        .bits = 0b1000'0100'0000'0000'0010'0000'0000'0000,
    },
    {
        .mask = 0b1111'1111'1010'0000'1010'0000'0000'0000,
        .bits = 0b1000'0100'1000'0000'0010'0000'0000'0000,
    },
    {
        .mask = 0b1111'1111'1010'0000'1010'0000'0000'0000,
        .bits = 0b1000'0101'0000'0000'0010'0000'0000'0000,
    },
    // SVE 32-bit gather load (vector plus immediate)
    // Note: mask covers msz=10 u=0, similar to the previous case.
    // Note: mask does _not_ cover msz=11. Covering this would make the mask
    // simpler, but there's a greater chance this encoding will be allocated in
    // the future.
    {
        .mask = 0b1111'1111'1110'0000'1010'0000'0000'0000,
        .bits = 0b1000'0100'0010'0000'1010'0000'0000'0000,
    },
    {
        .mask = 0b1111'1111'1110'0000'1010'0000'0000'0000,
        .bits = 0b1000'0100'1010'0000'1010'0000'0000'0000,
    },
    {
        .mask = 0b1111'1111'1110'0000'1010'0000'0000'0000,
        .bits = 0b1000'0101'0010'0000'1010'0000'0000'0000,
    },
    // SVE contiguous first-fault load (scalar plus scalar)
    {
        .mask = 0b1111'1110'0000'0000'1110'0000'0000'0000,
        .bits = 0b1010'0100'0000'0000'0110'0000'0000'0000,
    },
    // SVE 64-bit gather load (scalar plus 64-bit scaled offsets)
    // Note: mask covers opc=11 u=0 even though it is unallocated.
    {
        .mask = 0b1111'1111'1110'0000'1010'0000'0000'0000,
        .bits = 0b1100'0100'1110'0000'1010'0000'0000'0000,
    },
    {
        .mask = 0b1111'1111'1110'0000'1010'0000'0000'0000,
        .bits = 0b1100'0101'0110'0000'1010'0000'0000'0000,
    },
    {
        .mask = 0b1111'1111'1110'0000'1010'0000'0000'0000,
        .bits = 0b1100'0101'1110'0000'1010'0000'0000'0000,
    },
    // SVE 64-bit gather load (scalar plus 32-bit unpacked scaled offsets)
    // Note: mask covers opc=11 u=0 even though it is unallocated.
    {
        .mask = 0b1111'1111'1010'0000'1010'0000'0000'0000,
        .bits = 0b1100'0100'1010'0000'0010'0000'0000'0000,
    },
    {
        .mask = 0b1111'1111'1010'0000'1010'0000'0000'0000,
        .bits = 0b1100'0101'0010'0000'0010'0000'0000'0000,
    },
    {
        .mask = 0b1111'1111'1010'0000'1010'0000'0000'0000,
        .bits = 0b1100'0101'1010'0000'0010'0000'0000'0000,
    },
    // SVE 64-bit gather load (vector plus immediate)
    // Note: mask covers msz=11 u=0 even though it is unallocated.
    {
        .mask = 0b1111'1110'0110'0000'1010'0000'0000'0000,
        .bits = 0b1100'0100'0010'0000'1010'0000'0000'0000,
    },
    // SVE 64-bit gather load (scalar plus 64-bit unscaled offsets)
    // Note: mask covers msz=11 u=0 even though it is unallocated.
    {
        .mask = 0b1111'1110'0110'0000'1010'0000'0000'0000,
        .bits = 0b1100'0100'0100'0000'1010'0000'0000'0000,
    },
    // SVE 64-bit gather load (scalar plus unpacked 32-bit unscaled offsets)
    // Note: mask covers msz=11 u=0 even though it is unallocated.
    {
        .mask = 0b1111'1110'0010'0000'1010'0000'0000'0000,
        .bits = 0b1100'0100'0000'0000'0010'0000'0000'0000,
    },
};

// These rules cover fine-grained encoding issues that could be corrected in
// the mutator, if desired.
constexpr RequiredBits<uint32_t> kRequiredInstructionBits[] = {
    {
        // See: C4.1.65 Branches, Exception Generating and System
        // instructions
        .pattern =
            {
                .mask = 0b1111'1111'0000'0000'0000'0000'0000'0000,
                .bits = 0b1101'0101'0000'0000'0000'0000'0000'0000,
            },
        // The spec currently does not define any system instructions that have
        // non-zero bits for 22 and 23. Some versions of QEMU do not check this.
        .expect =
            {
                .mask = 0b0000'0000'1100'0000'0000'0000'0000'0000,
                .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
            },
    },
    {
        // See: C4.1.66 Loads and Stores
        // op1 = 0x00 op1 = 1 op2 = 0x
        .pattern =
            {
                .mask = 0b1011'1111'0000'0000'0000'0000'0000'0000,
                .bits = 0b0000'1100'0000'0000'0000'0000'0000'0000,
            },
        // op3 != 0xxxxx  is "unallocated"
        .expect =
            {
                .mask = 0b0000'0000'0010'0000'0000'0000'0000'0000,
                .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
            },
    },
    {
        // See: C4.1.66 Loads and Stores
        // op1 = 0x00 op1 = 1 op2 = x0
        .pattern =
            {
                .mask = 0b1011'1110'1000'0000'0000'0000'0000'0000,
                .bits = 0b0000'1100'0000'0000'0000'0000'0000'0000,
            },
        // op3 != x000000  is "unallocated"
        .expect =
            {
                .mask = 0b0000'0000'0001'1111'0000'0000'0000'0000,
                .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
            },
    },
    {
        // See: C4.1.66 Loads and Stores
        // op0 = 1x00
        .pattern =
            {
                .mask = 0b1011'1010'0000'0000'0000'0000'0000'0000,
                .bits = 0b1000'1000'0000'0000'0000'0000'0000'0000,
            },
        // op1 != 0 is "unallocated"
        .expect =
            {
                .mask = 0b0000'0100'0000'0000'0000'0000'0000'0000,
                .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
            },
    },
    {
        // See: C4.1.66 Loads and Stores
        // Should cover all compare and swap instructions.
        .pattern =
            {
                .mask = 0b0011'1111'1010'0000'0000'0000'0000'0000,
                .bits = 0b0000'1000'1010'0000'0000'0000'0000'0000,
            },
        // The spec declares Rt2 != 11111 (xzr) "unallocated". Some versions of
        // QEMU do not check this.
        .expect =
            {
                .mask = 0b0000'0000'0000'0000'0111'1100'0000'0000,
                .bits = 0b0000'0000'0000'0000'0111'1100'0000'0000,
            },
    },
    {
        // C4.1.68 Data Processing -- Register
        // Data-processing (1 source)
        .pattern =
            {
                .mask = 0b0101'1111'1110'0000'0000'0000'0000'0000,
                .bits = 0b0101'1010'1100'0000'0000'0000'0000'0000,
            },
        // S (bit 29) != 0 "unallocated".
        // Parts of opcode2 (bits 20:17) and opcode (bit 15) must be zero.
        .expect =
            {
                .mask = 0b0010'0000'0001'1110'1000'0000'0000'0000,
                .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
            },
    },
    {
        // C4.1.68 Data Processing -- Register
        // Data-processing (1 source)
        .pattern =
            {
                .mask = 0b0111'1111'1111'1111'0000'0000'0000'0000,
                .bits = 0b0101'1010'1100'0000'0000'0000'0000'0000,
            },
        // If S = 0 and opcode2 == 00000, part of opcode (bits 13:14) must be
        // zero. This is a very narrow part of the encoding space, but it
        // contains a lot of distinct instructions so the fuzzer finds it.
        .expect =
            {
                .mask = 0b0000'0000'0000'0000'0110'0000'0000'0000,
                .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
            },
    },
    {
        // C4.1.68 Data Processing -- Register
        // Add/subtract (extended register)
        .pattern =
            {
                .mask = 0b0001'1111'0010'0000'0000'0000'0000'0000,
                .bits = 0b0000'1011'0010'0000'0000'0000'0000'0000,
            },
        // The spec declares Opt (bits 23:22) != 00 "unallocated". Some versions
        // of QEMU do not check this.
        .expect =
            {
                .mask = 0b0000'0000'1100'0000'0000'0000'0000'0000,
                .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
            },
    },
    {
        // C4.1.68 Data Processing -- Register
        // Floating-point data-processing (2 source)
        .pattern =
            {
                .mask = 0b0101'1111'0010'0000'0000'1100'0000'0000,
                .bits = 0b0001'1110'0010'0000'0000'1000'0000'0000,
            },
        // The spec declares M (bit 31) != 0 is "unallocated".
        // The spec declares S (bit 29) != 0 is "unallocated".
        .expect =
            {
                .mask = 0b1010'0000'0000'0000'0000'0000'0000'0000,
                .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
            },
    },
    {
        // C4.1.68 Data Processing -- Register
        // Floating-point data-processing (3 source)
        .pattern =
            {
                .mask = 0b0101'1111'0000'0000'0000'0000'0000'0000,
                .bits = 0b0001'1111'0000'0000'0000'0000'0000'0000,
            },
        // The spec declares M (bit 31) != 0 is "unallocated".
        // The spec declares S (bit 29) != 0 is "unallocated".
        .expect =
            {
                .mask = 0b1010'0000'0000'0000'0000'0000'0000'0000,
                .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
            },
    },
    {
        // C4.1.69 Data Processing -- Scalar Floating-Point and Advanced SIMD
        // Floating-point immediate
        .pattern =
            {
                .mask = 0b0101'1111'0010'0000'0001'1100'0000'0000,
                .bits = 0b0001'1110'0010'0000'0001'0000'0000'0000,
            },
        // The spec declares M (bit 31) != 0 is "unallocated".
        // The spec declares S (bit 29) != 0 is "unallocated".
        // The spec declares imm5 (bit 5:9) != 00000 is "unallocated".
        .expect =
            {
                .mask = 0b1010'0000'0000'0000'0000'0011'1110'0000,
                .bits = 0b0000'0000'0000'0000'0000'0000'0000'0000,
            },
    },
};

// C4.1 A64 instruction set encoding
// op1 = 0010 is SVE encodings
constexpr BitMatcher<uint32_t> kSVEInstruction = {
    .mask = 0b0001'1110'0000'0000'0000'0000'0000'0000,
    .bits = 0b0000'0100'0000'0000'0000'0000'0000'0000,
};

// C4.1.66 Branches, Exception Generating and System instructions
// System register move
// Should match MRS and MSR instructions.  Bit 21 controls if this is a read or
// a write.  Bit 20 is technically redundant with the high bit of op0. It needs
// to be 1 for the instruction to be a system register move, but all system
// registers are specified with the high bit of op0 as 1.
constexpr BitMatcher<uint32_t> kSysregInstruction = {
    .mask = 0b1111'1111'1101'0000'0000'0000'0000'0000,
    .bits = 0b1101'0101'0001'0000'0000'0000'0000'0000,
};

// C4.1 A64 instruction set encoding
// op1 = x1x0 is a Load/Store instruction.
constexpr BitMatcher<uint32_t> kLoadStoreInstruction = {
    .mask = 0b0000'1010'0000'0000'0000'0000'0000'0000,
    .bits = 0b0000'1000'0000'0000'0000'0000'0000'0000,
};

// C4.1.30 SVE encodings for memory operations.
//  1000010 C4.1.77 SVE Memory - 32-bit Gather and Unsized Contiguous
//  1010010 C4.1.78 SVE Memory - Contiguous Load
//  1100010 C4.1.79 SVE Memory - 64-bit Gather
//  1110010 C4.1.80-C4.1.85 Other SVE Memory operations
constexpr BitMatcher<uint32_t> kSVEMemoryOperationInstruction = {
    .mask = 0b1001'1110'0000'0000'0000'0000'0000'0000,
    .bits = 0b1000'0100'0000'0000'0000'0000'0000'0000,
};

// C4.1.29 SME Memory operations.
constexpr BitMatcher<uint32_t> kSMEMemoryOperationInstruction = {
    .mask = 0b1111'1110'0000'0000'0000'0000'0000'0000,
    .bits = 0b1110'0000'0000'0000'0000'0000'0000'0000,
};

constexpr bool is_load_store_insn(uint32_t insn) {
  return kLoadStoreInstruction.matches(insn) ||
         kSMEMemoryOperationInstruction.matches(insn) ||
         kSVEMemoryOperationInstruction.matches(insn);
}

constexpr uint32_t sysreg(uint32_t op0, uint32_t op1, uint32_t CRn,
                          uint32_t CRm, uint32_t op2) {
  assert(op0 < 4);
  assert(op1 < 8);
  assert(CRn < 16);
  assert(CRm < 16);
  assert(op2 < 8);
  return op0 << 19 | op1 << 16 | CRn << 12 | CRm << 8 | op2 << 5;
}

// The bits of the sysreg instruction that select which sysreg is being read or
// written.
const uint32_t kSysregMask = sysreg(0b11, 0b111, 0b1111, 0b1111, 0b111);

// Sysregs that tests can safely use.
// Most sysregs are either inaccessible at EL0 or non-deterministic in some way.
// It's easier to allow specific registers than ban the problematic ones.
constexpr uint32_t kAllowedSysregs[] = {
    // DCZID_EL0 - Data Cache Zero ID register (ro)
    // Note: we're banning this register, for the moment, because at minimum it
    // will gratuitously expose a difference between CPU models without
    // providing much diagnostic value (the read should produce a constant).
    // Deeper investigation is needed to see if this can be affected by BIOS
    // settings, etc.
    // sysreg(0b11, 0b011, 0b0000, 0b0000, 0b111),

    // NCZV - Condition Flags (rw)
    sysreg(0b11, 0b011, 0b0100, 0b0010, 0b000),

    // DAIF omitted because it is blocked by the kernel.

    // SVCR - Streaming Vector Control Register (rw) (sme)
    // TODO(ncbray): SME support in Save/RestoreUContext
    // sysreg(0b11, 0b011, 0b0100, 0b0010, 0b010),
    // DIT - Data Independent Timing (rw)
    // TODO(ncbray): support in Save/RestoreUContext or randomize
    // Note: not recognized by Clang, yet.
    // sysreg(0b11, 0b011, 0b0100, 0b0010, 0b101),
    // SSBS - Speculative Store Bypass Safe (rw)
    // TODO(ncbray): support in Save/RestoreUContext or randomize
    // sysreg(0b11, 0b011, 0b0100, 0b0010, 0b110),
    // TCO - Tag Check Override (rw) (mte)
    // TODO(ncbray): support in Save/RestoreUContext or randomized.
    // Note: this is also entagled with a larger question of MTE support.
    // Note: not recognized by Clang, yet.
    // sysreg(0b11, 0b011, 0b0100, 0b0010, 0b111),
    // FPCR - Floating Point Control Register (rw)
    sysreg(0b11, 0b011, 0b0100, 0b0100, 0b000),
    // FPSR - Floating Point Status Register (rw)
    sysreg(0b11, 0b011, 0b0100, 0b0100, 0b001),

    // DSPSR_EL0 / DLR_EL0 omitted because they are UNDEFINED unless halted.

    // TPIDR_EL0 - EL0 Read/Write Software Thread ID Register (rw)
    sysreg(0b11, 0b011, 0b1101, 0b0000, 0b010),
    // TPIDRRO_EL0 - EL0 Read-Only Software Thread ID Register (ro)
    sysreg(0b11, 0b011, 0b1101, 0b0000, 0b011),
    // TPIDR2_EL0 - EL0 Read/Write Software Thread ID Register 2 (rw) (sme)
    // TODO(ncbray): SME support in Save/RestoreUContext
    // sysreg(0b11, 0b011, 0b1101, 0b0000, 0b101),

    // SCXTNUM_EL0, EL0 Read/Write Software Context Number (rw)
    // TODO(ncbray): support in Save/RestoreUContext
    // Note: not recognized by Clang, yet.
    // sysreg(0b11, 0b011, 0b1101, 0b0000, 0b111),
};

constexpr bool InstructionIsOK(uint32_t insn,
                               const InstructionFilterConfig<AArch64>& config) {
  for (const BitMatcher<uint32_t>& bits : kBannedInstructions) {
    if (bits.matches(insn)) {
      return false;
    }
  }
  if (!config.load_store_instructions_allowed && is_load_store_insn(insn)) {
    return false;
  }
  if (!config.sve_instructions_allowed && kSVEInstruction.matches(insn)) {
    return false;
  }
  for (const RequiredBits<uint32_t>& bits : kRequiredInstructionBits) {
    if (bits.violates_requirements(insn)) {
      return false;
    }
  }
  if (kSysregInstruction.matches(insn)) {
    for (uint32_t sysreg : kAllowedSysregs) {
      if ((insn & kSysregMask) == sysreg) return true;
    }
    return false;
  }
  return true;
}

}  // namespace

// For aarch64 we filter out any instruction sequence that contains a
// questionable instruction, even though we don't know for certain those bytes
// will be executed. A later mutation could make the instruction live.
template <>
bool StaticInstructionFilter<AArch64>(
    absl::string_view code, const InstructionFilterConfig<AArch64>& config) {
  if (code.size() % 4 != 0) return false;

  const uint32_t* begin = reinterpret_cast<const uint32_t*>(code.data());
  const uint32_t* end = begin + code.size() / sizeof(uint32_t);

  for (const uint32_t* insn = begin; insn < end; ++insn) {
    if (!InstructionIsOK(*insn, config)) return false;
  }

  return true;
}

}  // namespace silifuzz
