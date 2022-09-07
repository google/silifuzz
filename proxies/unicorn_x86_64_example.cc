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
#include <cstdlib>

#include "third_party/unicorn/unicorn.h"
#include "third_party/unicorn/x86.h"

// Checks that (x) returned UC_ERR_OK.
#define MUST_BE_OK(x)              \
  do {                             \
    if (UC_ERR_OK != (x)) abort(); \
  } while (false)

// Code region to map: [2Gb, 2Gb+4k)
constexpr uint64_t kCodeAddr = 1ULL << 31;  // 2G
constexpr uint64_t kCodeSize = 0x1000;

// Memory region to map: [4K, 1Gb)
constexpr uint64_t kMemAddr = 0x1000;
constexpr uint64_t kMemSize = (1ULL << 30) - kMemAddr;

// Stack is some address inside the memory region.
constexpr uint64_t kStackAddr = 0x1000000;

// Does uc_open(uc) on scope entry, uc_close(*uc) on scope exit.
struct ScopedUC {
  explicit ScopedUC(uc_engine **uc) : uc(uc) {
    MUST_BE_OK(uc_open(UC_ARCH_X86, UC_MODE_64, uc));
  }
  ~ScopedUC() { MUST_BE_OK(uc_close(*uc)); }
  uc_engine **uc;
};

// Consumes raw x86_64 instructions.
// Returns 0 if the instructions look interesting, -1 otherwise, as per
// https://llvm.org/docs/LibFuzzer.html#rejecting-unwanted-inputs.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Reject large inputs.
  if (size > kCodeSize) return -1;

  // Initialize emulator, ensure uc_close() is called on return.
  uc_engine *uc;
  ScopedUC scoped_uc(&uc);

  // Map the code page.
  MUST_BE_OK(uc_mem_map(uc, kCodeAddr, kCodeSize, UC_PROT_EXEC));

  // Write the code.
  MUST_BE_OK(uc_mem_write(uc, kCodeAddr, data, size));

  // Map the data region.
  MUST_BE_OK(uc_mem_map(uc, kMemAddr, kMemSize, UC_PROT_READ | UC_PROT_WRITE));

  // Set SP
  MUST_BE_OK(uc_reg_write(uc, UC_X86_REG_SP, &kStackAddr));

  // Emulate up to kMaxInstExecuted instructions.
  uint64_t end_of_code = kCodeAddr + size;
  size_t kMaxInstExecuted = 100;
  if (UC_ERR_OK !=
      uc_emu_start(uc, kCodeAddr, end_of_code, 0, kMaxInstExecuted)) {
    return -1;
  }

  // Reject the input if emulation didn't finish at end_of_code.
  uint64_t pc = 0;
  MUST_BE_OK(uc_reg_read(uc, UC_X86_REG_RIP, &pc));
  if (pc != end_of_code) return -1;

  // Accept the input.
  return 0;
}
