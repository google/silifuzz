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

#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "./util/checks.h"
#include "./util/itoa.h"
#include "third_party/unicorn/arm64.h"
#include "third_party/unicorn/unicorn.h"

namespace {

constexpr uint64_t kCodeAddr = 0x1000000;
constexpr uint64_t kCodeSize = 0x1000;

constexpr uint64_t kStackAddr = 0x2000000;
constexpr uint64_t kStackSize = 0x1000;

constexpr uint64_t kMem1Addr = 0x7000000;
constexpr uint64_t kMem1Size = 4 * 1024 * 1024;

constexpr uint64_t kMem2Addr = 0x10007000000;
constexpr uint64_t kMem2Size = 4 * 1024 * 1024;

#define UNICORN_CHECK(...)                              \
  do {                                                  \
    uc_err __uc_check_err = __VA_ARGS__;                \
    if ((__uc_check_err != UC_ERR_OK)) {                \
      LOG_FATAL(#__VA_ARGS__ " failed with ",           \
                silifuzz::IntStr(__uc_check_err), ": ", \
                uc_strerror(__uc_check_err));           \
    }                                                   \
  } while (0);

void map_memory(uc_engine *uc, uint64_t addr, uint64_t size, uint32_t prot) {
  uc_err err = uc_mem_map(uc, addr, size, prot);
  if (err != UC_ERR_OK) {
    LOG_FATAL("mapping ", silifuzz::HexStr(addr), " failed with ",
              silifuzz::IntStr(err), ": ", uc_strerror(err));
  }
}

void set_reg(uc_engine *uc, uc_arm64_reg reg, uint64_t value) {
  uc_err err = uc_reg_write(uc, reg, &value);
  if (err != UC_ERR_OK) {
    LOG_FATAL("trying to set ", silifuzz::IntStr(reg), " to ",
              silifuzz::HexStr(value), " failed with ", silifuzz::IntStr(err),
              ": ", uc_strerror(err));
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Require at least one instruction.
  if (size < 4) {
    return -1;
  }

  // Require complete instructions.
  // This makes disassembling the corpus easier.
  if (size % 4 != 0) {
    return -1;
  }

  // Reject huge examples, for now.
  if (size > kCodeSize) {
    return -1;
  }

  // Initialize emulator.
  uc_engine *uc;
  UNICORN_CHECK(uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc));

  // Details to sort out later:
  // TODO(ncbray) derive base address for code and validate lack of conflicts
  // TODO(ncbray) verify we're running at EL1 and drop to EL0?
  // TODO(ncbray) verify that the space around the code is initialized to zero.
  // TODO(ncbray) what are the instructions that execute but can't disassemble?
  // TODO(ncbray) why are system register load/stores _not_ generated?
  // TODO(ncbray) why do PC-relative loads work w/ execute-only memory?
  // 100001c: 980019c8 ldrsw       x8, 0x1000354
  // TODO(ncbray) why do atomic ops using the initial stack pointer not fault?
  // 1000000: 787f63fc ldumaxlh    wzr, w28, [sp]

  // Map code execute-only to discourage depending on any widget that may exist
  // before or after the code.
  map_memory(uc, kCodeAddr, kCodeSize, UC_PROT_EXEC);

  // Write the instructions to memory.
  uc_mem_write(uc, kCodeAddr, data, size);

  // Allocate stack.
  map_memory(uc, kStackAddr, kStackSize, UC_PROT_READ | UC_PROT_WRITE);

  // Stack grows towards zero, start at the largest address.
  // Note this address is unmapped.
  set_reg(uc, UC_ARM64_REG_SP, kStackAddr + kStackSize);

  // Setup memory regions.
  // HACK put the region addresses in an arbitrary register to make them
  // discoverable. In the future we should seed the dictionary with instructions
  // that materialize this constant instead.
  map_memory(uc, kMem1Addr, kMem1Size, UC_PROT_READ | UC_PROT_WRITE);
  set_reg(uc, UC_ARM64_REG_X6, kMem1Addr);
  map_memory(uc, kMem2Addr, kMem2Size, UC_PROT_READ | UC_PROT_WRITE);
  set_reg(uc, UC_ARM64_REG_X7, kMem2Addr);

  // Execute the instructions.
  // Stop at an arbitrary instruction count to avoid infinite loops.
  bool input_is_acceptable = true;
  uint64_t end_of_code = kCodeAddr + size;
  size_t max_inst_executed = 0x1000;
  uc_err err = uc_emu_start(uc, kCodeAddr, end_of_code, 0, max_inst_executed);

  // Check if the emulator stopped cleanly.
  if (err) {
    LOG_ERROR("uc_emu_start() returned ", silifuzz::IntStr(err), ": ",
              uc_strerror(err));
    input_is_acceptable = false;
  }

  // Check if the emulator stopped at the right address.
  // Unicorn does not return an error if it stops executing because it reached
  // the maximum instruction count.
  uint64_t pc = 0;
  UNICORN_CHECK(uc_reg_read(uc, UC_ARM64_REG_PC, &pc));
  if (pc != end_of_code) {
    LOG_ERROR("expected PC would be ", silifuzz::HexStr(end_of_code),
              ", but got ", silifuzz::HexStr(pc), " instead");
    input_is_acceptable = false;
  }

  uc_close(uc);

  return input_is_acceptable ? 0 : -1;
}
