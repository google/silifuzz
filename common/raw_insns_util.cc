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

#include "./common/raw_insns_util.h"

#include <openssl/sha.h>  // IWYU pragma: keep

#include <cstdint>
#include <cstring>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "third_party/cityhash/city.h"
#include "./common/memory_mapping.h"
#include "./common/memory_perms.h"
#include "./common/proxy_config.h"
#include "./common/snapshot.h"
#include "./common/snapshot_util.h"
#include "./instruction/static_insn_filter.h"
#include "./util/arch.h"
#include "./util/arch_mem.h"
#include "./util/checks.h"
#include "./util/page_util.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

// TODO(ncbray): share with exit_sequence.h
// This file is in silifuzz/snap/ and silifuzz/common/ should not depend on it.
constexpr inline uint64_t kSnapExitAddress = 0xABCD0000;

namespace {

uint64_t HashToCodeAddress(uint64_t hash, uint64_t code_range_start_address,
                           uint64_t code_range_num_bytes,
                           uint64_t granularity) {
  // Must be aligned.
  CHECK_EQ(code_range_start_address % granularity, 0);
  CHECK_EQ(code_range_num_bytes % granularity, 0);

  // Must a power of 2.
  CHECK_EQ(code_range_num_bytes & code_range_num_bytes - 1, 0);

  const uint64_t mask = code_range_num_bytes / granularity - 1;
  return code_range_start_address + (hash & mask) * granularity;
}

uint64_t InstructionsToCodeAddress(const absl::string_view& code,
                                   uint64_t code_range_start_address,
                                   uint64_t code_range_num_bytes,
                                   uint64_t granularity) {
  uint64_t hash = CityHash64(code.data(), code.size());
  return HashToCodeAddress(hash, code_range_start_address, code_range_num_bytes,
                           granularity);
}

template <typename Arch>
uint64_t StackSize(const FuzzingConfig<Arch>& config);

template <>
uint64_t StackSize(const FuzzingConfig<X86_64>& config) {
  // x86_64 assumes the stack is the first page of data1.
  return kPageSize;
}

template <>
uint64_t StackSize(const FuzzingConfig<AArch64>& config) {
  return config.stack_range.num_bytes;
}

// TODO(ncbray): share a definition of this value with exit_sequence.h
// Currently there is a layering issue where common/ should not depend on snap/.
template <typename Arch>
constexpr uint64_t ExitSequenceSize();

template <>
constexpr uint64_t ExitSequenceSize<X86_64>() {
  // TODO(ncbray): the actual value is 14, but historically we've been using 32.
  // Fixing this value will require adding a specific test, so deferring it
  // instead of fixing it during an unrelated refactoring.
  return 32;
}

template <>
constexpr uint64_t ExitSequenceSize<AArch64>() {
  return 12;
}

}  // namespace

template <typename Arch>
absl::StatusOr<Snapshot> InstructionsToSnapshot(
    absl::string_view code, const UContext<Arch>& uctx,
    const FuzzingConfig<Arch>& config) {
  if (!StaticInstructionFilter<Arch>(code, config.instruction_filter)) {
    return absl::InvalidArgumentError(
        "code snippet contains problematic instructions.");
  }

  if (code.size() > kPageSize - ExitSequenceSize<Arch>()) {
    return absl::InvalidArgumentError(
        "code snippet + the exit sequence must fit into a single page.");
  }

  const uint64_t code_start_addr = uctx.gregs.GetInstructionPointer();
  const uint64_t code_end_addr = code_start_addr + code.size();
  if (!IsPageAligned(code_start_addr)) {
    return absl::InvalidArgumentError(
        "initial instruction point is not page aligned.");
  }
  if (code_start_addr == kSnapExitAddress) {
    return absl::InvalidArgumentError(
        "derived code address collides with exit sequence address.");
  }

  Snapshot snapshot(Snapshot::ArchitectureTypeToEnum<Arch>());

  // Create mapping for the code.
  // Historically, we tried to make executable pages execute-only in an attempt
  // to push the fuzzer towards generating code that didn't depend on the
  // contents of the executable segment. This would give us flexibility to
  // change the exit sequence, maybe add an entry sequence, possibly reduce the
  // chance that mutation produces invalid instruction sequences, etc.
  // But Linux has removed support for execute-only pages on ARMv8 for good
  // reasons that look unlikely to change:
  // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=24cecc37746393432d994c0dbc251fb9ac7c5d72
  // https://blog.siguza.net/PAN/
  // So we can't actually use execute-only pages.
  RETURN_IF_NOT_OK(MemoryMapping::CanMakeSized(code_start_addr, kPageSize));
  MemoryMapping code_page_mapping = Snapshot::MemoryMapping::MakeSized(
      code_start_addr, kPageSize, MemoryPerms::XR());
  snapshot.add_memory_mapping(code_page_mapping);

  // Add the code bytes.
  std::string code_with_traps = std::string(code);
  // Fill the codepage with traps. This is to help the generated snapshot exit
  // ASAP in case if we happen to "fixup" an invalid instruction to a valid one
  // by adding an endpoint trap.
  PadToSizeWithTraps<Arch>(code_with_traps, kPageSize);
  snapshot.add_memory_bytes(
      Snapshot::MemoryBytes(code_start_addr, code_with_traps));

  // Add the stack below the stack pointer.
  uint64_t stack_pointer = uctx.gregs.GetStackPointer();
  if (!IsPageAligned(stack_pointer)) {
    return absl::InvalidArgumentError("stack pointer is not page aligned.");
  }
  uint64_t stack_size = StackSize(config);
  uint64_t stack_start = stack_pointer - stack_size;
  RETURN_IF_NOT_OK(MemoryMapping::CanMakeSized(stack_start, stack_size));
  MemoryMapping data_page_mapping = Snapshot::MemoryMapping::MakeSized(
      stack_start, stack_size, MemoryPerms::RW());
  snapshot.add_memory_mapping(data_page_mapping);

  // Note: data page mappings are not added to the snapshot here. We are
  // currently relying on the SnapMaker discovering the minimum set of pages
  // that are actually used.
  // TODO(ncbray): specify the data pages here and ignore them later?

  // Add the registers.
  snapshot.set_registers(ConvertRegsToSnapshot(uctx.gregs, uctx.fpregs));

  // Add the end state.
  snapshot.add_expected_end_state(
      Snapshot::EndState(Snapshot::Endpoint(code_end_addr)));

  return snapshot;
}

// Instantiate
template absl::StatusOr<Snapshot> InstructionsToSnapshot(
    absl::string_view code, const UContext<X86_64>& uctx,
    const FuzzingConfig<X86_64>& config);
template absl::StatusOr<Snapshot> InstructionsToSnapshot(
    absl::string_view code, const UContext<AArch64>& uctx,
    const FuzzingConfig<AArch64>& config);

template <>
UContext<X86_64> GenerateUContextForInstructions(
    absl::string_view code, const FuzzingConfig<X86_64>& config) {
  // All must be page-aligned.
  CHECK_EQ(config.data1_range.start_address % kPageSize, 0);
  CHECK_EQ(config.data1_range.num_bytes % kPageSize, 0);
  CHECK_EQ(config.data2_range.start_address % kPageSize, 0);
  CHECK_EQ(config.data2_range.num_bytes % kPageSize, 0);

  const uint64_t code_start_addr =
      InstructionsToCodeAddress(code, config.code_range.start_address,
                                config.code_range.num_bytes, kPageSize);

  UContext<X86_64> uctx = {};

  // These are the values of %cs and %ss kernel sets for userspace programs.
  // RestoreUContext does not modify the two but the runner still verifies
  // the values didn't change during snapshot execution.
  uctx.gregs.cs = 0x33;
  uctx.gregs.ss = 0x2b;

  // Raise IF (0x200) and the reserved 0x2 which is always on according to
  // https://en.wikipedia.org/wiki/FLAGS_register
  // The IF is only accessible to the kernel, assume it's always set in
  // user mode.
  uctx.gregs.eflags = 0x202;

  // RSP points to the bottom of the writable page.
  uctx.gregs.rsp = config.data1_range.start_address + kPageSize;
  uctx.gregs.rip = code_start_addr;

  memset(&uctx.fpregs, 0, sizeof(uctx.fpregs));
  // Initialize FCW and MXCSR to sensible defaults that mask as many exceptions
  // as possible with the idea to allow generated snapshots execute more code.
  uctx.fpregs.mxcsr = 0x1f80;
  uctx.fpregs.mxcsr_mask = 0xffff;
  uctx.fpregs.fcw = 0x37f;
  // Non-zero initialization of at least 1 XMM register inhibits init state
  // optimization on Arcadia. This is a workaround for erratum 1386 "XSAVES
  // Instruction May Fail to Save XMM Registers to the Provided State Save
  // Area". See https://www.amd.com/system/files/TechDocs/56683-PUB-1.07.pdf
  uctx.fpregs.xmm[0] = 0xcafebabe;

  return uctx;
}

template <>
UContext<AArch64> GenerateUContextForInstructions(
    absl::string_view code, const FuzzingConfig<AArch64>& config) {
  const uint64_t code_start_addr =
      InstructionsToCodeAddress(code, config.code_range.start_address,
                                config.code_range.num_bytes, kPageSize);

  // Setup register state
  UContext<AArch64> uctx = {};

  // x30 will be aliased to pc as an artifact of how we jump into the code.
  uctx.gregs.x[30] = code_start_addr;
  uctx.gregs.pc = code_start_addr;

  // sp points off the end of the stack.
  uctx.gregs.sp =
      config.stack_range.start_address + config.stack_range.num_bytes;

  // HACK seed the addresses of the memory regions in registers.
  uctx.gregs.x[6] = config.data1_range.start_address;
  uctx.gregs.x[7] = config.data2_range.start_address;

  // Note: FPCR of zero means round towards nearest and no exceptions enabled.

  return uctx;
}

std::string InstructionsToSnapshotId(absl::string_view code) {
  uint8_t sha1_digest[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const uint8_t*>(code.data()), code.size(), sha1_digest);
  return absl::BytesToHexString(
      {reinterpret_cast<const char*>(&sha1_digest), sizeof(sha1_digest)});
}

}  // namespace silifuzz
