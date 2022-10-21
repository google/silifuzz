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
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "third_party/cityhash/city.h"
#include "./common/memory_perms.h"
#include "./common/proxy_config.h"
#include "./common/snapshot.h"
#include "./common/snapshot_util.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

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

}  // namespace

absl::StatusOr<Snapshot> InstructionsToSnapshot_X86_64(
    absl::string_view code, const FuzzingConfig_X86_64& config) {
  Snapshot snapshot(Snapshot::Architecture::kX86_64);
  const uint64_t page_size = snapshot.page_size();

  // All must be page-aligned.
  CHECK_EQ(config.data1_range.start_address % page_size, 0);
  CHECK_EQ(config.data1_range.num_bytes % page_size, 0);
  CHECK_EQ(config.data2_range.start_address % page_size, 0);
  CHECK_EQ(config.data2_range.num_bytes % page_size, 0);

  // Leave this many bytes at the end of the code page for the exit sequence.
  constexpr auto kPaddingSizeBytes = 32;
  if (code.size() > snapshot.page_size() - kPaddingSizeBytes) {
    return absl::InvalidArgumentError(
        "code snippet + the exit sequence must fit into a single page.");
  }

  const uint64_t code_start_addr =
      InstructionsToCodeAddress(code, config.code_range.start_address,
                                config.code_range.num_bytes, page_size);
  auto code_page_mapping = Snapshot::MemoryMapping::MakeSized(
      code_start_addr, page_size, MemoryPerms::XR());
  snapshot.add_memory_mapping(code_page_mapping);
  std::string code_with_traps = std::string(code);
  // Fill the codepage with traps. This is to help the generated snapshot exit
  // ASAP in case if we happen to "fixup" an invalid instruction to a valid one
  // by adding an endpoint trap.
  CHECK_EQ(snapshot.trap_instruction().length(), 1);
  code_with_traps.resize(page_size, snapshot.trap_instruction()[0]);
  snapshot.add_memory_bytes(
      Snapshot::MemoryBytes(code_start_addr, code_with_traps));

  MemoryMapping data_page_mapping = Snapshot::MemoryMapping::MakeSized(
      config.data1_range.start_address, page_size, MemoryPerms::RW());
  snapshot.add_memory_mapping(data_page_mapping);

  UContext<X86_64> current = {};

  // These are the values of %cs and %ss kernel sets for userspace programs.
  // RestoreUContext does not modify the two but the runner still verifies
  // the values didn't change during snapshot execution.
  current.gregs.cs = 0x33;
  current.gregs.ss = 0x2b;

  // Raise IF (0x200) and the reserved 0x2 which is always on according to
  // https://en.wikipedia.org/wiki/FLAGS_register
  // The IF is only accessible to the kernel, assume it's always set in
  // user mode.
  current.gregs.eflags = 0x202;

  // RSP points to the bottom of the writable page.
  current.gregs.rsp = data_page_mapping.limit_address();
  current.gregs.rip = code_page_mapping.start_address();

  memset(&current.fpregs, 0, sizeof(current.fpregs));
  // Initialize FCW and MXCSR to sensible defaults that mask as many exceptions
  // as possible with the idea to allow generated snapshots execute more code.
  current.fpregs.mxcsr = 0x1f80;
  current.fpregs.fcw = 0x37f;
  // Non-zero initialization of at least 1 XMM register inhibits init state
  // optimization on Arcadia. This is a workaround for erratum 1386 "XSAVES
  // Instruction May Fail to Save XMM Registers to the Provided State Save
  // Area". See https://www.amd.com/system/files/TechDocs/56683-PUB-1.07.pdf
  current.fpregs.xmm[0] = 0xcafebabe;

  snapshot.set_registers(ConvertRegsToSnapshot(current.gregs, current.fpregs));

  snapshot.add_expected_end_state(Snapshot::EndState(
      Snapshot::Endpoint(code_page_mapping.start_address() + code.length())));
  return snapshot;
}

std::string InstructionsToSnapshotId(absl::string_view code) {
  uint8_t sha1_digest[SHA_DIGEST_LENGTH];
  SHA1(reinterpret_cast<const uint8_t*>(code.data()), code.size(), sha1_digest);
  return absl::BytesToHexString(
      {reinterpret_cast<const char*>(&sha1_digest), sizeof(sha1_digest)});
}

}  // namespace silifuzz
