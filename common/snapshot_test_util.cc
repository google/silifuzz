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

#include "./common/snapshot_test_util.h"

#include <cstdint>
#include <string>
#include <vector>

#include "absl/base/internal/endian.h"
#include "./common/snapshot_proto.h"
#include "./common/snapshot_test_config.h"
#include "./common/snapshot_util.h"
#include "./proto/snapshot.pb.h"
#include "./util/padding.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {

static void InitTestSnapshotRegs(const TestSnapshotConfig& config,
                                 UContext<X86_64>& ucontext) {
  memset(&ucontext, 0, sizeof(ucontext));

  constexpr uint64_t kCanary = 0xBBBBBBBBBBBBBBBB;
  ucontext.gregs.r8 = kCanary;
  ucontext.gregs.r9 = kCanary;
  ucontext.gregs.r10 = kCanary;
  ucontext.gregs.r11 = kCanary;
  ucontext.gregs.r12 = kCanary;
  ucontext.gregs.r13 = kCanary;
  ucontext.gregs.r14 = kCanary;
  ucontext.gregs.r15 = kCanary;
  ucontext.gregs.rdi = kCanary;
  ucontext.gregs.rsi = kCanary;
  ucontext.gregs.rbp = kCanary;
  ucontext.gregs.rbx = kCanary;
  ucontext.gregs.rdx = kCanary;
  ucontext.gregs.rax = kCanary;
  ucontext.gregs.rcx = kCanary;

  // Sets RIP and RSP to be within the memory of this snapshot.
  ucontext.gregs.rip = config.code_addr;
  ucontext.gregs.rsp = config.data_addr + config.data_num_bytes;

  // Set RBP to the start of the data page;
  ucontext.gregs.rbp = config.data_addr;

  // These are the values of %cs and %ss kernel sets for userspace programs.
  // RestoreUContext does not modify the two but the runner still verifies
  // the values didn't change during snapshot execution.
  ucontext.gregs.cs = 0x33;
  ucontext.gregs.ss = 0x2b;

  ucontext.gregs.eflags = 0x202;

  // Initialize FCW and MXCSR to sensible defaults that mask as many exceptions
  // as possible with the idea to allow generated snapshots execute more code.
  ucontext.fpregs.mxcsr = 0x1f80;
  ucontext.fpregs.mxcsr_mask = 0xffff;
  ucontext.fpregs.fcw = 0x37f;
}

template <typename Arch>
// static
Snapshot TestSnapshots::Create(Type type, Options options) {
  Architecture arch = Snapshot::ArchitectureTypeToEnum<Arch>();

  const TestSnapshotConfig& config = GetTestSnapshotConfig(arch, type);

  Snapshot snapshot(arch);
  snapshot.set_id(config.name);

  // Create code mapping
  auto code_mapping = MemoryMapping::MakeSized(
      config.code_addr, config.code_num_bytes, MemoryPerms::XR());
  snapshot.add_memory_mapping(code_mapping);

  // Create data mapping
  auto data_mapping = MemoryMapping::MakeSized(
      config.data_addr, config.data_num_bytes, MemoryPerms::RW());
  snapshot.add_memory_mapping(data_mapping);

  // Populate the data page with the 3 user-defined data pieces. These can be
  // addressed relative to RBP by the snapshots.
  ByteData addresses_data = ByteData(8 * 3, '\0');
  absl::little_endian::Store64(addresses_data.data(), options.read_address);
  absl::little_endian::Store64(addresses_data.data() + 8,
                               options.write_address);
  absl::little_endian::Store64(addresses_data.data() + 16,
                               options.exec_address);
  snapshot.add_memory_bytes(
      MemoryBytes(data_mapping.start_address(), addresses_data));

  // Define the rest of memory (if needed)
  if (options.define_all_mapped) {
    // Define the rest of the data mapping.
    Address start = data_mapping.start_address() + addresses_data.size();
    int size = data_mapping.num_bytes() - addresses_data.size();
    snapshot.add_memory_bytes(MemoryBytes(start, ByteData(size, '\0')));
  } else if (config.stack_bytes_used) {
    // Only define the stack memory that will be used.
    const Address stack_top_address = config.data_addr + config.data_num_bytes;
    snapshot.add_memory_bytes(
        MemoryBytes(stack_top_address - config.stack_bytes_used,
                    ByteData(config.stack_bytes_used, '\0')));
  }

  std::string bytecode = config.instruction_bytes;
  const auto bytecode_size = bytecode.size();  // so we can ignore the fix-up
                                               // under the next if
  if (options.define_all_mapped) {
    PadToSizeWithTraps<Arch>(bytecode, code_mapping.num_bytes());
  }

  if (!bytecode.empty()) {
    MemoryBytes code_bytes(config.code_addr, bytecode);
    snapshot.add_memory_bytes(code_bytes);
  }

  UContext<Arch> ucontext;
  InitTestSnapshotRegs(config, ucontext);

  snapshot.set_registers(
      ConvertRegsToSnapshot(ucontext.gregs, ucontext.fpregs));

  // We are expecting `bytecode` to execute fully:
  const uintptr_t endpoint_address = config.code_addr + bytecode_size;
  Endpoint endpoint(endpoint_address);
  if (options.force_normal_state ||
      (config.normal_end && !options.force_undefined_state)) {
    // Add a full end-state with supposedly matched register values:
    // expected value of rip when reaching `endpoint`
    SetInstructionPointer(ucontext.gregs, endpoint_address);
    RegisterState regs = ConvertRegsToSnapshot(ucontext.gregs, ucontext.fpregs);
    EndState end_state(endpoint, regs);
    end_state.add_platform(CurrentPlatformId());
    snapshot.add_expected_end_state(end_state);
    CHECK_STATUS(snapshot.IsComplete(Snapshot::kNormalState));
  } else {
    // Add an endpoint-only end-state:
    snapshot.add_expected_end_state(EndState(endpoint));
    // Self-check what we made:
    CHECK_STATUS(snapshot.IsComplete(Snapshot::kUndefinedEndState));
  }

  snapshot.NormalizeAll();

  if (options.define_all_mapped) {
    CHECK(snapshot.MappedMemoryIsDefined());
  }
  return snapshot;
}

template Snapshot TestSnapshots::Create<X86_64>(Type type, Options options);

template <typename Arch>
// static
proto::Snapshot TestSnapshots::CreateProto(Type type, Options options) {
  const Snapshot snapshot = Create<Arch>(type, options);
  proto::Snapshot proto;
  SnapshotProto::ToProto(snapshot, &proto);
  return proto;
}

template proto::Snapshot TestSnapshots::CreateProto<X86_64>(Type type,
                                                            Options options);

}  // namespace silifuzz.
