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
#include "absl/status/status.h"
#include "./common/memory_state.h"
#include "./common/snapshot_proto.h"
#include "./common/snapshot_test_config.h"
#include "./common/snapshot_util.h"
#include "./proto/snapshot.pb.h"
#include "./snap/exit_sequence.h"
#include "./util/arch.h"
#include "./util/arch_mem.h"
#include "./util/checks.h"
#include "./util/platform.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {

namespace {

void InitTestSnapshotRegs(const TestSnapshotConfig& config,
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

void InitTestSnapshotRegs(const TestSnapshotConfig& config,
                          UContext<AArch64>& ucontext) {
  memset(&ucontext, 0, sizeof(ucontext));

  constexpr uint64_t kCanary = 0xBBBBBBBBBBBBBBBB;
  for (uint64_t* reg = std::begin(ucontext.gregs.x);
       reg < std::end(ucontext.gregs.x); reg++) {
    *reg = kCanary;
  }

  // PC points at the begining of code.
  ucontext.gregs.pc = config.code_addr;
  // x30 will be aliased to pc as an artifact of how we jump into the code.
  ucontext.gregs.x[30] = ucontext.gregs.pc;

  // Stack pointer at the end of the data page.
  ucontext.gregs.sp = config.data_addr + config.data_num_bytes;

  // Initialize data pointers, similar to raw_insns_util.
  ucontext.gregs.x[6] = config.data_addr;
  ucontext.gregs.x[7] = config.data_addr;
}

// The bytes that RestoreUContext() will write into the stack of the
// snapshot as a (presently unavoidable) part of doing its work
// when jumping-in to start executing `snapshot`.
template <typename Arch>
Snapshot::MemoryBytes RestoreUContextStackBytes(const Snapshot& snapshot) {
  GRegSet<Arch> gregs;
  CHECK_STATUS(ConvertRegsFromSnapshot(snapshot.registers(), &gregs));
  std::string stack_data = RestoreUContextStackBytes(gregs);
  return Snapshot::MemoryBytes(GetStackPointer(gregs) - stack_data.size(),
                               stack_data);
}

// Applies side effects of RestoreUContextBytes() and other Snap machinery
// to the given snapshot/end_state pair.
template <typename Arch>
absl::StatusOr<Snapshot::EndState> ApplySideEffects(
    const Snapshot& snapshot, const Snapshot::EndState& end_state);

template <>
absl::StatusOr<Snapshot::EndState> ApplySideEffects<X86_64>(
    const Snapshot& snapshot, const Snapshot::EndState& end_state) {
  // Construct initial memory state of the snaphsot modulo non-writable
  // mappings.
  MemoryState memory_state =
      MemoryState::MakeInitial(snapshot, MemoryState::kZeroMappedBytes);
  for (const MemoryMapping& m : snapshot.memory_mappings()) {
    if (!m.perms().Has(MemoryPerms::W())) {
      memory_state.RemoveMemoryMapping(m.start_address(), m.limit_address());
    }
  }

  // Add RestoreUContext stack bytes, original end state memory delta, and
  // snap exit stack bytes to construct full end state memory bytes.
  memory_state.SetMemoryBytes(RestoreUContextStackBytes<X86_64>(snapshot));
  memory_state.SetMemoryBytes(end_state.memory_bytes());

  const auto& endpoint = end_state.endpoint();
  Snapshot::EndState es_with_sideeffects =
      Snapshot::EndState(endpoint, end_state.registers());
  es_with_sideeffects.set_platforms(end_state.platforms());

  // The snap exit consists of a call instruction followed by a 64-bit address.
  // The call instruction is rip-relative and the address is not part of the
  // instruction but rather situated right after it in the insns stream.
  // See exit_sequence.h for details.
  // The length of the exit sequence is thus the length of a call instruction
  // plus 8 bytes. When the exit call is executed, it leaves the address after
  // the call instruction on stack.
  Snapshot::Address snap_exit_addr =
      endpoint.instruction_address() + kSnapExitSequenceSize - sizeof(uint64_t);
  Snapshot::ByteData snap_exit_addr_data(
      reinterpret_cast<Snapshot::ByteData::value_type*>(&snap_exit_addr),
      sizeof(snap_exit_addr));
  // On x86_64, a stack push is done by decrementing the stack point first
  // and then writing to location pointed to by the new stack pointer.
  //
  // before call
  //   RSP-> 20000000: XX XX ....
  //         1ffffff8: XX XX ....
  //
  // after call
  //         20000000: XX XX ....
  //   RSP-> 1ffffff8: <return address>
  //
  const Snapshot::Address end_point_stack_pointer =
      snapshot.ExtractRsp(end_state.registers());
  RETURN_IF_NOT_OK(Snapshot::MemoryBytes::CanConstruct(
      end_point_stack_pointer - sizeof(snap_exit_addr), snap_exit_addr_data));
  Snapshot::MemoryBytes return_address_memory_bytes(
      end_point_stack_pointer - sizeof(snap_exit_addr), snap_exit_addr_data);
  memory_state.SetMemoryBytes(return_address_memory_bytes);
  RETURN_IF_NOT_OK(es_with_sideeffects.ReplaceMemoryBytes(
      memory_state.memory_bytes_list(memory_state.written_memory())));
  return es_with_sideeffects;
}

template <>
absl::StatusOr<Snapshot::EndState> ApplySideEffects<AArch64>(
    const Snapshot& snapshot, const Snapshot::EndState& end_state) {
  return end_state;
}

}  // namespace

template <typename Arch>
Snapshot CreateTestSnapshot(TestSnapshot type,
                            CreateTestSnapshotOptions options) {
  Snapshot::Architecture arch = Snapshot::ArchitectureTypeToEnum<Arch>();

  const TestSnapshotConfig& config = GetTestSnapshotConfig(arch, type);

  Snapshot snapshot(arch, config.name);

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
  Snapshot::ByteData addresses_data = Snapshot::ByteData(8 * 3, '\0');
  absl::little_endian::Store64(addresses_data.data(), options.read_address);
  absl::little_endian::Store64(addresses_data.data() + 8,
                               options.write_address);
  absl::little_endian::Store64(addresses_data.data() + 16,
                               options.exec_address);
  snapshot.add_memory_bytes(
      Snapshot::MemoryBytes(data_mapping.start_address(), addresses_data));

  // Define the rest of memory (if needed)
  if (options.define_all_mapped) {
    // Define the rest of the data mapping.
    Snapshot::Address start =
        data_mapping.start_address() + addresses_data.size();
    int size = data_mapping.num_bytes() - addresses_data.size();
    snapshot.add_memory_bytes(
        Snapshot::MemoryBytes(start, Snapshot::ByteData(size, '\0')));
  } else if (config.stack_bytes_used) {
    // Only define the stack memory that will be used.
    const Snapshot::Address stack_top_address =
        config.data_addr + config.data_num_bytes;
    snapshot.add_memory_bytes(Snapshot::MemoryBytes(
        stack_top_address - config.stack_bytes_used,
        Snapshot::ByteData(config.stack_bytes_used, '\0')));
  }

  std::string bytecode = config.instruction_bytes;
  const auto bytecode_size = bytecode.size();  // so we can ignore the fix-up
                                               // under the next if
  if (options.define_all_mapped) {
    PadToSizeWithTraps<Arch>(bytecode, code_mapping.num_bytes());
  }

  if (!bytecode.empty()) {
    Snapshot::MemoryBytes code_bytes(config.code_addr, bytecode);
    snapshot.add_memory_bytes(code_bytes);
  }

  UContext<Arch> ucontext;
  InitTestSnapshotRegs(config, ucontext);

  snapshot.set_registers(
      ConvertRegsToSnapshot(ucontext.gregs, ucontext.fpregs));

  // We are expecting `bytecode` to execute fully:
  Snapshot::Endpoint endpoint(config.code_addr + bytecode_size);
  if (options.force_normal_state || config.normal_end) {
    // Add a full end-state with supposedly matched register values:
    // expected value of rip when reaching `endpoint`
    SetInstructionPointer(ucontext.gregs, endpoint.instruction_address());
    Snapshot::RegisterState regs =
        ConvertRegsToSnapshot(ucontext.gregs, ucontext.fpregs);
    Snapshot::EndState end_state(endpoint, regs);
    end_state.add_platform(CurrentPlatformId());
    auto end_state_with_sideeffects =
        ApplySideEffects<Arch>(snapshot, end_state);
    CHECK_STATUS(end_state_with_sideeffects.status());
    CHECK_STATUS(
        snapshot.can_add_expected_end_state(*end_state_with_sideeffects));
    snapshot.add_expected_end_state(*end_state_with_sideeffects);
  } else {
    // Add an endpoint-only end-state:
    snapshot.add_expected_end_state(Snapshot::EndState(endpoint));
    // Self-check what we made:
    CHECK_STATUS(snapshot.IsComplete(Snapshot::kUndefinedEndState));
  }

  snapshot.NormalizeAll();

  if (options.define_all_mapped) {
    CHECK(snapshot.MappedMemoryIsDefined());
  }
  return snapshot;
}

template Snapshot CreateTestSnapshot<X86_64>(TestSnapshot type,
                                             CreateTestSnapshotOptions options);
template Snapshot CreateTestSnapshot<AArch64>(
    TestSnapshot type, CreateTestSnapshotOptions options);

template <typename Arch>
proto::Snapshot CreateTestSnapshotProto(TestSnapshot type,
                                        CreateTestSnapshotOptions options) {
  const Snapshot snapshot = CreateTestSnapshot<Arch>(type, options);
  proto::Snapshot proto;
  SnapshotProto::ToProto(snapshot, &proto);
  return proto;
}

template proto::Snapshot CreateTestSnapshotProto<X86_64>(
    TestSnapshot type, CreateTestSnapshotOptions options);
template proto::Snapshot CreateTestSnapshotProto<AArch64>(
    TestSnapshot type, CreateTestSnapshotOptions options);

}  // namespace silifuzz.
