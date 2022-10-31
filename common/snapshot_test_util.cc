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

#include "absl/base/attributes.h"
#include "absl/base/internal/endian.h"
#include "./common/snapshot_printer.h"
#include "./common/snapshot_proto.h"
#include "./common/snapshot_test_config.h"
#include "./common/snapshot_util.h"
#include "./proto/snapshot.pb.h"
#include "./util/padding.h"
#include "./util/ucontext/ucontext.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

static void InitTestSnapshotRegs(const TestSnapshotConfig& config,
                                 UContext<X86_64>& ucontext) {
  SaveUContext(&ucontext);
  ZeroOutRegsPadding(&ucontext);
  memset(ucontext.fpregs.st, 0, sizeof(ucontext.fpregs.st));
  memset(ucontext.fpregs.xmm, 0, sizeof(ucontext.fpregs.xmm));

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
  ucontext.gregs.rsp = kCanary;
  ucontext.gregs.rip = kCanary;

  ucontext.gregs.eflags = 0x202;
  // Intentionally leaving all segment registers untouched. They are much more
  // sensitive to the choice of value and are typically not touched by
  // user-space code.

  ucontext.gregs.fs_base = 0;
  ucontext.gregs.gs_base = 0;

  // Sets RIP and RSP to be within the memory of this snapshot.
  ucontext.gregs.rip = config.code_addr;
  ucontext.gregs.rsp = config.data_addr + config.data_num_bytes;
  // Set RBP to the start of the data page;
  ucontext.gregs.rbp = config.data_addr;
}

// static
Snapshot TestSnapshots::Create(Type type, Options options) {
  // Currently only x86_64 is supported.
  CHECK(Snapshot::CurrentArchitecture() == Architecture::kX86_64);

  const TestSnapshotConfig& config = GetTestSnapshotConfig(type);

  Snapshot snapshot(Snapshot::CurrentArchitecture());
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
    PadToSizeWithTraps<X86_64>(bytecode, code_mapping.num_bytes());
  }

  if (!bytecode.empty()) {
    MemoryBytes code_bytes(config.code_addr, bytecode);
    snapshot.add_memory_bytes(code_bytes);
  }

  UContext ucontext;
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
    ucontext.gregs.rip = endpoint_address;
    RegisterState regs = ConvertRegsToSnapshot(ucontext.gregs, ucontext.fpregs);
    EndState end_state(endpoint, regs);
    if (type == kHasPlatformMismatch) {
      EndState bogus_end_state(Endpoint(endpoint_address + 1), regs);
      bogus_end_state.add_platform(CurrentPlatformId());
      snapshot.add_expected_end_state(bogus_end_state);
      end_state.add_platform(PlatformId::kNonExistent);
      snapshot.add_expected_end_state(end_state);
    } else {
      end_state.add_platform(CurrentPlatformId());
      snapshot.add_expected_end_state(end_state);
    }
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

// static
proto::Snapshot TestSnapshots::CreateProto(Type type, Options options) {
  const Snapshot snapshot = Create(type, options);
  proto::Snapshot proto;
  SnapshotProto::ToProto(snapshot, &proto);
  return proto;
}

// static
void TestSnapshots::Log(const Snapshot& snapshot) {
  LinePrinter error_printer(LinePrinter::LogInfoPrinter);
  auto opt = SnapshotPrinter::DefaultOptions();
  opt.fp_regs_mode = SnapshotPrinter::kAllFPRegs;
  SnapshotPrinter printer(&error_printer, opt);
  printer.Print(snapshot);
}

// static
std::string TestSnapshots::ToString(const Snapshot& snapshot) {
  std::string result;
  LinePrinter error_printer(LinePrinter::StringPrinter(&result));
  auto opt = SnapshotPrinter::DefaultOptions();
  opt.fp_regs_mode = SnapshotPrinter::kAllFPRegs;
  SnapshotPrinter printer(&error_printer, opt);
  printer.Print(snapshot);
  return result;
}

}  // namespace silifuzz.
