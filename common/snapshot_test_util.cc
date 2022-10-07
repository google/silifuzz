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

#include <string>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/base/internal/endian.h"
#include "./common/snapshot_printer.h"
#include "./common/snapshot_proto.h"
#include "./common/snapshot_util.h"
#include "./proto/snapshot.pb.h"
#include "./util/ucontext/ucontext.h"
#include "./util/ucontext/ucontext_types.h"

#define DECLARE_SNAPSHOT(name)           \
  extern "C" char snapshot_begin_##name; \
  extern "C" char snapshot_end_##name;

// Expands to an std::string containing the machine code for `code`.
// `code` must be a string literal compatible with asm() statement.
#define DEFINE_SNAPSHOT(name, code)                                       \
  [=]() {                                                                 \
    asm("jmp snapshot_end_" #name                                         \
        ";\n"                                                             \
        "snapshot_begin_" #name ":\n" code ";snapshot_end_" #name ":\n"); \
    int length = (&snapshot_end_##name - &snapshot_begin_##name);         \
    return std::string(&snapshot_begin_##name, length);                   \
  }()

namespace silifuzz {

template <>
ABSL_CONST_INIT const char*
    EnumNameMap<TestSnapshots::Type>[ToInt(TestSnapshots::kSplitLock) + 1] = {
        "kEmpty",
        "kEndsAsExpected",
        "kHasPlatformMismatch",
        "kEndsUnexpectedly",
        "kRegsMismatch",
        "kMemoryMismatch",
        "kRegsAndMemoryMismatch",
        "kRegsMismatchRandom",
        "kMemoryMismatchRandom",
        "kRegsAndMemoryMismatchRandom",
        "kICEBP",
        "kINT3",
        "kINT3_CD03",
        "kSigIll",
        "kSigSegvWrite",
        "kSigSegvRead",
        "kSigSegvExec",
        "kSyscall",
        "kGeneralProtectionFault",
        "kChangesSegmentReg",
        "kIn",
        "kRunaway",
        "kSplitLock",
};

// static
bool TestSnapshots::HasNormalEndState(Type type) {
  switch (type) {
    case kEndsAsExpected:
    case kHasPlatformMismatch:
    case kRegsMismatch:
    case kMemoryMismatch:
    case kRegsAndMemoryMismatch:
    case kRegsMismatchRandom:
    case kMemoryMismatchRandom:
    case kRegsAndMemoryMismatchRandom:
    case kChangesSegmentReg:
    case kSyscall:
    case kSplitLock:
      return true;
    default:
      return false;
  }
}

DECLARE_SNAPSHOT(kEndsAsExpected);
DECLARE_SNAPSHOT(kRegsMismatch);
DECLARE_SNAPSHOT(kRegsMismatchRandom);
DECLARE_SNAPSHOT(kSigSegvWrite);
DECLARE_SNAPSHOT(kSigSegvRead);
DECLARE_SNAPSHOT(kSigSegvExec);
DECLARE_SNAPSHOT(kSyscall);
DECLARE_SNAPSHOT(kGeneralProtectionFault);
DECLARE_SNAPSHOT(kRunaway);
DECLARE_SNAPSHOT(kMemoryMismatch);
DECLARE_SNAPSHOT(kMemoryMismatchRandom);
DECLARE_SNAPSHOT(kRegsAndMemoryMismatchRandom);
DECLARE_SNAPSHOT(kRegsAndMemoryMismatch);
DECLARE_SNAPSHOT(kSigIll);
DECLARE_SNAPSHOT(kINT3);
DECLARE_SNAPSHOT(kChangesSegmentReg);
DECLARE_SNAPSHOT(kIn);
DECLARE_SNAPSHOT(kSplitLock);

static void InitTestSnapshotRegs(UContext<X86_64>& ucontext) {
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
}

// static
Snapshot TestSnapshots::Create(Type type, Options options) {
  // Currently only x86_64 is supported.
  CHECK(Snapshot::CurrentArchitecture() == Architecture::kX86_64);

  Snapshot snapshot(Snapshot::CurrentArchitecture());
  snapshot.set_id(EnumStr(type));

  // Assign statically a block of kMaxPagesPerTest pages to each test
  // snapshot so that test snapshots do not overlap.
  constexpr size_t kMaxPagesPerTest = 16;

  // Page number (i.e. address / page size) at the beginning of memory
  // region used by test snapshots.
  // Note: this value is chosen to avoid conflicts with ASAN.
  constexpr uint64_t kTestSnapshotsRegionBase = 0x12345;

  const int page_size = snapshot.page_size();
  const Address base_address =
      (kTestSnapshotsRegionBase + ToInt(type) * kMaxPagesPerTest) * page_size;

  // Creates memory regions at base_address for code and data.
  // The base_address variations and kRegionSize value are such as
  // to exercise the MemoryState::Delta*() logic.
  const auto kRegionSize = 2 * page_size;
  auto code_mapping =
      MemoryMapping::MakeSized(base_address, page_size, MemoryPerms::XR());
  snapshot.add_memory_mapping(code_mapping);
  auto data_mapping = MemoryMapping::MakeSized(
      base_address + page_size, kRegionSize - page_size, MemoryPerms::RW());
  snapshot.add_memory_mapping(data_mapping);

  // Populate the data page with the 3 user-defined data pieces. These can be
  // addressed relative to RBP by the snapshots.
  ByteData addresses_data = ByteData(8 * 3, '\0');
  absl::little_endian::Store64(addresses_data.data(), options.read_address);
  absl::little_endian::Store64(addresses_data.data() + 8,
                               options.write_address);
  absl::little_endian::Store64(addresses_data.data() + 16,
                               options.exec_address);

  // Where rsp will be in the snapshot:
  const Address stack_top_address = data_mapping.limit_address();

  // An online assembler like defuse.ca/online-x86-assembler.htm is very helpful
  // for generating the x64 `bytecode` here.
  // We use Intel syntax (dest, src order) in the comments for `bytecode`.
  std::string bytecode;
  std::optional<MemoryBytes> data_bytes;
  switch (type) {
    case kEmpty:
      break;
    case kEndsAsExpected:
    case kHasPlatformMismatch:
      bytecode = DEFINE_SNAPSHOT(kEndsAsExpected, "nop");
      break;
    case kEndsUnexpectedly:
      // The endpoint generated below has address that is after the last
      // instruction byte of `bytecode`. By making code be the trap instruction,
      // we guarantee that the actual endpoint instruction address will not
      // match the expected one.
      //
      // Currently this is the same `bytecode` as for kINT3 below because of
      // how we implement endpoint detection. However, the intentions
      // behind kINT3 and kEndsUnexpectedly are different.
      bytecode = snapshot.trap_instruction();
      break;
    case kRegsMismatch:
      // rsp has non-0 bits so, this modifies rax:
      bytecode = DEFINE_SNAPSHOT(kRegsMismatch, "xor %rsp, %rax");
      break;
    case kMemoryMismatch:
      // Specify the initial state of the memory that the snapshot writes
      // -- see comments on proto.Snapshot.memory_bytes for details.
      // (Same is done for other snapshots below that modify memory.)
      data_bytes =
          MemoryBytes(stack_top_address - 8 * 3, ByteData(8 * 3, '\0'));
      // Registers are kept unchanged.
      bytecode = DEFINE_SNAPSHOT(kMemoryMismatch,
                                 // save flags
                                 "pushfq;"
                                 "push %rax;"
                                 "xor %rax, %rax;"
                                 // make RAX -1
                                 "not %rax;"
                                 // put non-0 RAX into stack thus mutating
                                 // the 0-initialized memory.
                                 "push %rax;"
                                 // restore registers and flags
                                 "pop %rax;pop %rax;"
                                 "popfq;");
      break;
    case kRegsAndMemoryMismatch:
      data_bytes = MemoryBytes(stack_top_address - 8, ByteData(8, '\0'));
      bytecode = DEFINE_SNAPSHOT(
          kRegsAndMemoryMismatch,
          // deterministically mutate regs and memory
          "xor %rsp, %rbx; xor %rax, %rax; not %rax; push %rax");
      break;
    case kRegsMismatchRandom:
      // The snapshot looks at CPUID (non-deterministic but stable) and then
      // runs RDRAND %RAX if supported else RDTSC. This ensures this snapshot
      // produces a random value in %EAX under Unicorn (does not support
      // RDRAND), on all production platforms and under seccomp(2) which
      // disables RDTSC(P) via CR4.TSD.
      bytecode =
          DEFINE_SNAPSHOT(kRegsMismatchRandom,
                          "movq $0x1, %rax;"
                          "cpuid;"
                          // Check RDRAND bit (CPUID.01H:ECX.RDRAND[bit 30]).
                          "andl $(1 << 30), %ecx;"
                          "jz 1f;"
                          "rdrand %rax;"
                          "jmp 2f;"
                          "1: rdtsc;"
                          "2:;");
      break;
    case kMemoryMismatchRandom:
      // Registers are kept unchanged.
      data_bytes =
          MemoryBytes(stack_top_address - 8 * 3, ByteData(8 * 3, '\0'));
      bytecode =
          DEFINE_SNAPSHOT(kMemoryMismatchRandom,
                          // save flags and registers
                          "pushfq;push %rax; push %rdx;"
                          // place a random number in edx:eax
                          "rdtsc;"
                          // put the random value onto stack  thus guaranteeing
                          // there's a random value on the stack that can never
                          // be matched by any expected memory state.
                          "push %rax;"
                          // restore registers and flags
                          "pop %rax;pop %rdx; pop %rax; popfq");
      break;
    case kRegsAndMemoryMismatchRandom:
      data_bytes = MemoryBytes(stack_top_address - 8, ByteData(8, '\0'));
      bytecode = DEFINE_SNAPSHOT(kRegsAndMemoryMismatchRandom,
                                 // place a random number in EAX:EDX and stack
                                 "rdtsc; push %rax");
      break;
    case kICEBP:
      bytecode = {0xF1};  // ICEBP
      break;
    case kINT3:
      // Note that this is the same `bytecode` as snapshot.trap_instruction().
      bytecode = DEFINE_SNAPSHOT(kINT3, "int3");
      break;
    case kINT3_CD03:
      bytecode = {0xCD, 0x03};  // INT 3 encoded as cd 03
      break;
    case kSigIll:
      bytecode = DEFINE_SNAPSHOT(kSigIll, "ud2");
      break;
    case kSigSegvWrite:
      bytecode = DEFINE_SNAPSHOT(kSigSegvWrite,
                                 "movq 8(%rbp), %rax; mov %rbx, 0(%rax)");
      break;
    case kSigSegvRead:
      bytecode = DEFINE_SNAPSHOT(kSigSegvRead,
                                 "movq 0(%rbp), %rax; mov 0(%rax), %rbx");
      break;
    case kSigSegvExec:
      bytecode =
          DEFINE_SNAPSHOT(kSigSegvExec, "movq 16(%rbp), %rax; jmp *%rax");
      break;
    case kSyscall:
      bytecode = DEFINE_SNAPSHOT(kSyscall,
                                 "xor %rsi, %rsi; xor %rdi, %rdi;"
                                 // 0x135 == 309 == SYS_getcpu
                                 "mov $0x135, %rax;"
                                 "syscall; "
                                 // erases any result whatever it may be so that
                                 // the snapshot always ends deterministically
                                 "xor %rax, %rax");
      break;
    case kChangesSegmentReg:
      bytecode = DEFINE_SNAPSHOT(kChangesSegmentReg,
                                 // The 0x3 value matters here. There choice
                                 // of possible values is limited by LDT/GDT.
                                 // Values <= 3 are always fair game according
                                 // to the ISA though.
                                 // CS can only be loaded with a RET. SS is
                                 // very special wrt checks performed by the CPU
                                 "movw $0x3, %ax;"
                                 "movw %ax, %es;"
                                 "movw %ax, %ds;"
                                 "movw %ax, %gs;"
                                 "movw %ax, %fs;");
      break;
    case kGeneralProtectionFault:
      // fxsave requires dst to be 16-aligned otherwise #GP
      // The code is placed at `base_address` which is page-aligned
      DCHECK_NE((base_address + 1) % 16, 0);
      bytecode = DEFINE_SNAPSHOT(kGeneralProtectionFault, "fxsave 1(%rip)");
      break;
    case kIn:
      bytecode = DEFINE_SNAPSHOT(kIn, "in %dx, %eax");
      break;
    case kRunaway:
      // A trivial infinite loop (can only have one end-point rip value when
      // interrupted):
      // JMP . -- jumps to itself
      bytecode = DEFINE_SNAPSHOT(kRunaway, "jmp .");
      break;
    case kSplitLock:
      bytecode =
          DEFINE_SNAPSHOT(kSplitLock,
                          // x86 L1 cache line size is 64b typically. Just in
                          // case future CPUs have wider cache lines, align down
                          // to 256b boundary from stack top.
                          "movq %rsp, %rax;"
                          "dec %rax;"
                          "xorb %al,%al;"
                          "lock incl -1(%rax)");
      break;
  }
  snapshot.add_memory_bytes(
      MemoryBytes(data_mapping.start_address(), addresses_data));
  if (data_bytes.has_value()) {
    snapshot.add_memory_bytes(data_bytes.value());
  }

  if (options.define_all_mapped) {
    Address start = data_mapping.start_address() + addresses_data.size();
    int size = data_mapping.num_bytes() - addresses_data.size() -
               (data_bytes.has_value() ? data_bytes.value().num_bytes() : 0);
    snapshot.add_memory_bytes(MemoryBytes(start, ByteData(size, '\0')));
  }

  const auto bytecode_size = bytecode.size();  // so we can ignore the fix-up
                                               // under the next if
  if (bytecode.empty()) {
    // Put something non-empty into snapshot to make it valid,
    // endpoint_address below will still be at base_address.
    bytecode = {0x0};
  }
  MemoryBytes code_bytes(base_address, bytecode);
  snapshot.add_memory_bytes(code_bytes);
  if (options.define_all_mapped) {
    ByteData trap = snapshot.trap_instruction();
    DCHECK_EQ(trap.size(), 1);
    snapshot.add_memory_bytes(MemoryBytes(
        base_address + code_bytes.num_bytes(),
        ByteData(code_mapping.num_bytes() - code_bytes.num_bytes(), trap[0])));
  }

  UContext ucontext;
  InitTestSnapshotRegs(ucontext);
  // Sets RIP and RSP to be within the memory of this snapshot.
  ucontext.gregs.rip = base_address;
  ucontext.gregs.rsp = stack_top_address;
  // Set RBP to the start of the data page;
  ucontext.gregs.rbp = data_mapping.start_address();

  snapshot.set_registers(
      ConvertRegsToSnapshot(ucontext.gregs, ucontext.fpregs));

  // We are expecting `bytecode` to execute fully:
  const uintptr_t endpoint_address = base_address + bytecode_size;
  Endpoint endpoint(endpoint_address);
  if (options.force_normal_state ||
      (HasNormalEndState(type) && !options.force_undefined_state)) {
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
