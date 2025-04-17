// Copyright 2025 The SiliFuzz Authors.
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

#include "./tracing/native_tracer.h"

#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/user.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <utility>

#include "absl/crc/crc32c.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./common/harness_tracer.h"
#include "./common/mapped_memory_map.h"
#include "./common/memory_perms.h"
#include "./common/proxy_config.h"
#include "./common/snapshot.h"
#include "./common/snapshot_enums.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/make_snapshot.h"
#include "./runner/runner_provider.h"
#include "./tracing/extension_registers.h"
#include "./tracing/tracer.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/page_util.h"
#include "./util/ptrace_util.h"
#include "./util/reg_group_io.h"
#include "./util/reg_groups.h"
#include "./util/sve_constants.h"
#include "./util/ucontext/serialize.h"
#include "./util/ucontext/ucontext_types.h"
#include "./util/user_regs_util.h"

namespace silifuzz {

namespace {

#if defined(__x86_64__)
using UserFPRegsStruct = user_fpregs_struct;
#elif defined(__aarch64__)
using UserFPRegsStruct = user_fpsimd_struct;
#else
#error "Unsupported architecture"
#endif

void SetGRegs(const pid_t pid, user_regs_struct& regs) {
  struct iovec io{&regs, sizeof(regs)};
  PTraceOrDie(PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &io);
}

void GetFPRegs(const pid_t pid, UserFPRegsStruct& fp_regs) {
  struct iovec io = {&fp_regs, sizeof(fp_regs)};
  PTraceOrDie(PTRACE_GETREGSET, pid, (void*)NT_PRFPREG, &io);
};

void SetFPRegs(const pid_t pid, UserFPRegsStruct& fp_regs) {
  struct iovec io = {&fp_regs, sizeof(fp_regs)};
  PTraceOrDie(PTRACE_SETREGSET, pid, (void*)NT_PRFPREG, &io);
};

#if defined(__x86_64__)
// Enough to store all AVX512 components.
// Copy from X86_XSTATE_AVX512_SIZE in "gdb/common/x86-xstate.h"
constexpr size_t kXStateBufferSize = 2688;
// TODO(herooutman): Currently, we use another ptrace call to get FPRegs. Since
// XState always contains FPRegs, we can get them from XState and save the
// redundant ptrace call.
void GetX86XState(const pid_t pid, RegisterGroupIOBuffer<Host>& eregs) {
  eregs.register_groups =
      GetCurrentPlatformRegisterGroups().SetGPR(0).SetFPRAndSSE(0);
  if (!eregs.register_groups.GetAVX512() && !eregs.register_groups.GetAVX()) {
    VLOG_INFO(2,
              "Skipping XState collection because AVX and AVX512 are not "
              "enabled.");
    return;
  }
  alignas(64) uint8_t host_xstate[kXStateBufferSize] = {};
  alignas(64) uint8_t tracee_xstate[kXStateBufferSize] = {};

  struct iovec io = {tracee_xstate, kXStateBufferSize};
  PTraceOrDie(PTRACE_GETREGSET, pid, (void*)NT_X86_XSTATE, &io);

  SaveX86XState(tracee_xstate, host_xstate, eregs);
}
#endif

#if defined(__aarch64__)
void GetSVE(const pid_t pid, RegisterGroupIOBuffer<Host>& eregs) {
  // SVE_PT_SIZE(vq, flags) calculates the total size of the state in bytes. The
  // flags are set to 0x1 here indicating SVE is enabled. See <asm/ptrace.h> for
  // more details.
  constexpr size_t kMaxSVEStateSize = SVE_PT_SIZE(kSveZRegMaxSizeBytes / 16, 1);
  uint8_t data[kMaxSVEStateSize]{};

  struct iovec io = {data, kMaxSVEStateSize};
  PTraceOrDie(PTRACE_GETREGSET, pid, (void*)NT_ARM_SVE, &io);

  // Double-check the PTrace-returned state header matches our expectations.
  const user_sve_header* header =
      reinterpret_cast<const user_sve_header*>(data);
  CHECK_GE(kMaxSVEStateSize, header->size);
  if ((header->flags & SVE_PT_REGS_MASK) != SVE_PT_REGS_SVE ||
      header->vl == 0) {
    VLOG_INFO(2, "SVE is not supported!");
    return;
  }
  eregs.register_groups.SetSVEVectorWidth(header->vl);
  const size_t vq = header->vl / 16;

  memcpy(eregs.z, data + SVE_PT_SVE_ZREGS_OFFSET, SVE_PT_SVE_ZREGS_SIZE(vq));
  memcpy(eregs.p, data + SVE_PT_SVE_PREGS_OFFSET(vq),
         SVE_PT_SVE_PREGS_SIZE(vq));
  memcpy(eregs.ffr, data + SVE_PT_SVE_FFR_OFFSET(vq), SVE_PT_SVE_FFR_SIZE(vq));
}

void GetTLSRegs(const pid_t pid, uint64_t* data) {
  struct iovec io = {data, sizeof(*data)};
  PTraceOrDie(PTRACE_GETREGSET, pid, (void*)NT_ARM_TLS, &io);
};

void SetTLSRegs(const pid_t pid, uint64_t data) {
  struct iovec io = {&data, sizeof(data)};
  PTraceOrDie(PTRACE_SETREGSET, pid, (void*)NT_ARM_TLS, &io);
};
#endif

void DeserializeUserRegsStruct(const user_regs_struct& regs,
                               GRegSet<Host>* dst) {
#if defined(__x86_64__)
  // This abuses the fact that the legacy format is a byte dump of
  // user_regs_struct.
  CHECK_EQ(
      serialize_internal::DeserializeGRegs<X86_64>(&regs, sizeof(regs), dst),
      sizeof(regs));
#elif defined(__aarch64__)
  for (size_t i = 0; i < 31; ++i) {
    dst->x[i] = regs.regs[i];
  }
  dst->sp = regs.sp;
  dst->pc = regs.pc;
  dst->pstate = regs.pstate & kPStateMask;
#else
  LOG_FATAL(
      "DeserializeUserRegsStruct is not supported only on this architecture");
#endif
}

void SerializeUserRegsStruct(const GRegSet<Host>& regs, user_regs_struct* dst) {
#if defined(__x86_64__)
  // This abuses the fact that the legacy format is a byte dump of
  // user_regs_struct.
  CHECK_EQ(serialize_internal::SerializeLegacyGRegs(regs, dst, sizeof(*dst)),
           sizeof(*dst));
#elif defined(__aarch64__)
  for (size_t i = 0; i < 31; ++i) {
    dst->regs[i] = regs.x[i];
  }
  dst->sp = regs.sp;
  dst->pc = regs.pc;
  dst->pstate = regs.pstate;
#else
  LOG_FATAL("SerializeUserRegsStruct is not supported on this architecture");
#endif
}

void SerializeUserFPRegsStruct(const FPRegSet<Host>& fp_reg_set,
                               UserFPRegsStruct* dst) {
#if defined(__x86_64__)
  CHECK_EQ(
      serialize_internal::SerializeLegacyFPRegs(fp_reg_set, dst, sizeof(*dst)),
      sizeof(*dst));
#elif defined(__aarch64__)
  for (size_t i = 0; i < 32; ++i) {
    dst->vregs[i] = fp_reg_set.v[i];
  }
  dst->fpsr = fp_reg_set.fpsr;
  dst->fpcr = fp_reg_set.fpcr;
#else
  LOG_FATAL("SerializeUserRegsStruct is not supported on this architecture");
#endif
}

void DeserializeUserFPRegsStruct(const UserFPRegsStruct& fp_regs,
                                 FPRegSet<Host>* dst) {
#if defined(__x86_64__)
  CHECK_EQ(serialize_internal::DeserializeFPRegs<X86_64>(&fp_regs,
                                                         sizeof(fp_regs), dst),
           sizeof(fp_regs));
#elif defined(__aarch64__)
  for (size_t i = 0; i < 32; ++i) {
    dst->v[i] = fp_regs.vregs[i];
  }
  dst->fpsr = fp_regs.fpsr;
  dst->fpcr = fp_regs.fpcr;
#else
  LOG_FATAL(
      "DeserializeUserFPRegsStruct is not supported on this architecture");
#endif
}

}  // namespace

absl::Status NativeTracer::InitSnippet(
    absl::string_view instructions, const TracerConfig<Host>& tracer_config,
    const FuzzingConfig<Host>& fuzzing_config) {
  ASSIGN_OR_RETURN_IF_NOT_OK(
      Snapshot snapshot,
      MakeRawInstructions(instructions, MakingConfig::Quick(RunnerLocation())));
  snapshot_ = std::make_unique<Snapshot>(std::move(snapshot));

  code_start_address_ = snapshot_->ExtractRip(snapshot_->registers());
  CHECK_EQ(snapshot_->expected_end_states().size(), 1);
  code_end_address_ =
      snapshot_->expected_end_states()[0].endpoint().instruction_address();
  VLOG_INFO(
      2, "Finish making snapshot, start address: ", HexStr(code_start_address_),
      " end address: ", HexStr(code_end_address_));
  state_ = TracerState::kReady;
  VLOG_INFO(1, "entering ready state");
  return absl::OkStatus();
};

absl::Status NativeTracer::Run(size_t max_insn_executed) {
  CHECK(state_ == TracerState::kReady);
  state_ = TracerState::kPreTracing;
  VLOG_INFO(1, "entering pre-tracing state");
  // TODO(herooutman): consider to add runner location to tracer config.
  ASSIGN_OR_RETURN_IF_NOT_OK(
      RunnerDriver runner_driver,
      RunnerDriverFromSnapshot(*snapshot_, RunnerLocation()));

  // Need to initialize the register group IO library before using
  // RegisterGroupIOBuffer.
  InitRegisterGroupIO();
  size_t traced_insn_count = 0;
  absl::StatusOr<RunnerDriver::RunResult> run_result = runner_driver.TraceOne(
      snapshot_->id(),
      [&](pid_t pid, const user_regs_struct& regs,
          HarnessTracer::CallbackReason reason)
          -> HarnessTracer::ContinuationMode {
        if (pid_ == 0) pid_ = pid;
        if (reason != HarnessTracer::kSingleStepStop || ShouldStopTracing())
          return NextContinuationMode();

        uint64_t addr = GetIPFromUserRegs(regs);
        gregs_cache_.emplace(regs);
        if (state_ == TracerState::kPreTracing) {
          if (addr == code_start_address_) {
            // Note that the start address can be reached multiple times. Only
            // invoke the BeforeExecution callback the first time.
            BeforeExecution();
            // Always get the latest instruction pointer, as user callbacks may
            // change the value.
            addr = GetInstructionPointer();
            VLOG_INFO(1, "entering tracing state at ", HexStr(addr));
            state_ = TracerState::kTracing;
          } else if (IsInsideCode(addr)) {
            LOG_FATAL("Tracer touches user code at ", HexStr(addr),
                      " before reaching start address ",
                      HexStr(code_start_address_));
          }
        }
        if (state_ == TracerState::kTracing) {
          // BeforeInstruction() is invoked only when addr is pointing to test
          // instructions, and the instruction limit is not reached. In the edge
          // case of empty code, the instruction limit is not reached, and
          // BeforeInstruction() is not invoked.
          if (IsInsideCode(addr) && !stop_requested_) {
            if (++traced_insn_count > max_insn_executed) {
              insn_limit_reached_ = true;
            } else {
              BeforeInstruction();
              addr = GetInstructionPointer();
            }
          }
          if (!IsInsideCode(addr) || stop_requested_) {
            AfterExecution();
            VLOG_INFO(1, "entering finished state at ", HexStr(addr));
            state_ = TracerState::kFinished;
          }
        }
        CHECK(state_ == TracerState::kPreTracing ||
              state_ == TracerState::kTracing ||
              state_ == TracerState::kFinished)
            << absl::StrCat(
                   "Tracer touches user code at ", HexStr(addr),
                   " in an unexpected state: ", static_cast<int>(state_));
        return NextContinuationMode();
      },
      1);
  // Make sure the runner execution was successful.
  RETURN_IF_NOT_OK(run_result.status());
  VLOG_INFO(1, "Native tracer finished tracing with runner execution_result: ",
            run_result->execution_result().DebugString());
  if (!run_result->success()) {
    if (run_result->has_failed_player_result()) {
      switch (run_result->failed_player_result().outcome) {
        // Exclude end state mismatches error.
        case PlaybackOutcome::kAsExpected:
        case PlaybackOutcome::kMemoryMismatch:
        case PlaybackOutcome::kRegisterStateMismatch:
        case PlaybackOutcome::kEndpointMismatch:
          return absl::OkStatus();
        case PlaybackOutcome::kExecutionRunaway:
        case PlaybackOutcome::kExecutionMisbehave:
        default:
          return absl::InternalError("Snapshot did not finish as expected");
      }
    }
    return absl::InternalError("Snapshot failed to run");
  }
  if (insn_limit_reached_) {
    return absl::InternalError("Reached instruction limit.");
  }
  return absl::OkStatus();
}

void NativeTracer::ReadMemory(uint64_t address, void* buffer, size_t size) {
  struct iovec remote_iov, local_iov;
  remote_iov.iov_base = (void*)address;
  remote_iov.iov_len = size;
  local_iov.iov_base = buffer;
  local_iov.iov_len = size;
  ssize_t num_read = process_vm_readv(pid_, &local_iov, 1, &remote_iov, 1, 0);
  if (num_read == -1) {
    LOG_FATAL("process_vm_readv failed on process #", pid_, " at address ",
              HexStr(address), ": ", strerror(errno));
  }
  CHECK_EQ(size, num_read) << absl::StrCat(
      "process_vm_readv partial read, start address: ", HexStr(address),
      " size: ", size);
}

void NativeTracer::SetRegisters(const UContext<Host>& ucontext) {
  struct user_regs_struct regs;
  SerializeUserRegsStruct(ucontext.gregs, &regs);
  SetGRegs(pid_, regs);
#if defined(__aarch64__)
  SetTLSRegs(pid_, ucontext.gregs.tpidr);
#endif

  UserFPRegsStruct fp_regs;
  // On arm, user_fpsimd_struct has implicit alignment padding because
  // __uint128_t is 16-byte aligned. Memset the entire struct to avoid msan
  // complaints about reading uninitialized memory.
  memset(&fp_regs, 0, sizeof(fp_regs));
  SerializeUserFPRegsStruct(ucontext.fpregs, &fp_regs);
  SetFPRegs(pid_, fp_regs);

  // Ptrace may silently discard some bits of the register state.  If this
  // happens, the subsequent GetRegisters() call will return different data.
  // Reset the cache to force a refetch.
  gregs_cache_.reset();
}

void NativeTracer::GetRegisters(UContext<Host>& ucontext,
                                RegisterGroupIOBuffer<Host>* eregs) {
  const user_regs_struct& regs = GetGRegStruct();
  // Not all registers will be read. memset so the result is consistent.
  memset(&ucontext, 0, sizeof(ucontext));
  DeserializeUserRegsStruct(regs, &ucontext.gregs);
#if defined(__aarch64__)
  GetTLSRegs(pid_, &ucontext.gregs.tpidr);
  // tpidrro is not easily accessible using ptrace.
#endif

  UserFPRegsStruct fp_regs;
  GetFPRegs(pid_, fp_regs);
  DeserializeUserFPRegsStruct(fp_regs, &ucontext.fpregs);

  if (eregs != nullptr) {
    memset(eregs, 0, sizeof(*eregs));
#if defined(__x86_64__)
    GetX86XState(pid_, *eregs);
#elif defined(__aarch64__)
    GetSVE(pid_, *eregs);
#endif
  }
}

void NativeTracer::SetInstructionPointer(uint64_t address) {
  user_regs_struct regs = GetGRegStruct();
#if defined(__x86_64__)
  regs.rip = address;
  gregs_cache_.value().rip = address;
#elif defined(__aarch64__)
  regs.pc = address;
  gregs_cache_.value().pc = address;
#endif
  SetGRegs(pid_, regs);
}

uint64_t NativeTracer::GetInstructionPointer() {
  return GetIPFromUserRegs(GetGRegStruct());
}

uint64_t NativeTracer::GetStackPointer() {
  return GetSPFromUserRegs(GetGRegStruct());
}

uint32_t NativeTracer::PartialChecksumOfMutableMemory() {
  absl::crc32c_t checksum(0);
  // Empirically, checksumming the first 8 pages of each mutable region
  // covers ~58% of the pages the proxy tends to dirty. Doubling this
  // raises the coverage to 59%. Beyond the first few pages, the access
  // patterns are fairly unpredictable, so we'd need to checksum vastly
  // more memory to catch all the dirty pages. Unfortunately checksumming
  // all the mutable memory on x86_64 would make fault injection ~18x
  // slower. So we're trading some accuracy for a huge amount of speed.
  char data[kPageSize * 8];
  snapshot_->mapped_memory_map().Iterate([&](snapshot_types::Address start,
                                             snapshot_types::Address limit,
                                             MemoryPerms perms) {
    if (!perms.Has(MemoryPerms::kWritable)) return;
    memset(data, 0, sizeof(data));
    ReadMemory(start, data, std::min(sizeof(data), limit - start));
    checksum =
        absl::ExtendCrc32c(checksum, absl::string_view(data, sizeof(data)));
  });
  return static_cast<uint32_t>(checksum);
}

const user_regs_struct& NativeTracer::GetGRegStruct() {
  if (!gregs_cache_.has_value()) {
    gregs_cache_.emplace(user_regs_struct{});
    struct iovec io;
    io.iov_base = &gregs_cache_.value();
    io.iov_len = sizeof(gregs_cache_.value());
    // NT_PRSTATUS means read the general purpose registers.
    PTraceOrDie(PTRACE_GETREGSET, pid_, (void*)NT_PRSTATUS, &io);
    CHECK_EQ(io.iov_len, sizeof(gregs_cache_.value()));
  }
  return *gregs_cache_;
}

}  // namespace silifuzz
