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

#include "./runner/runner.h"

#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/ucontext.h>
#include <ucontext.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <random>

#include "third_party/lss/lss/linux_syscall_support.h"
#include "./common/snapshot_enums.h"
#include "./runner/endspot.h"
#include "./runner/runner_main_options.h"
#include "./runner/runner_util.h"
#include "./runner/snap_runner_util.h"
#include "./snap/exit_sequence.h"
#include "./snap/snap.h"
#include "./snap/snap_checksum.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/cpu_id.h"
#include "./util/itoa.h"
#include "./util/logging_util.h"
#include "./util/mem_util.h"
#include "./util/misc_util.h"
#include "./util/page_util.h"
#include "./util/proc_maps_parser.h"
#include "./util/reg_checksum.h"
#include "./util/reg_group_io.h"
#include "./util/reg_group_set.h"
#include "./util/reg_groups.h"
#include "./util/text_proto_printer.h"
#include "./util/ucontext/serialize.h"
#include "./util/ucontext/signal.h"
#include "./util/ucontext/ucontext_types.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

// Snap runner binary.
//
// The process implements the following API to communicate with its parent:
//  stdout:   a single silifuzz.proto.SnapshotExecutionResult formatted as
//            text proto. In "run" mode this happens for the first failed snap,
//            in "make" mode the proto is always printed. This is intended to
//            be machine-readable.
//  stderr:   human-readable log messages. The verbosity is controlled by --v
//            with the following levels.
//             0: Quiet (default).
//             1: Log once-in-a-process-lifetime events/info
//                (e.g. process memory mappings).
//             2: Log per-Snap preparation info (memory mappings, etc).
//             3: Log every Snap being executed.
//  exit code: 0 for success i.e. the process ran the requested number of
//               iterations and all snapshots passed.
//             1 for any snap failure (stdout will contain the machine-readable
//               result).
//             2 graceful shutdown due to timeout.
//
//             TODO(ksteuck): [impl] an exit code for internal process failure
//               (mapping conflict, unmappable region, etc).
//
// Signal handling:
//
// This process supports receiving the following signals:
//    SIGALRM: the process exceeded its wall time limit.
//             The process will exit immediately with exit code 2 when this
//             signal is received.
//
//    SIGXCPU: the process exceeded its CPU time limit as set by setrlimit(2)
//             The process will exit immediately with exit code 2 when this
//             signal is received.
//
// This process can terminate with the following signals:
//    SIGKILL: the process was limited by setrlimit(2) and exceeded its
//             hard CPU bugdet or another process or the operating system
//             decided the process cannot continue.
//             Cannot be intercepted and always results in termination.
//
//    SIGSYS: a snap tried to make a syscall not allowed by seccomp(2) config.
//            Cannot be intercepted and always results in termination.
//
// When the runner is used in snap making, it handles the following signals:
//    SIGSEGV: If the fault is due to a missing page and the number of added
//             pages for snap making is below a preset limit, a new R/W data
//             page will be mapped to the page-aligned fault address and
//             execution resumes from the signal. Otherwise, the process will
//             terminate.
//
// In a typical setup this process will be limited by setrlimit(RLIMIT_CPU) and
// a much larger setitimer(ITIMER_REAL). The first SIGXCPU/SIGALRM will
// initiate a graceful process shutdown. Reaching hard cap on RLIMIT_CPU will
// trigger SIGKILL.

namespace silifuzz {

namespace {

using snapshot_types::Endpoint;
using snapshot_types::EndpointType;

// Number of data pages mapped by SIGSEGV handler during snap making.
// This is incremented every time a new data page is discovered during making.
size_t num_added_pages = 0;

// Maximum number of data pages mapped by SIGSEGV handler during snap making.
// This should only be non-zero when the runner is in make mode.
size_t max_pages_to_add = 0;

// Static limit of number of page addresses below.
constexpr size_t kMaxAddedPageAddresses = 20;

uint64_t added_page_addresses[kMaxAddedPageAddresses];

constexpr int kInitialMappingProtection = PROT_READ | PROT_WRITE;

// Attempts to recover from a SEGV fault due to missing mapping.
// Returns true iff the fault is recoverable by adding a new mapping.
bool TryToRecoverFromSignal(int signal, const siginfo_t& siginfo,
                            const ucontext_t& ucontext) {
  if (signal != SIGSEGV || siginfo.si_code != SEGV_MAPERR) {
    return false;
  }

  // Only fix up this SEGV fault if not fixing it would cause a SigCause
  // kSegvCantRead or kSegvCantWrite to be reported.
  SignalRegSet sig_reg_set;
  ConvertSignalRegsFromLibC(ucontext, &sig_reg_set);
  const snapshot_types::SigCause cause = SigSegvCause(sig_reg_set);
  if (cause != Endpoint::kSegvCantRead && cause != Endpoint::kSegvCantWrite) {
    return false;
  }

  // Check to see if we have reached the max number of mapped data pages.
  size_t real_max_pages_to_add =
      std::min(max_pages_to_add, kMaxAddedPageAddresses);
  if (num_added_pages >= real_max_pages_to_add) {
    return false;
  }

  // Map a new r/w data page containing the fault address.
  uint64_t fault_address = reinterpret_cast<uint64_t>(siginfo.si_addr);
  uint64_t fault_page_address = RoundDownToPageAlignment(fault_address);

  // This will mmap() any faulting addresses. We rely on high level code to
  // filter out bad mappings created by the runner during making.
  // The assumption here is that we can continue execution by mmapping a
  // missing data page whose address is in siginfo.si_addr. On the x86 with
  // User Mode Instruction Prevention (UMIP) enabled, some instructions are
  // emulated in software by the kernel. It is observed that the kernel does
  // not report the second page of a page crossing fault for an emulated SGDT
  // instruction. In that case, the code below will try to map the first page
  // of the fault twice and not able to continue execution as the second page
  // is never mapped. We use MAP_FIXED_NOREPLACE flag to prevent the runner from
  // mmapping to an existing page. This flag is supported since kernel
  // version 4.17.
  void* new_page = sys_mmap(
      AsPtr(fault_page_address), getpagesize(), PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED | MAP_FIXED_NOREPLACE, -1, 0);
  if (new_page == MAP_FAILED) {
    return false;
  }
  CHECK_EQ(new_page, AsPtr(fault_page_address));

  // Paranoia check to see if this page has been added before.
  for (size_t i = 0; i < num_added_pages; ++i) {
    CHECK_NE(added_page_addresses[i], fault_page_address);
  }
  added_page_addresses[num_added_pages] = fault_page_address;
  num_added_pages++;

  return true;
}

// The signal handler for the duration of the corpus execution.
// NOTE: even though this handler is installed for SIGSYS it will be
// ignored. See file-level comment.
void SigAction(int signal, siginfo_t* siginfo, void* uc) {
  // SIGALRM signals deadline from the orchestrator. Exit immediately.
  if (signal == SIGALRM) {
    _exit(2);
  }
  const ucontext_t* ucontext = reinterpret_cast<const ucontext_t*>(uc);
  if (IsInsideSnap()) {
    // If the signal is due to an unmapped page and we are allowed to map
    // pages, try resuming from the signal. This happens during snap making.
    // We only want to recover for SEGV_MAPERR since it is the only case that
    // we can fix by mapping a missing page. Other cases of SIGSEGV involve
    // permission errors related an existing page.
    if (TryToRecoverFromSignal(signal, *siginfo, *ucontext)) {
      return;
    }

    // The signal arrived while executing a snapshot -- blame it on the
    // snapshot itself.
    RunnerReentryFromSignal(*ucontext, *siginfo);
    __builtin_unreachable();
  }
  // A signal was not caused by any snapshot. If it is one of the
  // timeout signals we _exit(2). Otherwise crash.
  ASS_LOG_INFO("Received signal ", SignalNameStr(signal),
               " while outside of snap. Exiting");
  if (signal == SIGXCPU) {
    _exit(2);
  }
  // A signal occurred while executing the runner code. Most likely indicates
  // a bug in the runner or a signal from the environment (keyboard, RLIMIT).
  ASS_LOG_FATAL("Unhandled signal ", SignalNameStr(signal));
  __builtin_unreachable();
}

// Returns true iff current memory contents match memory byte data.
bool VerifyMemoryBytes(const SnapMemoryBytes& memory_bytes) {
  const void* address = AsPtr(memory_bytes.start_address);
  const size_t size = memory_bytes.size();
  return memory_bytes.repeating()
             ? MemAllEqualTo(address, memory_bytes.data.byte_run.value, size)
             : MemEq(address, memory_bytes.data.byte_values.elements, size);
}

// Copies memory bytes from Snap to runtime address.
void SetupMemoryBytes(const SnapMemoryBytes& memory_bytes) {
  void* target_address = AsPtr(memory_bytes.start_address);
  if (memory_bytes.repeating()) {
    MemSet(target_address, memory_bytes.data.byte_run.value,
           memory_bytes.size());
  } else {
    MemCopy(target_address, memory_bytes.data.byte_values.elements,
            memory_bytes.size());
  }
}

void CheckFixedMmapOK(void* mapped_address, void* target_address) {
  if (mapped_address == MAP_FAILED) {
    LOG_FATAL("mmap(", HexStr(AsInt(target_address)),
              ") failed: ", ErrnoStr(errno));
  }
  if (mapped_address != target_address) {
    LOG_FATAL("mmap failed: got ", HexStr(AsInt(mapped_address)), " want ",
              HexStr(AsInt(target_address)));
  }
}

// Can this memory mapping be mapped directly from the backing file?
bool CanDirectMap(const SnapMemoryMapping& memory_mapping) {
  // We could support mmapping writeable pages with COW, but that's not a
  // feature we need right now and it makes the code a little more complicated.
  if ((memory_mapping.perms & PROT_WRITE) != 0) {
    return false;
  }
  // There must be only one memory_bytes entry.
  if (memory_mapping.memory_bytes.size != 1) {
    return false;
  }
  const SnapMemoryBytes& memory_bytes = memory_mapping.memory_bytes[0];
  // The bytes must be uncompressed.
  if (memory_bytes.repeating()) {
    return false;
  }
  // The bytes must cover the mapping completely.
  if (memory_bytes.start_address != memory_mapping.start_address ||
      memory_bytes.size() != memory_mapping.num_bytes) {
    return false;
  }
  // The underlying data pointer must be page aligned.
  return IsPageAligned(memory_bytes.data.byte_values.elements);
}

SeccompOptions SeccompOptionsFromRunnerMainOptions(
    const RunnerMainOptions& options) {
  SeccompOptions seccomp_options;
  seccomp_options.allow_kill = options.enable_tracer;
  if (options.max_pages_to_add > 0) {
    seccomp_options.allow_mmap = true;
    seccomp_options.allow_rt_sigreturn = true;
  }
  return seccomp_options;
}

}  // namespace

void InstallSigHandler() {
  struct kernel_sigaction action = {};  // zero-initialized.
  action.sa_sigaction_ = SigAction;

  // Use alt stack to protect our signal handlers from snapshots that corrupt
  // the stack pointer.
  static char alt_stack[64 * 1024] = {0};
  stack_t ss{.ss_sp = alt_stack, .ss_flags = 0, .ss_size = sizeof(alt_stack)};
  if (sigaltstack(&ss, nullptr) != 0) {
    LOG_FATAL("sigaltstack() failed: ", ErrnoStr(errno));
  }

  // Mask the timeout signal(s) because we don't care for nested timeout alerts.
  // Consequentially, we should not continue snapshot execution after the first
  // runaway is detected. See also SA_NODEFER below.
  // See also "Signal handling" file-level comment.
  for (const auto masked_signal : {SIGXCPU, SIGALRM}) {
    if (sys_sigaddset(&action.sa_mask, masked_signal) != 0) {
      LOG_FATAL("sigaddset() failed: ", ErrnoStr(errno));
    }
  }

  // SA_NODEFER tells the kernel to keep the triggering signal unmasked before
  // entering the sighandler. This prevents signals from being blocked when we
  // leave SigAction() via RestoreUContextNoSyscalls() without invoking
  // sigprocmask(2).
  action.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;

  // Catch all possible signals: see <bits/signum.h>.
  // Exceptions: SIGKILL, SIGSTOP -- unblockable.
  // SIGINT, SIGHUP, SIGWINCH -- runner can receive external signals from a
  //                             terminal window or the keyboard.
  for (int signal = 1; signal < _NSIG; ++signal) {
    if (signal == SIGKILL || signal == SIGSTOP || signal == SIGWINCH ||
        signal == SIGHUP || signal == SIGINT) {
      continue;
    }
    struct kernel_sigaction save_action;
    if (sys_sigaction(signal, &action, &save_action) != 0) {
      LOG_FATAL("sigaction() failed for ", SignalNameStr(signal), ": ",
                ErrnoStr(errno));
    }
    // Sanity-check that we don't install the same handler twice.
    CHECK_NE(save_action.sa_sigaction_, SigAction);
  }
}

void CreateMemoryMapping(const SnapMemoryMapping& memory_mapping, int corpus_fd,
                         const void* corpus_mapping) {
  const uint64_t start_address = memory_mapping.start_address;
  VLOG_INFO(2, "Mapping ", HexStr(start_address));

  // Make the initial mapping.
  void* target_address = AsPtr(start_address);
  if (corpus_fd != -1 && CanDirectMap(memory_mapping)) {
    // We can map this data directly from the corpus file.

    // Calculate offset of the bytes from the start of the corpus file.
    off_t offset = static_cast<off_t>(
        AsInt(memory_mapping.memory_bytes[0].data.byte_values.elements) -
        AsInt(corpus_mapping));
    CHECK(IsPageAligned(offset));

    // Map.
    void* mapped_address =
        mmap(target_address, memory_mapping.num_bytes, memory_mapping.perms,
             MAP_SHARED | MAP_FIXED, corpus_fd, offset);
    CheckFixedMmapOK(mapped_address, target_address);
  } else {
    // The data cannot be direct mapped.

    void* mapped_address = mmap(target_address, memory_mapping.num_bytes,
                                kInitialMappingProtection,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CheckFixedMmapOK(mapped_address, target_address);

    // Initialize the contents of the mapping.
    // We will always initialize writeable mappings before the snap runs, so we
    // only setup read-only mappings here.
    if (!memory_mapping.writable()) {
      for (const auto& memory_bytes : memory_mapping.memory_bytes) {
        SetupMemoryBytes(memory_bytes);
      }
    }

    // Set the final protections.
    if (memory_mapping.perms != kInitialMappingProtection) {
      VLOG_INFO(2, "mprotect mapping ", HexStr(start_address));
      // mprotect should sync the data cache and invalidate the instruction
      // cache as needed. No need to do it explicitly.
      int mprotect_result = mprotect(target_address, memory_mapping.num_bytes,
                                     memory_mapping.perms);
      if (mprotect_result != 0) {
        LOG_FATAL("mprotect(", HexStr(AsInt(target_address)),
                  ") failed: ", ErrnoStr(errno));
      }
    }
  }
}

void MapSnap(const Snap<Host>& snap, int corpus_fd,
             const void* corpus_mapping) {
  for (const auto& memory_mapping : snap.memory_mappings) {
    CreateMemoryMapping(memory_mapping, corpus_fd, corpus_mapping);
  }
}

// ApplyProcMapsFixups manipulates this process' memory mappings. Resizes the
// [stack] mapping to occupy the maximum allowed stack size. Unmaps [vdso] and
// [vvar] mappings.
void ApplyProcMapsFixups(ProcMapsEntry proc_maps_entries[],
                         size_t num_proc_maps_entries) {
  struct kernel_rlimit rlimit = {};
  CHECK_EQ(sys_getrlimit(RLIMIT_STACK, &rlimit), 0);
  CHECK_NE(rlimit.rlim_cur, RLIM_INFINITY);

  for (size_t i = 0; i < num_proc_maps_entries; ++i) {
    ProcMapsEntry* e = &proc_maps_entries[i];
    if (strcmp(e->name, "[stack]") == 0) {
      uint64_t orig_start_addr = e->start_address;
      e->start_address = e->limit_address - rlimit.rlim_cur;
      CHECK_LE(e->start_address, orig_start_addr);
      VLOG_INFO(1, "Growing [stack]. Previous size ",
                HexStr(e->limit_address - orig_start_addr), " new size is ",
                HexStr(e->limit_address - e->start_address));
    }
    if (strcmp(e->name, "[vdso]") == 0 || strcmp(e->name, "[vvar]") == 0) {
      CHECK_EQ(
          munmap(AsPtr(e->start_address), e->limit_address - e->start_address),
          0);
      VLOG_INFO(1, "Unmapped ", static_cast<const char*>(e->name));
    }
  }
}

// MapCorpus establishes memory mappings for all snaps in 'corpus'. If a
// snap uses a memory mapping that conflicts with the runner itself (binary,
// stack, heap and VDSO), it can crash the runner. Therefore, it performs
// range checks before adding memory mappings into the runners address
// space and dies if a conflict is detected.
void MapCorpus(const SnapCorpus<Host>& corpus, int corpus_fd,
               const void* corpus_mapping) {
  CHECK(corpus.IsExpectedArch());

  // On x86_64, we should only need 8 entries to describe all memory ranges when
  // running a fully static runner. 20 is more than enough to avoid overflow.
  constexpr size_t kMaxProcMapsEntries = 20;
  ProcMapsEntry proc_maps_entries[kMaxProcMapsEntries];
  const size_t num_proc_maps_entries =
      ReadProcMapsEntries(proc_maps_entries, kMaxProcMapsEntries);

  if (VLOG_IS_ON(1)) {
    for (size_t i = 0; i < num_proc_maps_entries; ++i) {
      ProcMapsEntry* e = &proc_maps_entries[i];
      VLOG_INFO(1, HexStr(e->start_address), "-", HexStr(e->limit_address), " ",
                static_cast<const char*>(e->name));
    }
  }
  ApplyProcMapsFixups(proc_maps_entries, num_proc_maps_entries);

  VLOG_INFO(1, "Creating memory mappings");
  for (const auto& snap : corpus.snaps) {
    // TODO(dougkwan): [impl] Make this fail more gracefully. We can skip
    // conflicting snaps. To do that we need space to store the passing
    // snaps. One possible way to do that without additional memory
    // allocation at runtime is to make 'corpus' writable and remove
    // conflicting snaps found here.
    if (SnapOverlapsWithProcMapsEntries(*snap, proc_maps_entries,
                                        num_proc_maps_entries)) {
      LOG_FATAL("Cannot handle overlapping mappings");
    }
    // If any of these memory mappings overlap, the mapping earlier in this list
    // will be silently overwritten by the mapping later in this list.
    // Currently, the corpus creator should avoid overlapping RO pages, but
    // there may be zero-initialized RW pages that overlap between snaps. The
    // most obvious case will be that most Snaps will have stacks mapped in
    // exactly the same location.
    MapSnap(*snap, corpus_fd, corpus_mapping);
  }
  VLOG_INFO(1, "Done creating memory mappings");

  if (corpus_fd != -1) {
    CHECK_EQ(close(corpus_fd), 0);
  }
}

bool VerifySnapChecksums(const Snap<Host>& snap) {
  bool ok = true;
  for (const SnapMemoryMapping& memory_mapping : snap.memory_mappings) {
    // Writeable mappings will only be initialized right before execution.
    if (memory_mapping.writable()) continue;
    VLOG_INFO(1, "Checksumming ", snap.id, " @ ",
              HexStr(memory_mapping.start_address));

    uint32_t actual = CalculateMemoryChecksum(
        AsPtr(memory_mapping.start_address), memory_mapping.num_bytes);
    if (memory_mapping.memory_checksum != actual) {
      LOG_ERROR(snap.id, " @ ", HexStr(memory_mapping.start_address));
      LOG_ERROR("    Expected checksum ",
                HexStr(memory_mapping.memory_checksum), " but got ",
                HexStr(actual));
      ok = false;
    }
  }

  // Helper to log differences in register memory checksum.
  auto LogRegisterChecksumDiffs =
      [](const SnapRegisterMemoryChecksum<Host>& expected,
         const SnapRegisterMemoryChecksum<Host>& actual) {
        if (expected.fpregs_checksum != actual.fpregs_checksum) {
          LOG_ERROR("    Expected fpregs checksum ",
                    HexStr(expected.fpregs_checksum), " but got ",
                    HexStr(actual.fpregs_checksum));
        }
        if (expected.gregs_checksum != actual.gregs_checksum) {
          LOG_ERROR("    Expected gregs checksum ",
                    HexStr(expected.gregs_checksum), " but got ",
                    HexStr(actual.gregs_checksum));
        }
      };

  {
    VLOG_INFO(1, "Checksumming ", snap.id, " initial registers");
    const SnapRegisterMemoryChecksum<Host>& expected =
        snap.registers_memory_checksum;
    const SnapRegisterMemoryChecksum<Host> actual =
        CalculateRegisterMemoryChecksum(snap.registers);
    if (expected != actual) {
      LogRegisterChecksumDiffs(expected, actual);
      ok = false;
    }
  }
  {
    VLOG_INFO(1, "Checksumming ", snap.id, " end state registers");
    const SnapRegisterMemoryChecksum<Host>& expected =
        snap.end_state_registers_memory_checksum;
    const SnapRegisterMemoryChecksum<Host> actual =
        CalculateRegisterMemoryChecksum(snap.end_state_registers);
    if (expected != actual) {
      LOG_ERROR(snap.id, " end state registers");
      LogRegisterChecksumDiffs(expected, actual);
      ok = false;
    }
  }
  return ok;
}

void VerifyChecksums(const SnapCorpus<Host>& corpus) {
  bool ok = true;
  for (const Snap<Host>* snap : corpus.snaps) {
    ok &= VerifySnapChecksums(*snap);
  }
  if (!ok) {
    LOG_FATAL("Checksum mismatch");
  }
}

RunSnapOutcome EndSpotToOutcome(const Snap<Host>& snap,
                                const EndSpot& end_spot) {
  if (end_spot.signum != 0) {
    if (end_spot.signum == SIGXCPU || end_spot.signum == SIGALRM) {
      return RunSnapOutcome::kExecutionRunaway;
    }
    return RunSnapOutcome::kExecutionMisbehave;
  }
  // Verify register state.
  if (!MemEqT(*end_spot.gregs, *snap.end_state_registers.gregs) ||
      !MemEqT(*end_spot.fpregs, *snap.end_state_registers.fpregs)) {
    return RunSnapOutcome::kRegisterStateMismatch;
  }
  // Verify register checksum if there is one in the snap and it references the
  // same register groups.
  RegisterChecksum<Host> snap_checksum = snap.end_state_register_checksum;
  if (!snap_checksum.register_groups.Empty() &&
      snap_checksum.register_groups ==
          end_spot.register_checksum.register_groups &&
      snap.end_state_register_checksum != end_spot.register_checksum) {
    VLOG_INFO(1, "Register checksum mismatch: ",
              HexStr(snap.end_state_register_checksum.checksum), " vs ",
              HexStr(end_spot.register_checksum.checksum));
    return RunSnapOutcome::kRegisterStateMismatch;
  }

  // Verify writable memory contents after execution.
  for (const auto& memory_bytes : snap.end_state_memory_bytes) {
    if (!VerifyMemoryBytes(memory_bytes)) {
      VLOG_INFO(1, "Memory mismatch at ", HexStr(memory_bytes.start_address));
      return RunSnapOutcome::kMemoryMismatch;
    }
  }

  return RunSnapOutcome::kAsExpected;
}

// Copies read/writable memory contents needed to run the snap.
void PrepareSnapMemory(const Snap<Host>& snap) {
  for (const auto& memory_mapping : snap.memory_mappings) {
    // Read-only contents will not have changed.
    if (memory_mapping.writable()) {
      for (const auto& memory_bytes : memory_mapping.memory_bytes) {
        SetupMemoryBytes(memory_bytes);
      }
    }
  }
}

// Logs the actual memory bytes of `snap` as a series of proto.MemoryBytes
// protos formatted as text.
// The output may appear fragmented due to internal buffer capacity limits e.g.
// a single MemoryBytes{40Kb} may be split into a semantically equivalent series
// of 10 4Kb entries.
void LogSnapMemoryBytes(const Snap<Host>& snap,
                        class TextProtoPrinter::Message& end_state_m) {
  const size_t kPageSize = getpagesize();
  for (const auto& memory_mapping : snap.memory_mappings) {
    if (!memory_mapping.writable()) {
      continue;
    }
    VLOG_INFO(2, "Logging memory bytes at ",
              HexStr(memory_mapping.start_address));
    // Convert the memory bytes to page-sized chunks to avoid overflowing
    // TextProtoPrinter::Bytes buffer which can only hold a page-ful of escaped
    // bytes. The consumer may choose to normalize.
    const char* start_address =
        reinterpret_cast<const char*>(AsPtr(memory_mapping.start_address));
    const char* limit_address = start_address + memory_mapping.num_bytes;
    for (; start_address < limit_address; start_address += kPageSize) {
      auto memory_bytes_m = end_state_m->Message("memory_bytes");
      size_t bytes_to_log =
          std::min<size_t>(kPageSize, limit_address - start_address);
      memory_bytes_m->Hex("start_address", AsInt(start_address));
      memory_bytes_m->Bytes("byte_values", start_address, bytes_to_log);
    }
  }
}

// Logs the run result of `snap` to stdout formatted as
// proto.SnapshotExecutionResult text proto. Additionally, logs execution
// result in human-readable format to stderr.
void LogSnapRunResult(const Snap<Host>& snap, const RunnerMainOptions& options,
                      const RunSnapResult& run_result) {
  if (run_result.outcome != RunSnapOutcome::kAsExpected) {
    LOG_ERROR("Snapshot [", snap.id,
              "] failed, outcome = ", IntStr(ToInt(run_result.outcome)));
    LOG_ERROR("Corpus   [", options.corpus_name, "]");
    if (run_result.outcome == RunSnapOutcome::kRegisterStateMismatch) {
      LOG_INFO("Registers (diff vs expected end_state 0):");
      LOG_INFO("  gregs (modified only):");
      // Use instruction pointer == 0 as a proxy for undefined state. The only
      // possible case where the value is 0 is for Snaps with the undefined end
      // state.
      // See SnapGenerator::Options::allow_undefined_end_state for details.
      bool log_diff =
          snap.end_state_registers.gregs->GetInstructionPointer() != 0;
      LogGRegs(*run_result.end_spot.gregs, snap.end_state_registers.gregs,
               log_diff);
      LOG_INFO("  fpregs (modified only):");
      LogFPRegs(*run_result.end_spot.fpregs, true,
                snap.end_state_registers.fpregs, log_diff);
      LogRegisterChecksum(run_result.end_spot.register_checksum,
                          &snap.end_state_register_checksum, log_diff);
    } else if (run_result.outcome == RunSnapOutcome::kMemoryMismatch) {
      LOG_INFO("Memory state mismatch (details omitted)");
    } else if (run_result.outcome == RunSnapOutcome::kExecutionMisbehave) {
      LOG_INFO("Execution misbehaved");
      run_result.end_spot.Log();
    } else if (run_result.outcome == RunSnapOutcome::kExecutionRunaway) {
      LOG_INFO("Execution was a run-away");
      run_result.end_spot.Log();
    }
  }
  // The root message is proto.SnapshotExecutionResult
  TextProtoPrinter snapshot_execution_result;
  {
    snapshot_execution_result.String("snapshot_id", snap.id);
    auto player_result = snapshot_execution_result.Message("player_result");
    // actual_end_state is a text representation of silifuzz.proto.EndState.
    // There is no in-memory format to represent EndState in the runner, the
    // the memory state is read directly from the corresponding live mappings.
    auto actual_end_state = player_result->Message("actual_end_state");
    player_result->Int("outcome", ToInt(run_result.outcome));
    player_result->Int("cpu_id", run_result.cpu_id);
    // TODO(ksteuck): [as-needed] Populate cpu_usage field.
    auto registers_m = actual_end_state->Message("registers");

    // Serialize the GRegs
    Serialized<EndSpot::gregs_t> serialized_gregs;
    CHECK(SerializeGRegs(*run_result.end_spot.gregs, &serialized_gregs));
    registers_m->Bytes("gregs", serialized_gregs.data, serialized_gregs.size);

    // Serialize the FPRegs
    Serialized<EndSpot::fpregs_t> serialized_fpregs;
    CHECK(SerializeFPRegs(*run_result.end_spot.fpregs, &serialized_fpregs));
    registers_m->Bytes("fpregs", serialized_fpregs.data,
                       serialized_fpregs.size);

    // Serialize register checksum.
    uint8_t checksum_buffer[256];
    ssize_t checksum_size = Serialize(run_result.end_spot.register_checksum,
                                      checksum_buffer, sizeof(checksum_buffer));
    CHECK_NE(checksum_size, -1);
    actual_end_state->Bytes("register_checksum",
                            reinterpret_cast<const char*>(checksum_buffer),
                            checksum_size);

    std::optional<Endpoint> endpoint = EndSpotToEndpoint(run_result.end_spot);
    if (endpoint.has_value()) {
      auto endpoint_m = actual_end_state->Message("endpoint");
      if (endpoint->type() == EndpointType::kSignal) {
        auto signal_m = endpoint_m->Message("signal");
        signal_m->Enum("sig_num", EnumStr(endpoint->sig_num()));
        signal_m->Enum("sig_cause", EnumStr(endpoint->sig_cause()));
        signal_m->Hex("sig_address", endpoint->sig_address());
        signal_m->Hex("sig_instruction_address",
                      endpoint->sig_instruction_address());
      } else {
        endpoint_m->Hex("instruction_address", endpoint->instruction_address());
      }
    }
    LogSnapMemoryBytes(snap, actual_end_state);
    // Append additional pages mapped during making.
    for (int i = 0; i < num_added_pages; ++i) {
      auto memory_bytes_m = actual_end_state->Message("memory_bytes");
      const char* start_address =
          reinterpret_cast<const char*>(AsPtr(added_page_addresses[i]));
      memory_bytes_m->Hex("start_address", AsInt(start_address));
      memory_bytes_m->Bytes("byte_values", start_address, kPageSize);
    }
  }
  LogToStdout(snapshot_execution_result.c_str());
}

const SnapCorpus<Host>* CommonMain(const RunnerMainOptions& options) {
  // Pin CPU if pinning is requested.
  if (options.cpu != kAnyCPUId) {
    const int error = SetCPUAffinity(options.cpu);
    // Linux kernel API uses unsigned long type.
    if (error != 0) {
      LOG_FATAL("Cannot pin cpu to core ", IntStr(options.cpu),
                " error=", IntStr(error));
    }
  }

  InitSnapExit(&SnapExitImpl);

  // Initialize register checksumming.
  InitRegisterGroupIO();
  RegisterGroupSet<Host> checksum_register_group =
      GetCurrentPlatformChecksumRegisterGroups();
  snap_exit_register_group_io_buffer.register_groups = checksum_register_group;

  // Preserve this value because the following logic might synthesize a new
  // SnapCorpus struct.
  const void* corpus_mapping = reinterpret_cast<const void*>(options.corpus);

  auto corpus = [&options]() -> const SnapCorpus<Host>* {
    static SnapCorpus<Host> one_snap_corpus = {};
    if (options.snap_id == nullptr) {
      return options.corpus;
    }
    for (int i = 0; i < options.corpus->snaps.size; ++i) {
      const Snap<Host>* snap = options.corpus->snaps[i];
      if (strcmp(snap->id, options.snap_id) == 0) {
        // Creates a slice of size 1 over the original corpus.
        memcpy(&one_snap_corpus, options.corpus, sizeof(one_snap_corpus));
        one_snap_corpus.snaps.size = 1;
        one_snap_corpus.snaps.elements = &options.corpus->snaps[i];
        return &one_snap_corpus;
      }
    }
    LOG_FATAL("Snap ", options.snap_id, " not found in the corpus");
  }();
  MapCorpus(*corpus, options.corpus_fd, corpus_mapping);
  if (options.strict) {
    VerifyChecksums(*corpus);
  }
  InstallSigHandler();

  return corpus;
}

void RunSnap(const Snap<Host>& snap, const RunnerMainOptions& options,
             RunSnapResult& result) {
  PrepareSnapMemory(snap);
  result.cpu_id = GetCPUIdNoSyscall();
  RunSnap(snap.registers, options, result.end_spot);
  if (result.cpu_id != GetCPUIdNoSyscall()) {
    result.cpu_id = kUnknownCPUId;
  }
  result.outcome = options.skip_end_state_check
                       ? RunSnapOutcome::kAsExpected
                       : EndSpotToOutcome(snap, result.end_spot);
}

int MakerMain(const RunnerMainOptions& options) {
  const SnapCorpus<Host>* corpus = CommonMain(options);

  max_pages_to_add = options.max_pages_to_add;
  EnterSeccompFilterMode(SeccompOptionsFromRunnerMainOptions(options));

  const Snap<Host>& snap = *corpus->snaps.at(0);
  RunSnapResult run_result;
  RunSnap(snap, options, run_result);

  LogSnapRunResult(snap, options, run_result);
  if (run_result.outcome != RunSnapOutcome::kAsExpected) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

int RunnerMain(const RunnerMainOptions& options) {
  CHECK(!options.sequential_mode);
  const SnapCorpus<Host>* corpus = CommonMain(options);
  CHECK_GT(corpus->snaps.size, 0);

  EnterSeccompFilterMode(SeccompOptionsFromRunnerMainOptions(options));

  std::mt19937_64 gen(options.seed);  // 64-bit Mersenne Twister engine
  VLOG_INFO(1, "Seed = ", IntStr(options.seed));
  size_t snap_execution_count = 0;
  const char* previous_snap_id = "<none>";
  while (snap_execution_count < options.num_iterations) {
    // Generate Snap batch
    size_t batch[RunnerMainOptions::kMaxBatchSize];
    size_t batch_size = options.batch_size;
    CHECK_LE(batch_size, RunnerMainOptions::kMaxBatchSize);
    std::uniform_int_distribution<size_t> dist(0, corpus->snaps.size - 1);
    for (size_t i = 0; i < batch_size; ++i) {
      batch[i] = dist(gen);
    }

    // Adjust schedule size to honor options.num_iterations.
    size_t remaining_iterations = options.num_iterations - snap_execution_count;
    size_t schedule_size =
        std::min<size_t>(options.schedule_size, remaining_iterations);

    std::uniform_int_distribution<size_t> schedule_dist(0, batch_size - 1);
    for (size_t i = 0; i < schedule_size; ++i, ++snap_execution_count) {
      if ((snap_execution_count & (snap_execution_count - 1)) == 0) {
        VLOG_INFO(1, "iter #", IntStr(snap_execution_count), " of ",
                  IntStr(options.num_iterations));
      }
      const Snap<Host>& snap = *(corpus->snaps[batch[schedule_dist(gen)]]);
      VLOG_INFO(3, "#", IntStr(snap_execution_count), " Running ", snap.id);
      RunSnapResult run_result;
      RunSnap(snap, options, run_result);
      if (run_result.outcome != RunSnapOutcome::kAsExpected) {
        LogSnapRunResult(snap, options, run_result);
        LOG_ERROR("Seed = ", IntStr(options.seed), " iteration #",
                  IntStr(snap_execution_count));
        LOG_ERROR("CPU id = ", IntStr(run_result.cpu_id));
        LOG_ERROR("Previous snapshot [", previous_snap_id, "]");
        // Done last since there's a chance this can cause a fault if things
        // have gone seriously wrong.
        if (VerifySnapChecksums(snap)) {
          // Print a positive message so we know it completed.
          LOG_ERROR("Snap checksums verified");
        }
        return EXIT_FAILURE;
      }
      previous_snap_id = snap.id;
    }
  }

  return EXIT_SUCCESS;
}

int RunnerMainSequential(const RunnerMainOptions& options) {
  CHECK(options.sequential_mode);
  const SnapCorpus<Host>* corpus = CommonMain(options);

  EnterSeccompFilterMode(SeccompOptionsFromRunnerMainOptions(options));
  VLOG_INFO(1, "Running in sequential mode");

  for (size_t i = 0; i < corpus->snaps.size; ++i) {
    const Snap<Host>& snap = *(corpus->snaps[i]);
    if ((i & (i - 1)) == 0) {
      VLOG_INFO(1, "iter #", IntStr(i), " of ", IntStr(corpus->snaps.size));
    }
    VLOG_INFO(3, "#", IntStr(i), " Running ", snap.id);
    RunSnapResult run_result;
    RunSnap(snap, options, run_result);
    if (run_result.outcome != RunSnapOutcome::kAsExpected) {
      LogSnapRunResult(snap, options, run_result);
      LOG_ERROR("Id = ", snap.id, " Iteration #", IntStr(i));
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}

}  // namespace silifuzz
