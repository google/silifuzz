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
#include <ucontext.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <random>
#include <type_traits>

#include "third_party/lss/lss/linux_syscall_support.h"
#include "./common/snapshot_enums.h"
#include "./runner/runner_util.h"
#include "./runner/snap_runner_util.h"
#include "./snap/exit_sequence.h"
#include "./snap/snap.h"
#include "./util/checks.h"
#include "./util/cpu_id.h"
#include "./util/itoa.h"
#include "./util/logging_util.h"
#include "./util/mem_util.h"
#include "./util/misc_util.h"
#include "./util/proc_maps_parser.h"
#include "./util/text_proto_printer.h"
#include "./util/ucontext/serialize.h"
#include "./util/ucontext/ucontext.h"

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
// In a typical setup this process will be limited by setrlimit(RLIMIT_CPU) and
// a much larger setitimer(ITIMER_REAL). The first SIGXCPU/SIGALRM will
// initiate a graceful process shutdown. Reaching hard cap on RLIMIT_CPU will
// trigger SIGKILL.

// linux_syscall_support.h does not have an implementation of sys_sigaction on
// aarch64.
// TODO: fix this upstream.
#if defined(__aarch64__)
LSS_INLINE int LSS_NAME(sigaction)(int signum,
                                   const struct kernel_sigaction* act,
                                   struct kernel_sigaction* oldact) {
  // Note that this implementation does not call sigreturn if the handler
  // returns normally, which would likely result in the stack pointer
  // being corrupted. Fortunately our signal handler never returns normally, so
  // this isn't an issue and we can stick with a simple implementation for now.
  return LSS_NAME(rt_sigaction)(signum, act, oldact, (KERNEL_NSIG + 7) / 8);
}
#endif

namespace silifuzz {

namespace {

using snapshot_types::Endpoint;
using snapshot_types::EndpointType;
using snapshot_types::EndSpot;

constexpr int kInitialMappingProtection = PROT_READ | PROT_WRITE;

// The signal handler for the duration of the corpus execution.
// NOTE: even though this handler is installed for SIGSYS it will be
// ignored. See file-level comment.
void SigAction(int signal, siginfo_t* siginfo, void* uc) {
  // SIGALRM signals deadline from the orchestrator. Exit immediately.
  if (signal == SIGALRM) {
    _exit(2);
  }
  if (IsInsideSnap()) {
    // The signal arrived while executing a snapshot -- blame it on the
    // snapshot itself.
    RunnerReentryFromSignal(*static_cast<const ucontext_t*>(uc), *siginfo);
    __builtin_unreachable();
  }
  // A signal was not caused by any snapshot. If it is one of the
  // timeout signals we _exit(2). Otherwise crash.
  ASS_LOG_INFO("Received signal ", IntStr(signal),
               " while outside of snap. Exiting");
  if (signal == SIGXCPU) {
    _exit(2);
  }
  // A signal occurred while executing the runner code. Most likely indicates
  // a bug in the runner or a signal from the environment (keyboard, RLIMIT).
  ASS_LOG_FATAL("Unhandled signal ", IntStr(signal));
  __builtin_unreachable();
}

// Returns true iff current memory contents match memory byte data.
bool VerifyMemoryBytes(const Snap::MemoryBytes& memory_bytes) {
  const void* address = AsPtr(memory_bytes.start_address);
  const size_t size = memory_bytes.size();
  return memory_bytes.repeating()
             ? MemAllEqualTo(address, memory_bytes.data.byte_run.value, size)
             : MemEq(address, memory_bytes.data.byte_values.elements, size);
}

// Copies memory bytes from Snap to runtime address.
void SetupMemoryBytes(const Snap::MemoryBytes& memory_bytes) {
  void* target_address = AsPtr(memory_bytes.start_address);
  if (memory_bytes.repeating()) {
    MemSet(target_address, memory_bytes.data.byte_run.value,
           memory_bytes.size());
  } else {
    MemCopy(target_address, memory_bytes.data.byte_values.elements,
            memory_bytes.size());
  }
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
      LOG_FATAL("sigaction() failed for ", IntStr(signal), ": ",
                ErrnoStr(errno));
    }
    // Sanity-check that we don't install the same handler twice.
    CHECK_NE(save_action.sa_sigaction_, SigAction);
  }
}

void CreateMemoryMapping(const Snap::MemoryMapping& memory_mapping) {
  const uint64_t start_address = memory_mapping.start_address;
  VLOG_INFO(2, "Mapping ", HexStr(start_address));

  // Make the initial mapping.
  void* target_address = AsPtr(start_address);
  void* mapped_address =
      mmap(target_address, memory_mapping.num_bytes, kInitialMappingProtection,
           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (mapped_address == MAP_FAILED) {
    LOG_FATAL("mmap(", HexStr(AsInt(target_address)),
              ") failed: ", ErrnoStr(errno));
  }
  if (mapped_address != target_address) {
    LOG_FATAL("mmap failed: got ", HexStr(AsInt(mapped_address)), " want ",
              HexStr(AsInt(target_address)));
  }

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

void MapSnap(const Snap& snap) {
  for (const auto& memory_mapping : snap.memory_mappings) {
    CreateMemoryMapping(memory_mapping);
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
void MapCorpus(const SnapCorpus& corpus) {
  CHECK(corpus.IsArch<Host>());

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
    // Currently, the corpus creator should avoid overlaping RO pages, but there
    // may be zero-initialized RW pages that overlap between snaps. The most
    // obvious case will be that most Snaps will have stacks mapped in exactly
    // the same location.
    MapSnap(*snap);
  }
  VLOG_INFO(1, "Done creating memory mappings");
}

RunSnapOutcome EndSpotToOutcome(const Snap& snap, const EndSpot& end_spot) {
  if (end_spot.signum != 0) {
    if (end_spot.signum == SIGXCPU || end_spot.signum == SIGALRM) {
      return RunSnapOutcome::kExecutionRunaway;
    }
    return RunSnapOutcome::kExecutionMisbehave;
  }
  // Verify register state.
  if (!MemEq(&end_spot.gregs, &snap.end_state_registers->gregs,
             sizeof(end_spot.gregs)) ||
      !MemEq(&end_spot.fpregs, &snap.end_state_registers->fpregs,
             sizeof(end_spot.fpregs))) {
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
void PrepareSnapMemory(const Snap& snap) {
  for (const auto& memory_mapping : snap.memory_mappings) {
    // Read-only contents will not have changed.
    if (memory_mapping.writable()) {
      for (const auto& memory_bytes : memory_mapping.memory_bytes) {
        SetupMemoryBytes(memory_bytes);
      }
    }
  }
}

RunSnapResult RunSnap(const Snap& snap) {
  PrepareSnapMemory(snap);
  int64_t cpu_id = GetCPUIdNoSyscall();
  EndSpot end_spot = RunSnap(*snap.registers);
  if (cpu_id != GetCPUIdNoSyscall()) {
    cpu_id = kUnknownCPUId;
  }
  RunSnapOutcome outcome = EndSpotToOutcome(snap, end_spot);
  return {.end_spot = end_spot, .outcome = outcome, .cpu_id = cpu_id};
}

// Logs the actual memory bytes of `snap` as a series of proto.MemoryBytes
// protos formatted as text.
// The output may appear fragmented due to internal buffer capacity limits e.g.
// a single MemoryBytes{40Kb} may be split into a semantically equivalent series
// of 10 4Kb entries.
void LogSnapMemoryBytes(const Snap& snap,
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
void LogSnapRunResult(const Snap& snap, const RunSnapResult& run_result) {
  if (run_result.outcome != RunSnapOutcome::kAsExpected) {
    LOG_ERROR("Snapshot [", snap.id,
              "] failed, outcome = ", IntStr(ToInt(run_result.outcome)));
    if (run_result.outcome == RunSnapOutcome::kRegisterStateMismatch) {
      LOG_INFO("Registers (diff vs expected end_state 0):");
      LOG_INFO("  gregs (modified only):");
      // Use instruction pointer == 0 as a proxy for undefined state. The only
      // possible case where the value is 0 is for Snaps with the undefined end
      // state.
      // See SnapGenerator::Options::allow_undefined_end_state for details.
      bool log_diff =
          GetInstructionPointer(snap.end_state_registers->gregs) != 0;
      LogGRegs(run_result.end_spot.gregs, &snap.end_state_registers->gregs,
               log_diff);
      LOG_INFO("  fpregs (modified only):");
      LogFPRegs(run_result.end_spot.fpregs, true,
                &snap.end_state_registers->fpregs, log_diff);
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
    Serialized<decltype(run_result.end_spot.gregs)> serialized_gregs;
    CHECK(SerializeGRegs(run_result.end_spot.gregs, &serialized_gregs));
    registers_m->Bytes("gregs", serialized_gregs.data, serialized_gregs.size);

    // Serialize the FPRegs
    Serialized<decltype(run_result.end_spot.fpregs)> serialized_fpregs;
    CHECK(SerializeFPRegs(run_result.end_spot.fpregs, &serialized_fpregs));
    registers_m->Bytes("fpregs", serialized_fpregs.data,
                       serialized_fpregs.size);

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
  }
  LogToStdout(snapshot_execution_result.c_str());
}

const SnapCorpus* CommonMain(const RunnerMainOptions& options) {
  // Pin CPU if pinning is requested.
  if (options.cpu != kAnyCPUId) {
    const int error = SetCPUId(options.cpu);
    // Linux kernel API uses unsigned long type.
    if (error != 0) {
      LOG_FATAL("Cannot pin cpu to core ", IntStr(options.cpu),
                " error=", IntStr(error));
    }
  }

  InitSnapExit(&SnapExitImpl);

  auto corpus = [&options]() -> const SnapCorpus* {
    static SnapCorpus one_snap_corpus = {};
    if (options.snap_id == nullptr) {
      return options.corpus;
    }
    for (int i = 0; i < options.corpus->snaps.size; ++i) {
      const Snap* snap = options.corpus->snaps[i];
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
  MapCorpus(*corpus);
  InstallSigHandler();

  return corpus;
}

RunSnapResult RunSnapWithOpts(const Snap& snap,
                              const RunnerMainOptions& options) {
  if (options.enable_tracer) {
    CHECK_EQ(kill(options.pid, SIGSTOP), 0);
  }
  RunSnapResult run_result = RunSnap(snap);
  if (options.enable_tracer) {
    CHECK_EQ(kill(options.pid, SIGSTOP), 0);
  }
  return run_result;
}

int MakerMain(const RunnerMainOptions& options) {
  const SnapCorpus* corpus = CommonMain(options);

  EnterSeccompStrictMode(options.enable_tracer);

  const Snap& snap = *corpus->snaps.at(0);
  RunSnapResult run_result = RunSnapWithOpts(snap, options);

  LogSnapRunResult(snap, run_result);
  if (run_result.outcome != RunSnapOutcome::kAsExpected) {
    return EXIT_FAILURE;
  }

  return 0;
}

int RunnerMain(const RunnerMainOptions& options) {
  CHECK(!options.sequential_mode);
  const SnapCorpus* corpus = CommonMain(options);
  CHECK_GT(corpus->snaps.size, 0);

  EnterSeccompStrictMode(options.enable_tracer);

  std::mt19937_64 gen(options.seed);  // 64-bit Mersenne Twister engine
  VLOG_INFO(1, "Seed = ", IntStr(options.seed));
  size_t snap_execution_count = 0;
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
      const Snap& snap = *(corpus->snaps[batch[schedule_dist(gen)]]);
      VLOG_INFO(3, "#", IntStr(snap_execution_count), " Running ", snap.id);
      RunSnapResult run_result = RunSnapWithOpts(snap, options);
      if (run_result.outcome != RunSnapOutcome::kAsExpected) {
        LogSnapRunResult(snap, run_result);
        LOG_ERROR("Seed = ", IntStr(options.seed), " iteration #",
                  IntStr(snap_execution_count));
        return EXIT_FAILURE;
      }
    }
  }

  return EXIT_SUCCESS;
}

int RunnerMainSequential(const RunnerMainOptions& options) {
  CHECK(options.sequential_mode);
  const SnapCorpus* corpus = CommonMain(options);

  EnterSeccompStrictMode(options.enable_tracer);
  VLOG_INFO(1, "Running in sequential mode");

  for (size_t i = 0; i < corpus->snaps.size; ++i) {
    const Snap& snap = *(corpus->snaps[i]);
    if ((i & (i - 1)) == 0) {
      VLOG_INFO(1, "iter #", IntStr(i), " of ", IntStr(corpus->snaps.size));
    }
    VLOG_INFO(3, "#", IntStr(i), " Running ", snap.id);
    RunSnapResult run_result = RunSnapWithOpts(snap, options);
    if (run_result.outcome != RunSnapOutcome::kAsExpected) {
      LogSnapRunResult(snap, run_result);
      LOG_ERROR("Id = ", snap.id, " Iteration #", IntStr(i));
      return EXIT_FAILURE;
    }
  }

  return EXIT_SUCCESS;
}

}  // namespace silifuzz
