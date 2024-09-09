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

// Test runner binary that works together with orchestrator_test.py.
// Keep this runner super-simple, so that it stays close to actual runners.
// Don't add any dependencies.

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

#include <csignal>
#include <string>

#include "./snap/snap.h"
#include "./snap/snap_corpus_util.h"
#include "./util/arch.h"
#include "./util/mmapped_memory_ptr.h"

// Some divisions in a loop. Make sure compiler doesn't remove them.
__attribute__((noinline)) void MakeCpuBusy(size_t num_iterations) {
  volatile uint64_t x = 1234567, y;
  for (size_t i = 0; i < num_iterations; i++) {
    y = 1000000000000ULL / x;
  }
}

void LogHumanReadable(const char* format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  fflush(stderr);
}

namespace silifuzz {

// Print the first Snap ID in the corpus.
void PrintFirstSnapId(const char* filename) {
  MmappedMemoryPtr<const SnapCorpus<Host>> corpus =
      LoadCorpusFromFile<Host>(filename);
  if (corpus->snaps.size >= 1) {
    LogHumanReadable("%s\n", corpus->snaps[0]->id);
  } else {
    LogHumanReadable("%s\n", "EMPTY");
  }
}
}  // namespace silifuzz

int main(int argc, char** argv) {
  // Limit the file size with 1Mb.
  struct rlimit rlimit_fsize = {1 << 20, 1 << 20};
  setrlimit(RLIMIT_FSIZE, &rlimit_fsize);

  // If true, the test runner considers any subsequent arguments after
  // print_first_snap_id that are not recognized as flags to be paths. The
  // runner opens these files and prints the ID of the first Snap in the file.
  bool print_first_snap_id = false;

  // Run commands supplied from the command line, one by one.
  for (int i = 1; i < argc; i++) {
    std::string cmd(argv[i]);
    if (cmd == "--timeout=2") {
      // Limit CPU time with 2 seconds.
      // orchestrator-test.sh uses --timeout=2.
      struct rlimit rlimit_cpu = {2, 10};
      setrlimit(RLIMIT_CPU, &rlimit_cpu);
    } else if (cmd == "short_output") {
      LogHumanReadable("ShortOutput\n");
    } else if (cmd == "long_output") {
      LogHumanReadable("LongOutputBegins\n");
      for (size_t i = 0; i < 10000000; i++) {
        LogHumanReadable("%zd\n", i);
      }
    } else if (cmd == "short_loop") {
      // sub-second.
      MakeCpuBusy(100000000);
    } else if (cmd == "long_loop") {
      // ~5 sec
      MakeCpuBusy(2000000000);
    } else if (cmd == "infinite_loop") {
      // Never ends.
      MakeCpuBusy(1ULL << 60);
    } else if (cmd == "print_main_address") {
      // Print the address of main() so that we can check for presence of ASLR.
      LogHumanReadable("main: %p\n", &main);
    } else if (cmd == "exit7") {
      return 7;
    } else if (cmd == "snap_fail") {
      LogHumanReadable("snap_fail: %s\n", "my_snap");
      fprintf(stdout,
              R"pb(
                execution_result: { code: SNAPSHOT_FAILED }
                failed_snapshot_execution: {
                  snapshot_id: 'my_snap'
                  player_result: {
                    outcome: REGISTER_STATE_MISMATCH
                    cpu_id: 1
                    actual_end_state: {
                      endpoint: { instruction_address: 0x6595e5c4025 }
                      registers: { gregs: '' fpregs: '' }
                    }
                  }
                }
              )pb");
      fflush(stdout);
      return 1;
    } else if (cmd == "print_first_snap_id") {
      print_first_snap_id = true;
    } else if (cmd == "--sequential_mode") {
      LogHumanReadable("TEST RUNNER sequential_mode\n");
    } else if (cmd == "ignore_alarm") {
      struct sigaction sigact = {};
      sigact.sa_handler = SIG_IGN;
      sigaction(SIGALRM, &sigact, nullptr);
    } else if (cmd == "sleep100") {
      sleep(100);
    } else if (cmd == "checksum_mismatch") {
      LogHumanReadable("checksum_mismatch");
      fprintf(stdout,
              R"pb(
                failed_snapshot_execution: {
                  snapshot_id: 'my_snap'
                  player_result: {
                    outcome: REGISTER_STATE_MISMATCH
                    cpu_id: 1
                    actual_end_state: {
                      endpoint: { instruction_address: 0x6595e5c4025 }
                      registers: { gregs: '' fpregs: '' }
                    }
                  }
                }
                postfailure_checksum_status: MISMATCH
                execution_result: { code: SNAPSHOT_FAILED }
              )pb");
      fflush(stdout);
      return 1;
    } else if (cmd == "no_execution_result") {
      LogHumanReadable("no_execution_result");
      fprintf(stdout, R"pb()pb");
      fflush(stdout);
      return 1;
    } else if (cmd == "mmap_failed") {
      LogHumanReadable("mmap_failed");
      fprintf(
          stdout,
          R"pb(
            execution_result: { code: MMAP_FAILED msg: 'failed to map memory' }
          )pb");
      fflush(stdout);
      return 1;
    } else {
      if (print_first_snap_id) {
        silifuzz::PrintFirstSnapId(argv[i]);
      }
    }
  }

  return 0;
}
