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

#include <cstdlib>

#include "./common/snapshot_test_enum.h"
#include "./runner/default_snap_corpus.h"
#include "./runner/runner_main_options.h"
#include "./runner/runner_util.h"
#include "./runner/snap_runner_util.h"
#include "./snap/exit_sequence.h"
#include "./snap/snap.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {

namespace {

// An instance of the test corpus. main() loads this from $TEST_CORPUS.
const SnapCorpus<Host>* kSnapRunnerTestCorpus;

// Returns a Snap runner test Snap of the given type.
const Snap<Host>& GetSnapRunnerTestSnap(TestSnapshot type) {
  const Snap<Host>* snap = kSnapRunnerTestCorpus->Find(EnumStr(type));
  if (snap == nullptr) {
    LOG_FATAL("Cannot find snap with ID: ", EnumStr(type));
  }
  return *snap;
}

// Runner tests do not run well with normal libc because of an invalid fs_base.
// We could make the tests work but it would not be how the runner is intended
// to be used.

TEST(Runner, EndsAsExpected) {
  RunSnapResult result;
  RunSnap(GetSnapRunnerTestSnap(TestSnapshot::kEndsAsExpected),
          RunnerMainOptions::Default(), result);
  CHECK_EQ(result.outcome, RunSnapOutcome::kAsExpected);
}

TEST(Runner, RegsMismatch) {
  RunSnapResult result;
  RunSnap(GetSnapRunnerTestSnap(TestSnapshot::kRegsMismatch),
          RunnerMainOptions::Default(), result);
  CHECK_EQ(result.outcome, RunSnapOutcome::kRegisterStateMismatch);
}

TEST(Runner, MemoryMismatch) {
  RunSnapResult result;
  RunSnap(GetSnapRunnerTestSnap(TestSnapshot::kMemoryMismatch),
          RunnerMainOptions::Default(), result);
  CHECK_EQ(result.outcome, RunSnapOutcome::kMemoryMismatch);
}

TEST(Runner, SkipEndStateCheck) {
  RunnerMainOptions options = RunnerMainOptions::Default();
  RunSnapResult result;
  // Do not skip end state check. This should fails.
  options.skip_end_state_check = false;
  RunSnap(GetSnapRunnerTestSnap(TestSnapshot::kMemoryMismatch), options,
          result);
  CHECK_EQ(result.outcome, RunSnapOutcome::kMemoryMismatch);

  // Skip end state check. This should ends as expected.
  options.skip_end_state_check = true;
  RunSnap(GetSnapRunnerTestSnap(TestSnapshot::kMemoryMismatch), options,
          result);
  CHECK_EQ(result.outcome, RunSnapOutcome::kAsExpected);
}

// Initializes the test environment. Loads and maps the corpus, then drops into
// the seccomp sandbox.
void InitTestEnv() {
  const char* corpus_file = getenv("TEST_CORPUS");
  CHECK_NE(corpus_file, nullptr);
  kSnapRunnerTestCorpus = LoadCorpus(corpus_file, true, nullptr);
  InitSnapExit(&SnapExitImpl);
  MapCorpus(*kSnapRunnerTestCorpus, -1, nullptr);
  SeccompOptions seccomp_options;
  EnterSeccompFilterMode(seccomp_options);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  silifuzz::InitTestEnv();
  RUN_TEST(Runner, EndsAsExpected);
  RUN_TEST(Runner, RegsMismatch);
  RUN_TEST(Runner, MemoryMismatch);
  RUN_TEST(Runner, SkipEndStateCheck);
})
