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

#include <cstdlib>  // EXIT_SUCCESS

#include "./runner/runner_util.h"
#include "./runner/snap_runner_util.h"
#include "./snap/exit_sequence.h"
#include "./snap/testing/snap_test_snaps.h"
#include "./snap/testing/snap_test_types.h"
#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {

namespace {

// Runner tests do not run well with normal libc because of an invalid fs_base.
// We could make the tests work but it would not be how the runner is intended
// to be used.

TEST(Runner, EndsAsExpected) {
  RunSnapResult result;
  RunSnap(GetSnapRunnerTestSnap(TestSnapshot::kEndsAsExpected), result);
  CHECK_EQ(result.outcome, RunSnapOutcome::kAsExpected);
}

TEST(Runner, RegsMismatch) {
  RunSnapResult result;
  RunSnap(GetSnapRunnerTestSnap(TestSnapshot::kRegsMismatch), result);
  CHECK_EQ(result.outcome, RunSnapOutcome::kRegisterStateMismatch);
}

TEST(Runner, MemoryMismatch) {
  RunSnapResult result;
  RunSnap(GetSnapRunnerTestSnap(TestSnapshot::kMemoryMismatch), result);
  CHECK_EQ(result.outcome, RunSnapOutcome::kMemoryMismatch);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  silifuzz::InitSnapExit(&SnapExitImpl);
  silifuzz::MapCorpus(silifuzz::kSnapRunnerTestCorpus, -1, nullptr);
  silifuzz::EnterSeccompStrictMode();

  RUN_TEST(Runner, EndsAsExpected);
  RUN_TEST(Runner, RegsMismatch);
  RUN_TEST(Runner, MemoryMismatch);
})
