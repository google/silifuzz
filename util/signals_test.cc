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
//
// signal utilities.

#include "./util/signals.h"

#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>

#include "gtest/gtest.h"
#include "./util/checks.h"

namespace silifuzz {
namespace {

TEST(Signals, IgnoreSignal) {
  int pipefd[2];
  ASSERT_EQ(pipe(pipefd), 0);

  // Close the read end. Child should get a EPIPE on write.
  close(pipefd[0]);

  EXPECT_EXIT(
      {
        // Revert SIGPIPE to default to ensure IgnoreSignal() works.
        signal(SIGPIPE, SIG_DFL);

        IgnoreSignal(SIGPIPE);
        char dummy = 0;
        ssize_t result;
        do {
          result = write(pipefd[1], &dummy, sizeof(dummy));
        } while (result == -1 && errno == EINTR);
        if (result != -1) {
          LOG_ERROR("write succeeded unexpectedly");
          exit(1);
        }
        if (errno != EPIPE) {
          LOG_ERROR("unexpected errno ", strerror(errno));
          exit(2);
        }
        LOG_INFO("Success");
        exit(0);
      },
      testing::ExitedWithCode(0), "Success");

  close(pipefd[1]);
}

}  // namespace
}  // namespace silifuzz
