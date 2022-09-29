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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_SUBPROCESS_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_SUBPROCESS_H_

#include <sys/types.h>

#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/time/time.h"

namespace silifuzz {

// Minimalistic utility class for launching sub-processes and collecting
// stdout.
// This class is thread-compatible.
class Subprocess {
 public:
  // How to map a file descriptor in the child process.
  // Current this applies only to stderr.
  enum FileDescriptorMapping {
    kNoMapping = 0,  // leave file descriptor unmapped.
    kMapToStdout,    // map to stdout
    kMapToDevNull,   // send output to /dev/null.
  };

  // Represent options for running the subprocess.
  class Options {
   public:
    // Returns default Options instance.
    static const Options& Default() {
      static Options* opts = new Options();
      return *opts;
    }

    // Sets resource limits for the subprocess. See man setrlimit for details
    // on the parameters.
    Options& SetRLimit(int resource, uint64_t soft, uint64_t hard) {
      rlimit_tuples_.push_back({resource, soft, hard});
      return *this;
    }

    // Sets an interval timer for the subprocess. See man setitimer for
    // details. `which` must be one of ITIMER_VIRTUAL or ITIMER_REAL.
    Options& SetITimer(int which, absl::Duration v) {
      struct itimerval itimer;
      itimer.it_value.tv_sec = absl::ToInt64Seconds(v);
      itimer.it_value.tv_usec =
          absl::ToInt64Microseconds(v - absl::Seconds(itimer.it_value.tv_sec));
      itimer.it_interval.tv_sec = itimer.it_interval.tv_usec = 0;
      itimer_vals_.push_back({which, itimer});
      return *this;
    }

    Options& MapStderr(FileDescriptorMapping map) {
      map_stderr_ = map;
      return *this;
    }

    Options& DisableAslr(bool v) {
      disable_aslr_ = v;
      return *this;
    }

    Options& SetParentDeathSignal(int signal) {
      parent_death_signal_ = signal;
      return *this;
    }

   private:
    friend class Subprocess;  // for rlimit_tuples_ and itimer_vals_ access.

    // How stderr of the child process will be mapped.
    // See defintion of FileDescriptorMapping above.
    FileDescriptorMapping map_stderr_ = kNoMapping;

    // Disable ASLR.
    bool disable_aslr_ = false;

    // If greater than 0, send this signal to the child process if the parent
    // process dies.
    int parent_death_signal_ = 0;

    // Represents setrlimit(2) args.
    struct RLimitTuple {
      int resource = 0;
      uint64_t soft_limit = 0;
      uint64_t hard_limit = 0;
    };
    struct ITimerVal {
      int which;
      struct itimerval value;
    };

    // setrlimit(2) caps for the child process.
    std::vector<RLimitTuple> rlimit_tuples_;

    // setitimer(2) timers for the child process.
    std::vector<ITimerVal> itimer_vals_;
  };

  Subprocess(const Options& options = Options::Default());
  ~Subprocess();

  // Not movable or copyable, has I/O state.
  Subprocess(const Subprocess&) = delete;
  Subprocess& operator=(const Subprocess&) = delete;
  Subprocess(Subprocess&&) = delete;
  Subprocess& operator=(Subprocess&&) = delete;

  // Starts the subprocess.
  // NOTE: this API is not reentrant but can be called multiple times
  // in when paired wit Communicate().
  absl::Status Start(const std::vector<std::string>& argv);

  // Consumes the stdout of the process and waits for it to exit.
  // Returns the process exit status.
  int Communicate(std::string* stdout_output);

  // Returns the child process PID or -1 when no process is running.
  pid_t pid() const { return child_pid_; }

 private:
  static void GlobalInit();
  // PID of the child process.
  pid_t child_pid_;

  // File descriptor for our end of the child's stdout pipe.
  int child_stdout_;

  // C-tor parameter.
  Options options_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_SUBPROCESS_H_
