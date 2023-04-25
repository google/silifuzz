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

// This file contains utilities useful for code that calls ptrace(2).

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_PTRACE_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_PTRACE_UTIL_H_

#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>

#include <cerrno>
#include <optional>

#include "./util/checks.h"

namespace silifuzz {

// waitpid(2) wrapper that is EINTR- and Fiber-safe.
// (Some callers might not care about the latter.)
// Returns true iff the wait was successful, false if waitpid raised ECHILD.
// and check-fails otherwise.
bool WaitpidOrDie(pid_t pid, int* status, int options);

// Calls waitpid(2) expecting `pid` to stop, e.g. after receiving
// PTRACE_INTERRUPT or raising SIGSTOP in PTRACE_SEIZE-ed state.
// Returns true iff `pid` has indeed stopped and fills *status
// with the waitpid(2) status if we could obtain one, and nullopt otherwise.
bool WaitpidToStop(pid_t pid, std::optional<int>* status);

// ptrace(2) wrapper that check-fails if ptrace returns -1.
// CAVEAT: cannot be used with commands that return a useful value
// (e.g. PTRACE_PEEK*).
template <typename RequestT,  // because enum arg type of ptrace() is not public
          typename DataT = void*>
void PTraceOrDie(RequestT request, pid_t pid, void* addr, DataT data);

// A variant of PTraceOrDie() that is fine with ESRCH and EPERM errors.
// Particularly meant for PTRACE_SEIZE.
// Returns iff ptrace() has succeeded.
template <typename RequestT, typename DataT = void*>
bool PTraceOrDieExitedOk(RequestT request, pid_t pid, void* addr, DataT data);

// ========================================================================= //
// Impls only below this point.

template <typename RequestT, typename DataT>
void PTraceOrDie(RequestT request, pid_t pid, void* addr, DataT data) {
  if (ptrace(request, pid, addr, data) == -1) {
    LOG_FATAL("ptrace request ", request, " on ", pid,
              " failed: ", strerror(errno));
  }
}

template <typename RequestT, typename DataT>
bool PTraceOrDieExitedOk(RequestT request, pid_t pid, void* addr, DataT data) {
  if (ptrace(request, pid, addr, data) == -1) {
    if (errno == ESRCH || errno == EPERM) {
      // Happens when process with `pid` quits before we do this request,
      // but the parent process hasn't called waitpid() on it yet.
      return false;
    } else {
      LOG_FATAL("ptrace request ", request, " on ", pid,
                " failed: ", strerror(errno));
    }
  }
  return true;
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_PTRACE_UTIL_H_
