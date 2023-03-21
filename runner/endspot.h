// Copyright 2023 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_ENDSPOT_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_ENDSPOT_H_

#include <cstdint>

#include "./util/ucontext/signal.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

// Description of an execution endpoint plus the associated CPU and signal
// state.
struct EndSpot {
  using gregs_t = GRegSet<Host>;
  using fpregs_t = FPRegSet<Host>;

  // The signal that was triggered. 0 if none.
  int signum;

  // The siginfo_t::si_addr value if relevant for `signum`:
  // the address that causes the signal.
  uintptr_t sig_address;

  // Arch-specific regs related to the signal.
  SignalRegSet sigregs;

  // Values for all the registers.
  gregs_t* gregs;
  fpregs_t* fpregs;

  // Logs this EndSpot via LOG_INFO().
  // Not a DebugString() so that we can use this in nolibc mode.
  void Log() const;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_ENDSPOT_H_
