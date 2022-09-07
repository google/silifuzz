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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_SIGNAL_TEST_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_SIGNAL_TEST_H_

#include <signal.h>

#include <cstdint>

#include "./util/ucontext/signal.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {

// This class sets up a signal handler and then captures the result of the
// signal handler after invoking a test function.
// This class cleans up the signal handler when it is destroyed.
// This class is not thread safe in the slightest because signal handlers are
// global state and the implentation also has to rely on global state to get
// information from the signal handler back to the test.
class FatalSignalHandler {
 public:
  explicit FatalSignalHandler(int signal);
  ~FatalSignalHandler();

  bool CaptureSignal(void (*f)(uint64_t), uint64_t arg, siginfo_t* siginfo,
                     ucontext_t* uc, ExtraSignalRegs* extra);

 private:
  void HandleSignal(int signal, siginfo_t* siginfo, ucontext_t* uc);

  static void SigAction(int signal, siginfo_t* siginfo, void* uc);

  // The signal that we are catching.
  int signal_;

  // The signal handler state before we hooked it.
  struct sigaction old_;

  // The context before we tried to trigger the signal handler.
  UContext saved_context_;

  // Pointers to where we should capture the result of the signal handler.
  siginfo_t* siginfo_result_;
  ucontext_t* uc_result_;
  ExtraSignalRegs* extra_result_;

  // The sigaction handler does not have a user context, so we need to use a
  // global to thunk back into the object.
  static FatalSignalHandler* current_handler_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_SIGNAL_TEST_H_
