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

#include "./util/ucontext/signal_test.h"

#include <signal.h>

#include <cstdint>

#include "gtest/gtest.h"
#include "./util/ucontext/signal.h"
#include "./util/ucontext/ucontext.h"

#if defined(HWADDRESS_SANITIZER)
// This is defined if hwasan is enabled.
extern "C" __attribute__((weak)) void __hwasan_handle_longjmp(const void* sp);
#endif

namespace silifuzz {

FatalSignalHandler* FatalSignalHandler::current_handler_;

FatalSignalHandler::FatalSignalHandler(int signal)
    : signal_(signal), old_({}), saved_context_view_(saved_context_) {
  // Turn off alternate signal stack in case we are running under HWASAN.
  // __hwasan_handle_longjmp() cannot handle split stacks.
  stack_t stack{
      .ss_sp = 0,
      .ss_flags = SS_DISABLE,
      .ss_size = 0,
  };
  EXPECT_EQ(sigaltstack(&stack, &old_stack_), 0);

  struct sigaction action = {};
  action.sa_sigaction = SigAction;
  action.sa_flags = SA_SIGINFO | SA_NODEFER;
  EXPECT_EQ(sigaction(signal_, &action, &old_), 0);
}

FatalSignalHandler::~FatalSignalHandler() {
  EXPECT_EQ(sigaction(signal_, &old_, nullptr), 0);
  EXPECT_EQ(sigaltstack(&old_stack_, nullptr), 0);
}

bool FatalSignalHandler::CaptureSignal(void (*f)(uint64_t), uint64_t arg,
                                       siginfo_t* siginfo, ucontext_t* uc,
                                       ExtraSignalRegs* extra) {
  // Bind pointers
  current_handler_ = this;
  siginfo_result_ = siginfo;
  uc_result_ = uc;
  extra_result_ = extra;

  volatile bool first_time = true;
  bool success = false;
  SaveUContext(&saved_context_);
  if (first_time) {
    first_time = false;
    f(arg);
    ADD_FAILURE() << "Function did not fail as expected.";
  } else {
    success = true;
  }

  // Clean up
  current_handler_ = nullptr;
  siginfo_result_ = nullptr;
  uc_result_ = nullptr;
  extra_result_ = nullptr;

  return success;
}

__attribute__((no_sanitize("memtag"))) void FatalSignalHandler::HandleSignal(
    int signal, siginfo_t* siginfo, ucontext_t* uc) {
  *siginfo_result_ = *siginfo;
  *uc_result_ = *uc;
  SaveExtraSignalRegs(extra_result_);
#if defined(HWADDRESS_SANITIZER)
  // If hwasan is enabled, we need to untag the region between the old and the
  // new stack pointer.
  const uint8_t* dst_sp =
      reinterpret_cast<const uint8_t*>(saved_context_.gregs.GetStackPointer());
  __hwasan_handle_longjmp(dst_sp);

#endif
  RestoreUContextView(saved_context_view_);
}

void FatalSignalHandler::SigAction(int signal, siginfo_t* siginfo, void* uc) {
  current_handler_->HandleSignal(signal, siginfo,
                                 reinterpret_cast<ucontext_t*>(uc));
}

}  // namespace silifuzz
