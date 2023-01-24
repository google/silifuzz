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

// Helper binary to test different parts of :harness_tracer functionality.
// Implements a number of modes (controlled by argv[1]).
// Refer to individual *Helper() functions for details.
#include <string.h>
#include <unistd.h>

#include <csignal>
#include <cstdint>

#include "absl/strings/string_view.h"
// The harness tracer looks for syscalls from a tracee. As such we need to
// make raw syscalls without going through the standard C library, which may
// make additional syscalls than the name of a function implies. For example,
// raise() in glibc makes several syscalls internally.
#include "third_party/lss/lss/linux_syscall_support.h"

#if defined(ABSL_HAVE_ADDRESS_SANITIZER) ||   \
    defined(ABSL_HAVE_HWADDRESS_SANITIZER) || \
    defined(ABSL_HAVE_LEAK_SANITIZER) ||      \
    defined(ABSL_HAVE_MEMORY_SANITIZER) || defined(ABSL_HAVE_THREAD_SANITIZER)
#include <sanitizer/common_interface_defs.h>
#endif

namespace {

void ToggleActive() { sys_raise(SIGSTOP); }

void DoWork(int n) {
#if defined(__x86_64__)
  // Regular 0x90 nops don't work under various compile modes due to compiler-
  // inserted NOPs, loop unrolling, etc. Instead, we resort to hardcoding this
  // loop to run exactly `n` xchg instructions.
  asm("1: xchg %%rbx, %%rbx;\n"
      "dec %%rcx;\n"
      "jnz 1b;\n" ::"c"(n)
      :);

#elif defined(__aarch64__)
  register uint64_t x10 asm("x10") = n;
  asm("loop_head%=: subs x10, x10, #1;\n"
      "bne loop_head%=;\n" ::"r"(x10)
      :);
#else
#error "Unsupported architecture"
#endif
}

// Verifies that the tracer can single-step through the tracee
// code. Runs a total of 150 nop instructions with 100 of them while the
// tracer is active.
void SingleStepHelper() {
  // activate the tracer
  ToggleActive();
  DoWork(50);
  // deactive the tracer
  ToggleActive();

  // this is untraced
  DoWork(50);

  // activate the tracer again
  ToggleActive();
  // do more traced work
  DoWork(50);
  ToggleActive();
}

// Verifies that the tracer is able to intercept syscalls (getcpu)
void SyscallHelper() {
  ToggleActive();

  uint32_t cpu = 0;
  // Make syscalls using sys_ as regular libc call we go via vDSO and won't
  // be intercepted by ptrace.
  sys_getcpu(&cpu, nullptr, nullptr);

  ToggleActive();
}

#if defined(__x86_64__)
uint64_t volatile num_sigtrap_raised = 0;
// Counts the number of SIGTRAPs received by the binary.
void SigtrapHandler(int sig, siginfo_t* info, void* ucontext) {
  num_sigtrap_raised++;
}

// Verifies that the tracer correctly delivers signals in both active and
// inactive mode (tests SIGTRAP only). Tries multiple different variants of
// triggering SIGTRAP.
int SignalHelper() {
  struct kernel_sigaction action {};
  action.sa_sigaction_ = SigtrapHandler;
  // Must set SA_NODEFER otherwise the handler gets reset to SIG_DFL
  // https://bugzilla.redhat.com/show_bug.cgi?id=227693
  action.sa_flags = SA_SIGINFO | SA_NODEFER | SA_RESTART;
  sys_sigaction(SIGTRAP, &action, nullptr);

  sys_raise(SIGTRAP);
  __asm__("int3\n");                   // just a regular single-byte x86 trap
  __asm__(".byte 0xcd;.byte 0x03\n");  // int 3
  __asm__(".byte 0xf1\n");             // icebp aka int1
  ToggleActive();
  sys_raise(SIGTRAP);
  __asm__("int3\n");
  __asm__(".byte 0xcd;.byte 0x03\n");
  // TODO(ksteuck): [bug] icebp does not trigger the sig handler in
  // single-stepping mode.
  __asm__(".byte 0xf1\n");
  ToggleActive();
  sys_raise(SIGTRAP);
  __asm__("int3\n");
  __asm__(".byte 0xcd;.byte 0x03\n");
  __asm__(".byte 0xf1\n");

  return num_sigtrap_raised;
}

// Exits with code 1 when SIGUSR1 is received.
void Sigusr1Handler(int sig, siginfo_t* info, void* ucontext) { _exit(1); }

// Verifies that the tracer can inject a signal (SIGUSR1) into
// the tracee when a certain condition is met (getcpu syscall in this case).
int SignalInjectionHelper() {
  struct kernel_sigaction action {};
  action.sa_sigaction_ = Sigusr1Handler;
  action.sa_flags = SA_RESTART | SA_SIGINFO;
  sys_sigaction(SIGUSR1, &action, nullptr);
  ToggleActive();
  unsigned int cpu = -1;
  sys_getcpu(&cpu, nullptr, nullptr);
  // Should never make it here when under tracer.
  return 0;
}

#elif defined(__aarch64__)
// TODO(ncbray): port sys_sigaction to aarch64. Currently it doesn't restore the
// stack correctly.

int SignalHelper() {
  assert(false);
  return -1;
}

int SignalInjectionHelper() {
  assert(false);
  return -1;
}
#else
#error "Unsupported architecture"
#endif

};  // namespace

int main(int argc, char** argv) {
  // This program must be single-threaded.
  // The following call makes sanitizers stop background threads.
#if defined(ABSL_HAVE_ADDRESS_SANITIZER) ||   \
    defined(ABSL_HAVE_HWADDRESS_SANITIZER) || \
    defined(ABSL_HAVE_LEAK_SANITIZER) ||      \
    defined(ABSL_HAVE_MEMORY_SANITIZER) || defined(ABSL_HAVE_THREAD_SANITIZER)
  __sanitizer_sandbox_on_notify(nullptr);
#endif

  absl::string_view msg = "Helper alive\n";
  write(STDOUT_FILENO, msg.data(), msg.size());

  if (strcmp(argv[1], "test-syscall") == 0) {
    SyscallHelper();
  } else if (strcmp(argv[1], "test-singlestep") == 0) {
    SingleStepHelper();
  } else if (strcmp(argv[1], "test-crash") == 0) {
    sys_raise(SIGABRT);
  } else if (strcmp(argv[1], "test-exit") == 0) {
    // do nothing.
  } else if (strcmp(argv[1], "test-signal") == 0) {
    return SignalHelper();
  } else if (strcmp(argv[1], "test-signal-injection") == 0) {
    return SignalInjectionHelper();
  }

  absl::string_view msg2 = "Helper exiting\n";
  write(STDOUT_FILENO, msg2.data(), msg2.size());

  return 0;
}
