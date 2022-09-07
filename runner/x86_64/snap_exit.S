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

/*
 * Snap exit point implementation for x86_64
 *
 * After execution, a Snap calls a pre-defined exit address that jumps to
 * here. The exit point saves register state and jumps back immediately to the
 * runner via RunerReentry().
 *
 * This code is not thread-safe as it uses some globals without locks.
 */
  .text
  .align 16
  .global SnapExitImpl
  .type SnapExitImpl, @function

SnapExitImpl:
  /*
   * We need the minimum of %rsp and %rdi to call SaveUContextNoSyscalls().
   * These two are saved here in a dedicated stack and are passed to
   * RunnerReentry() later for fixing up snap_exit_context.
   */

  /*
   * Effectively switch to the new stack and push old %rsp onto new stack.
   * Other than the registers explicitly saved here, we should not change any
   * register before calling SaveUContextNoSyscalls() below. In particular,
   * the instructions for saving %rsp and %rdi below are known to not change
   * eflags register.
   */
  movq %rsp, .LSnapExitStackEnd-8(%rip)  /* pushes current %rsp
                                            onto SnapExitStack */
  leaq .LSnapExitStackEnd-8(%rip), %rsp
  pushq %rdi

  /*
   * Save register state except %rsp and %rdi. Note that %rip saved is the
   * address after the call below. The real end point address will be
   * reconstructed by RunnerReentry(). See there for details.
   */
  leaq snap_exit_context(%rip), %rdi
  call SaveUContextNoSyscalls

  /* Jump to C++ code for re-entry to runner. */
  popq %rdi /* rdi at snap exit */
  popq %rsi /* rsp at snap exit */
  jmp RunnerReentry

 .size SnapExitImpl, .-SnapExitImpl

/*
 * This must be big enough for all the functions from entry to SnapExitImpl()
 * until exit of RunnerReentry(), which switches back to the runner's stack
 * before jumping into the Snap. The actual stack size is rounded up to the
 * nearest multiple of 16.
 */
#define SNAP_EXIT_STACK_SIZE 65536

  .bss
  .align 16
  .type .LSnapExitStack, @object
.LSnapExitStack:
  .zero SNAP_EXIT_STACK_SIZE
  .align 16  /* Make sure stack end is aligned properly. */
.LSnapExitStackEnd:
  .size .LSnapExitStack, .-.LSnapExitStack

  /* We do not need executable stack.  */
  .section        .note.GNU-stack,"",@progbits
