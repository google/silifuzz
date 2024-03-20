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

#ifdef UCONTEXT_NO_SYSCALLS
#define SAVE_UCONTEXT SaveUContextNoSyscalls
#define RESTORE_UCONTEXT_VIEW RestoreUContextViewNoSyscalls
#else
#define SAVE_UCONTEXT SaveUContext
#define RESTORE_UCONTEXT_VIEW RestoreUContextView
#endif

  .text


  // Swap stacks and the restore the context. This lets us see the effects of
  // RestoreUContext() both on the stack we're restoring in to and the stack
  // we're restoring out on.
  .p2align 2
  .globl  CaptureStack
  .type   CaptureStack, @function
CaptureStack:
  // rdi is the context view we will restore.
  // rsi is the alternate stack.

  movq %rsi, %rsp
  jmp RESTORE_UCONTEXT_VIEW

  .size   CaptureStack, .-CaptureStack

  .section        .note.GNU-stack,"",@progbits
