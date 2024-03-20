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

// Initialize greg to a unique value that will detect truncation.
.macro pattern_init_greg i
  mov x\i, #\i
  orr x\i, x\i, x\i, lsl 8
  eor x\i, x\i, #0xff00
  orr x\i, x\i, x\i, lsl 48
.endm

// Initialize fpreg to a unique value that will detect truncation or swizzling.
// Note: clobbers x0
.macro pattern_init_fpreg i
  mov w0, \i
  orr w0, w0, w0, lsl 8
  eor w0, w0, #0xff00
  dup v\i\().8h, w0
.endm

  .p2align 2
  .globl  PatternInitVolatileRegs
  .type   PatternInitVolatileRegs, @function
PatternInitVolatileRegs:
  // This is no guarantee anything but the 64 LSB of v8-v15 are preserved, so
  // treat all the FP registers as volatile.
  pattern_init_fpreg 0
  pattern_init_fpreg 1
  pattern_init_fpreg 2
  pattern_init_fpreg 3
  pattern_init_fpreg 4
  pattern_init_fpreg 5
  pattern_init_fpreg 6
  pattern_init_fpreg 7
  pattern_init_fpreg 8
  pattern_init_fpreg 9
  pattern_init_fpreg 10
  pattern_init_fpreg 11
  pattern_init_fpreg 12
  pattern_init_fpreg 13
  pattern_init_fpreg 14
  pattern_init_fpreg 15
  pattern_init_fpreg 16
  pattern_init_fpreg 17
  pattern_init_fpreg 18
  pattern_init_fpreg 19
  pattern_init_fpreg 20
  pattern_init_fpreg 21
  pattern_init_fpreg 22
  pattern_init_fpreg 23
  pattern_init_fpreg 24
  pattern_init_fpreg 25
  pattern_init_fpreg 26
  pattern_init_fpreg 27
  pattern_init_fpreg 28
  pattern_init_fpreg 29
  pattern_init_fpreg 30
  pattern_init_fpreg 31

  pattern_init_greg 1
  pattern_init_greg 2
  pattern_init_greg 3
  pattern_init_greg 4
  pattern_init_greg 5
  pattern_init_greg 6
  pattern_init_greg 7
  pattern_init_greg 8
  pattern_init_greg 9
  pattern_init_greg 10
  pattern_init_greg 11
  pattern_init_greg 12
  pattern_init_greg 13
  pattern_init_greg 14
  pattern_init_greg 15
  pattern_init_greg 16
  pattern_init_greg 17
  ret
  .size   PatternInitVolatileRegs, .-PatternInitVolatileRegs

  .p2align 2
  .globl  PatternInitStableRegs
  .type   PatternInitStableRegs, @function
PatternInitStableRegs:
  pattern_init_greg 18
  pattern_init_greg 19
  pattern_init_greg 20
  pattern_init_greg 21
  pattern_init_greg 22
  pattern_init_greg 23
  pattern_init_greg 24
  pattern_init_greg 25
  pattern_init_greg 26
  pattern_init_greg 27
  pattern_init_greg 28
  ret
  .size   PatternInitStableRegs, .-PatternInitStableRegs

  // Helper function to check we're saving the general purpose registers.
  .p2align 2
  .globl  SaveUContextTwice
  .type   SaveUContextTwice, @function
SaveUContextTwice:
  // Save callee saved registers.
  stp x29, x30, [sp, #-16]!
  mov x29, sp // Setup the frame pointer.
  stp x27, x28, [sp, #-16]!
  stp x25, x26, [sp, #-16]!
  stp x23, x24, [sp, #-16]!
  stp x21, x22, [sp, #-16]!
  stp x19, x20, [sp, #-16]!
  // On Linux x18 is usually caller saved, but shadow stack can change this.
  // Be conservative, and behave as if x18 is callee saved.
  stp x18, xzr, [sp, #-16]!

  // Save the called saved FP registers.
  // Note: these store instructions cannot be encoded with pre-index offsets.
  sub sp, sp, 32
  st1 {v12.1d, v13.1d, v14.1d, v15.1d}, [sp]
  sub sp, sp, 32
  st1 {v8.1d, v9.1d, v10.1d, v11.1d}, [sp]

  // Save the two context pointers.
  stp x0, x1, [sp, #-16]!

  // Only init the stable registers once so it's obvious if they're clobbered.
  bl PatternInitStableRegs

  // Save the first context.
  bl PatternInitVolatileRegs
  ldr x0, [sp, #0]
  bl SAVE_UCONTEXT
FirstContextPC:

  // Save the second context.
  bl PatternInitVolatileRegs
  ldr x0, [sp, #8]
  bl SAVE_UCONTEXT
SecondContextPC:

  // Discard the context pointers.
  add sp, sp, #16

  // Restore FP registers.
  ld1 {v8.1d, v9.1d, v10.1d, v11.1d}, [sp], #32
  ld1 {v12.1d, v13.1d, v14.1d, v15.1d}, [sp], #32

  // Restore callee saved registers.
  ldp x18, xzr, [sp], #16
  ldp x19, x20, [sp], #16
  ldp x21, x22, [sp], #16
  ldp x23, x24, [sp], #16
  ldp x25, x26, [sp], #16
  ldp x27, x28, [sp], #16
  ldp x29, x30, [sp], #16

  // Return expected offset between program counters.
  mov x0, SecondContextPC - FirstContextPC
  ret
  .size   SaveUContextTwice, .-SaveUContextTwice


  // Helper function to check we're saving the actual NZCV register rather than
  // corrupting it while saving the context.
  .p2align 2
  .globl  NCZVSaveUContext
  .type   NCZVSaveUContext, @function
NCZVSaveUContext:
  // Save return address.
  stp x29, x30, [sp, #-16]!

  // Clear carry.
  adds wzr, wzr, wzr

  // 32-bit add, set flags, discard result.
  adds wzr, w1, w2

  // Save the context.
  bl SAVE_UCONTEXT

  // Return.
  ldp x29, x30, [sp], #16
  ret
  .size   NCZVSaveUContextTwice, .-NCZVSaveUContext


  // Helper instruction sequence that saves the state on entry to x0 and then
  // immediately restores it to x1. This allows us to record the state after a
  // restore and then switch back to the original caller.
  .p2align 2
  .globl  SaveThenRestore
  .type   SaveThenRestore, @function
SaveThenRestore:
  // Save the arguments because SaveUContext may clobber them.
  stp x0, x1, [sp, #-16]!

  // Save the current context.
  bl SAVE_UCONTEXT

  // Restore the context view pointed to by the second argument.
  ldr x0, [sp, #8]
  bl RESTORE_UCONTEXT_VIEW
  .size   SaveThenRestore, .-SaveThenRestore


  // Swap stacks and the restore the context in view. This lets us see the
  // effects of RestoreUContextView() both on the stack we're restoring in
  // to and the stack we're restoring out on.
  .p2align 2
  .globl  CaptureStack
  .type   CaptureStack, @function
CaptureStack:
  // x0 is a view of the context we will restore.
  // x1 is alternate stack.
  mov sp, x1
  bl RESTORE_UCONTEXT_VIEW

  .size   CaptureStack, .-CaptureStack

  .section        .note.GNU-stack,"",@progbits
