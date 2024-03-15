/* Copyright 2008-2024 Google LLC
   Contributed by Paul Pluzhnikov <ppluzhnikov@google.com>
   Copyright (C) 2010 Konstantin Belousov <kib@freebsd.org>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.  */

// clang-format off
#include <asm/prctl.h>  // for ARCH_(SET|GET)_(FS|GS)
#include <asm/unistd.h>  // for__NR_arch_prctl
#include "./util/ucontext/x86_64/ucontext_offsets.h"

/* Function body shared by SaveUContext() and SaveUContextNoSyscalls() via file
   inclusion. */

  .cfi_startproc

  /* SaveUContext calls other functions. Establish a stack frame so that
     callees see a correctly aligned stack pointer and stack unwinding works. */
  pushq %rbp
  movq %rsp, %rbp

  /* Save eflags and %r15 and also load GRegSet base to callee-saved register
     %r15 so that it is preserved across calls and syscalls below. */
  pushfq
  pushq %r15
  leaq UCONTEXT_GREGS_OFFSET(%rdi), %r15
  popq GREGS_R15_OFFSET(%r15)
  popq GREGS_EFLAGS_OFFSET(%r15)

  /* Callee saved registers %rbx, %r12-%14. */
  movq %r12, GREGS_R12_OFFSET(%r15)
  movq %r13, GREGS_R13_OFFSET(%r15)
  movq %r14, GREGS_R14_OFFSET(%r15)
  movq %rbx, GREGS_RBX_OFFSET(%r15)

  /* Save argument registers. */
  movq %r8,  GREGS_R8_OFFSET(%r15)
  movq %r9,  GREGS_R9_OFFSET(%r15)
  movq %r10, GREGS_R10_OFFSET(%r15)
  movq %r11, GREGS_R11_OFFSET(%r15)
  movq %rdi, GREGS_RDI_OFFSET(%r15)
  movq %rsi, GREGS_RSI_OFFSET(%r15)
  movq %rdx, GREGS_RDX_OFFSET(%r15)
  movq %rax, GREGS_RAX_OFFSET(%r15)
  movq %rcx, GREGS_RCX_OFFSET(%r15)

  /* We want to save %rsp of the caller before the call instead of the current
   value. We can derived it from the frame pointer. */
  leaq 0x10(%rbp), %rax
  movq %rax, GREGS_RSP_OFFSET(%r15)

  /* Similarly, save %rbp of the caller. */
  movq (%rbp), %rax
  movq %rax, GREGS_RBP_OFFSET(%r15)

  /* Save segment registers. */
  movw %cs, GREGS_CS_OFFSET(%r15)
  movw %gs, GREGS_GS_OFFSET(%r15)
  movw %fs, GREGS_FS_OFFSET(%r15)
  movw %ss, GREGS_SS_OFFSET(%r15)
  movw %ds, GREGS_DS_OFFSET(%r15)
  movw %es, GREGS_ES_OFFSET(%r15)

  /* Skip this if we are not allowed to make syscalls */
#if !defined(UCONTEXT_NO_SYSCALLS)
  /* Save fs_base and gs_base */
  /* Equivalent to the following C++ code
     arch_prctl(ARCH_GET_FS, &context.gregs.fs_base);
     arch_prctl(ARCH_GET_GS, &context.gregs.gs_base);
     This code clobbers %rax, %rcx, %rdx, %rsi, %rdi and %r11 all of which
     get restored later. */
  mov $__NR_arch_prctl, %rax
  mov $ARCH_GET_FS, %rdi
  leaq GREGS_FS_BASE_OFFSET(%r15), %rsi
  syscall
  mov $__NR_arch_prctl, %rax
  mov $ARCH_GET_GS, %rdi
  leaq GREGS_GS_BASE_OFFSET(%r15), %rsi
  syscall
#else
  /* Make sure fs_base and gs_base are initialized. */
  movq $0, GREGS_FS_BASE_OFFSET(%r15)
  movq $0, GREGS_GS_BASE_OFFSET(%r15)
#endif

  /* Save fp state. */
  movq GREGS_RDI_OFFSET(%r15), %rdi
  fxsave64 UCONTEXT_FPREGS_OFFSET(%rdi) /* Address must be 16-aligned.
                                           UContext type ensures that */

  /* Save %rip. It is the PC value after call instruction in caller. */
  movq 8(%rbp), %rax
  movq %rax, GREGS_RIP_OFFSET(%r15)

  /* Restore all argument registers.
     Some we have clobbered above; some might have been clobbered in syscall.
     We do not have to restore these registers (in general a caller of a
     function, SaveUContext() in this case, should not assume that those
     registers do not change), but doing the restore makes the definition,
     behavior, and testing of SaveUContext() and RestoreUContext() simpler
     and more aligned. */
  movq GREGS_R8_OFFSET(%r15), %r8
  movq GREGS_R9_OFFSET(%r15), %r9
  movq GREGS_R10_OFFSET(%r15), %r10
  movq GREGS_R11_OFFSET(%r15), %r11
  movq GREGS_RSI_OFFSET(%r15), %rsi
  movq GREGS_RDX_OFFSET(%r15), %rdx
  movq GREGS_RAX_OFFSET(%r15), %rax
  movq GREGS_RCX_OFFSET(%r15), %rcx
  movq GREGS_RDI_OFFSET(%r15), %rdi
  pushq GREGS_EFLAGS_OFFSET(%r15)
  movq GREGS_R15_OFFSET(%r15), %r15
  popfq

  /* Instructions in the epilogue must not change %rflags. */
  movq %rbp, %rsp
  popq %rbp
  retq
  .cfi_endproc
