/* Copyright 2008-2022 Google LLC
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

  /* Save eflags. */
  pushfq
  popq UCONTEXT_GREGS_EFLAGS_OFFSET(%rdi)

  /* Save %R15 in ucontext. Then copy ucontext (%RDI) ptr in %R15 to allow
    later code use %RDI for syscalls without the need to push/pop every time. */
  movq %r15, UCONTEXT_GREGS_R15_OFFSET(%rdi)
  mov %rdi, %r15

  /* Callee saved: RBX, RBP, R12-R14  */
  movq %r12, UCONTEXT_GREGS_R12_OFFSET(%r15)
  movq %r13, UCONTEXT_GREGS_R13_OFFSET(%r15)
  movq %r14, UCONTEXT_GREGS_R14_OFFSET(%r15)
  movq %rbp, UCONTEXT_GREGS_RBP_OFFSET(%r15)
  movq %rbx, UCONTEXT_GREGS_RBX_OFFSET(%r15)

  /* Save argument registers. */
  movq %r8,  UCONTEXT_GREGS_R8_OFFSET(%r15)
  movq %r9,  UCONTEXT_GREGS_R9_OFFSET(%r15)
  movq %r10, UCONTEXT_GREGS_R10_OFFSET(%r15)
  movq %r11, UCONTEXT_GREGS_R11_OFFSET(%r15)
  movq %rdi, UCONTEXT_GREGS_RDI_OFFSET(%r15)
  movq %rsi, UCONTEXT_GREGS_RSI_OFFSET(%r15)
  movq %rdx, UCONTEXT_GREGS_RDX_OFFSET(%r15)
  movq %rax, UCONTEXT_GREGS_RAX_OFFSET(%r15)
  movq %rcx, UCONTEXT_GREGS_RCX_OFFSET(%r15)

  /* Save segment registers. */
  movw %cs, UCONTEXT_GREGS_CS_OFFSET(%r15)
  movw %gs, UCONTEXT_GREGS_GS_OFFSET(%r15)
  movw %fs, UCONTEXT_GREGS_FS_OFFSET(%r15)
  movw %ss, UCONTEXT_GREGS_SS_OFFSET(%r15)
  movw %ds, UCONTEXT_GREGS_DS_OFFSET(%r15)
  movw %es, UCONTEXT_GREGS_ES_OFFSET(%r15)

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
  leaq UCONTEXT_GREGS_FS_BASE_OFFSET(%r15), %rsi
  syscall
  mov $__NR_arch_prctl, %rax
  mov $ARCH_GET_GS, %rdi
  leaq UCONTEXT_GREGS_GS_BASE_OFFSET(%r15), %rsi
  syscall
#else
  /* Make sure fs_base and gs_base are initialized. */
  movq $0, UCONTEXT_GREGS_FS_BASE_OFFSET(%r15)
  movq $0, UCONTEXT_GREGS_GS_BASE_OFFSET(%r15)
#endif

  /* Save fp state. */
  leaq UCONTEXT_FPREGS_OFFSET(%r15), %r8
  fxsave64 (%r8) /* Value of r8 must be 16-aligned.
                    UContext type ensures that */

  /* Save rsp. */
  leaq 8(%rsp), %rax /* Exclude this call. */
  movq %rax, UCONTEXT_GREGS_RSP_OFFSET(%r15)

  /* Save rip. */
  movq 0(%rsp), %rax
  movq %rax, UCONTEXT_GREGS_RIP_OFFSET(%r15)

  /* Restore all argument registers.
     Some we have clobbered above; some might have been clobbered in syscall.
     We do not have to restore these registers (in general a caller of a
     function, SaveUContext() in this case, should not assume that those
     registers do not change), but doing the restore makes the definition,
     behavior, and testing of SaveUContext() and RestoreUContext() simpler
     and more aligned. */
  movq UCONTEXT_GREGS_R8_OFFSET(%r15), %r8
  movq UCONTEXT_GREGS_R9_OFFSET(%r15), %r9
  movq UCONTEXT_GREGS_R10_OFFSET(%r15), %r10
  movq UCONTEXT_GREGS_R11_OFFSET(%r15), %r11
  movq UCONTEXT_GREGS_RSI_OFFSET(%r15), %rsi
  movq UCONTEXT_GREGS_RDX_OFFSET(%r15), %rdx
  movq UCONTEXT_GREGS_RAX_OFFSET(%r15), %rax
  movq UCONTEXT_GREGS_RCX_OFFSET(%r15), %rcx
  mov %r15, %rdi
  movq UCONTEXT_GREGS_R15_OFFSET(%r15), %r15

  /* Restore eflags. */
  pushq UCONTEXT_GREGS_EFLAGS_OFFSET(%rdi)
  popfq

  retq
  .cfi_endproc
