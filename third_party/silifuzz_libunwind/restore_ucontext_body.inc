/* Copyright 2007-2022 Google LLC
   Contributed by Arun Sharma <arun.sharma@google.com>
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

/* Function body shared by RestoreUContext() and RestoreUContextNoSyscalls()
   via file inclusion. */

  .cfi_startproc

  /* RestoreUContext calls other functions. Establish a stack frame so that
     callees see a correctly aligned stack pointer and stack unwinding works. */
  pushq %rbp
  movq %rsp, %rbp

  /* Load GRegSet and FPRegSet pointers into callee save registers so that
     they are preserved across calls and syscalls below. These will be restored
     at the exit of this function */
  leaq UCONTEXT_FPREGS_OFFSET(%rdi), %r14
  leaq UCONTEXT_GREGS_OFFSET(%rdi), %r15

  /*
     if (HasAVX512Registers()) {
       ClearAVX512OnlyState();
     }

     This has to done early as the callees below clobber registers. We must do
     this before restoring any caller-saved registers.
   */
  call HasAVX512Registers
  testb %al, %al
  je 1f
  call ClearAVX512OnlyState
1:

  /* Restore fp state. */
  vzeroupper
  fxrstor64 (%r14) /* Value of r14 must be 16-aligned.
                      UContext type ensures that. */

  movw GREGS_ES_OFFSET(%r15), %es
  movw GREGS_DS_OFFSET(%r15), %ds
  movw GREGS_FS_OFFSET(%r15), %fs
  movw GREGS_GS_OFFSET(%r15), %gs
  /* We do not restore CS and SS - see comments for SaveUContext()
     and RestoreUContext() in ucontext.h. */
  /* Changing %ss is fraught with danger
     (https://www.felixcloutier.com/x86/mov#operation)
  movw GREGS_SS_OFFSET(%r15), %ss */
  /* %cs cannot be changed with a MOV (causes #UD) https://stackoverflow.com/questions/57314216
  movw GREGS_SS_OFFSET(%r15), %cs */

/* Skip this if we are not allowed to make syscalls */
#if !defined(UCONTEXT_NO_SYSCALLS)
  /* Restore FS_BASE and GS_BASE.
     Roughly equivalent to the following C++ code:
     arch_prctl(ARCH_SET_FS, context.gregs.fs_base);
     arch_prctl(ARCH_SET_GS, context.gregs.gs_base);
     Clobbers %rax, %rsi, %rdi, %rcx and %r11 all which get restored
     later. */
  mov $__NR_arch_prctl, %rax
  mov $ARCH_SET_FS, %rdi
  movq GREGS_FS_BASE_OFFSET(%r15), %rsi
  syscall
  mov $__NR_arch_prctl, %rax
  mov $ARCH_SET_GS, %rdi
  movq GREGS_GS_BASE_OFFSET(%r15), %rsi
  syscall
#endif /* UCONTEXT_NO_SYSCALLS */

  /* Restore bulk of the registers. */
  movq GREGS_R8_OFFSET(%r15),%r8
  movq GREGS_R9_OFFSET(%r15),%r9
  movq GREGS_R10_OFFSET(%r15),%r10
  movq GREGS_R11_OFFSET(%r15),%r11
  movq GREGS_RBX_OFFSET(%r15),%rbx
  movq GREGS_RBP_OFFSET(%r15),%rbp
  movq GREGS_R12_OFFSET(%r15),%r12
  movq GREGS_R13_OFFSET(%r15),%r13
  movq GREGS_R14_OFFSET(%r15),%r14
  movq GREGS_RSI_OFFSET(%r15),%rsi
  movq GREGS_RDI_OFFSET(%r15),%rdi
  movq GREGS_RDX_OFFSET(%r15),%rdx
  movq GREGS_RAX_OFFSET(%r15),%rax
  movq GREGS_RSP_OFFSET(%r15),%rsp

  /* Push the return address on the restored stack for below retq to use. */
  movq GREGS_RIP_OFFSET(%r15),%rcx
  pushq %rcx

  /* Restore rcx. */
  movq GREGS_RCX_OFFSET(%r15),%rcx

  /* Push eflags on the restored stack for popfq below to use. */
  pushq GREGS_EFLAGS_OFFSET(%r15)

  /* Restore r15. */
  movq GREGS_R15_OFFSET(%r15),%r15

  /* Restore eflags. */
  popfq

  /* Restore rip. */
  retq
  .cfi_endproc

