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

  /* Save ucontext (%RDI) ptr in %R15 to allow later code use %RDI for
     syscalls without the need to push/pop every time. */
  mov %rdi, %r15

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
  leaq UCONTEXT_FPREGS_OFFSET(%r15), %r8
  fxrstor64 (%r8) /* Value of r8 must be 16-aligned.
                     UContext type ensures that. */

  movw UCONTEXT_GREGS_ES_OFFSET(%r15), %es
  movw UCONTEXT_GREGS_DS_OFFSET(%r15), %ds
  movw UCONTEXT_GREGS_FS_OFFSET(%r15), %fs
  movw UCONTEXT_GREGS_GS_OFFSET(%r15), %gs
  /* We do not restore CS and SS - see comments for SaveUContext()
     and RestoreUContext() in ucontext.h. */
  /* Changing %ss is fraught with danger
     (https://www.felixcloutier.com/x86/mov#operation)
  movw UCONTEXT_GREGS_SS_OFFSET(%r15), %ss */
  /* %cs cannot be changed with a MOV (causes #UD) https://stackoverflow.com/questions/57314216
  movw UCONTEXT_GREGS_SS_OFFSET(%r15), %cs */

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
  movq UCONTEXT_GREGS_FS_BASE_OFFSET(%r15), %rsi
  syscall
  mov $__NR_arch_prctl, %rax
  mov $ARCH_SET_GS, %rdi
  movq UCONTEXT_GREGS_GS_BASE_OFFSET(%r15), %rsi
  syscall
#endif /* UCONTEXT_NO_SYSCALLS */

  /* Restore bulk of the registers. */
  movq UCONTEXT_GREGS_R8_OFFSET(%r15),%r8
  movq UCONTEXT_GREGS_R9_OFFSET(%r15),%r9
  movq UCONTEXT_GREGS_R10_OFFSET(%r15),%r10
  movq UCONTEXT_GREGS_R11_OFFSET(%r15),%r11
  movq UCONTEXT_GREGS_RBX_OFFSET(%r15),%rbx
  movq UCONTEXT_GREGS_RBP_OFFSET(%r15),%rbp
  movq UCONTEXT_GREGS_R12_OFFSET(%r15),%r12
  movq UCONTEXT_GREGS_R13_OFFSET(%r15),%r13
  movq UCONTEXT_GREGS_R14_OFFSET(%r15),%r14
  movq UCONTEXT_GREGS_RSI_OFFSET(%r15),%rsi
  movq UCONTEXT_GREGS_RDI_OFFSET(%r15),%rdi
  movq UCONTEXT_GREGS_RDX_OFFSET(%r15),%rdx
  movq UCONTEXT_GREGS_RAX_OFFSET(%r15),%rax
  movq UCONTEXT_GREGS_RSP_OFFSET(%r15),%rsp

  /* Push the return address on the restored stack for below retq to use. */
  movq UCONTEXT_GREGS_RIP_OFFSET(%r15),%rcx
  pushq %rcx

  /* Restore rcx. */
  movq UCONTEXT_GREGS_RCX_OFFSET(%r15),%rcx

  /* Push eflags on the restored stack for popfq below to use. */
  pushq UCONTEXT_GREGS_EFLAGS_OFFSET(%r15)

  /* Restore r15. */
  movq UCONTEXT_GREGS_R15_OFFSET(%r15),%r15

  /* Restore eflags. */
  popfq

  /* Restore rip. */
  retq
  .cfi_endproc

