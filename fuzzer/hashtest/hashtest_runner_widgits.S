// Copyright 2024 The Silifuzz Authors.
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


.text


  .global NopTest
  .type NopTest, @function
NopTest:
  .cfi_startproc
  ret
  .cfi_endproc
  .size NopTest, . - NopTest


  .global RunHashTest512
  .type RunHashTest512, @function
RunHashTest512:
  .cfi_startproc

  // Set the frame pointer
  push   %rbp
  mov    %rsp, %rbp

  // Save callee saved registers
  push %rbx
  push %r12
  push %r13
  push %r14
  push %r15

  // Save output buffer
  push %rcx

  // arg0 / RDI: pointer to the test function
  // arg1 / RSI: number of iterations
  // arg2 / RDX: input entropy
  // arg3 / RCX: output entropy

  // HACK: clear TMP vector registers
  // Needed because some SSE instructions will perserve the upper bits of a
  // register.
  vpxorq  %zmm0, %zmm0, %zmm0
  vpxorq  %zmm1, %zmm1, %zmm1
  vpxorq  %zmm2, %zmm2, %zmm2
  vpxorq  %zmm3, %zmm3, %zmm3
  vpxorq  %zmm4, %zmm4, %zmm4
  vpxorq  %zmm5, %zmm5, %zmm5
  vpxorq  %zmm6, %zmm6, %zmm6
  vpxorq  %zmm7, %zmm7, %zmm7

  // Load the vector entropy
  // We do this first because it has the strongest alignment requirements.
  vmovdqa64 0x000(%rdx), %zmm8
  vmovdqa64 0x040(%rdx), %zmm9
  vmovdqa64 0x080(%rdx), %zmm10
  vmovdqa64 0x0C0(%rdx), %zmm11
  vmovdqa64 0x100(%rdx), %zmm12
  vmovdqa64 0x140(%rdx), %zmm13
  vmovdqa64 0x180(%rdx), %zmm14
  vmovdqa64 0x1C0(%rdx), %zmm15
  add $0x200, %rdx

  // Note: zmm16-zmm31 currently unused
  // TODO(ncbray): can these registers be targeted by AVX instructions?
  // If not there won't be a reason to clear them.

  // Load the mask entropy
  // Requires AVX512BW, but currently all the AVX512 chips we run on support
  // this extension.
  kmovq 0x00(%rdx), %k4
  kmovq 0x08(%rdx), %k5
  kmovq 0x10(%rdx), %k6
  kmovq 0x18(%rdx), %k7
  add $0x20, %rdx

  // Load the MMX entropy
  mov 0x00(%rdx), %mm4
  mov 0x08(%rdx), %mm5
  mov 0x10(%rdx), %mm6
  mov 0x18(%rdx), %mm7
  add $0x20, %rdx

  // Load the GP entropy
  mov 0x00(%rdx), %r9
  mov 0x08(%rdx), %r10
  mov 0x10(%rdx), %r11
  mov 0x18(%rdx), %r12
  mov 0x20(%rdx), %r13
  mov 0x28(%rdx), %r14
  mov 0x30(%rdx), %r15
  add $0x38, %rdx

  // Set the number of iterations
  mov %rsi, %r8

  // Clear the GP TMP registers
  // This is needed because 8/16-bit register writes do not zero the upper bits
  // of a GP register. The HashTest generator currently does not understand this
  // means that a 8/16-bit write effectively "reads" from the output. It is
  // unclear if the generator should be fixed, however, as this doesn't affect
  // determinisim if the registers are cleared first.
  // RDI is also affected, but we know its value will be constant (the address
  // of the test funciton).
  xor %rax, %rax
  xor %rcx, %rcx
  xor %rdx, %rdx
  xor %rbx, %rbx
  xor %rbp, %rbp
  xor %rsi, %rsi

  // Init flags
  test %al, %al

  // Invoke the test
  // TODO(ncbray): this leaves RDI dirty, should it need to be cleared?
  call *%rdi

  // Recover output buffer
  pop %rcx

  // Load the vector entropy
  // We do this first because it has the strongest alignment requirements
  vmovdqa64 %zmm8, 0x000(%rcx)
  vmovdqa64 %zmm9, 0x040(%rcx)
  vmovdqa64 %zmm10, 0x080(%rcx)
  vmovdqa64 %zmm11, 0x0C0(%rcx)
  vmovdqa64 %zmm12, 0x100(%rcx)
  vmovdqa64 %zmm13, 0x140(%rcx)
  vmovdqa64 %zmm14, 0x180(%rcx)
  vmovdqa64 %zmm15, 0x1C0(%rcx)
  add $0x200, %rcx

  // Save the mask entropy
  kmovq %k4, 0x00(%rcx)
  kmovq %k5, 0x08(%rcx)
  kmovq %k6, 0x10(%rcx)
  kmovq %k7, 0x18(%rcx)
  add $0x20, %rcx

  // Store the MMX entropy
  mov %mm4, 0x00(%rcx)
  mov %mm5, 0x08(%rcx)
  mov %mm6, 0x10(%rcx)
  mov %mm7, 0x18(%rcx)
  add $0x20, %rcx

  // Save the GP entropy
  mov %r9, 0x00(%rcx)
  mov %r10, 0x08(%rcx)
  mov %r11, 0x10(%rcx)
  mov %r12, 0x18(%rcx)
  mov %r13, 0x20(%rcx)
  mov %r14, 0x28(%rcx)
  mov %r15, 0x30(%rcx)
  add $0x38, %rcx

  // Restore callee saved registers
  pop %r15
  pop %r14
  pop %r13
  pop %r12
  pop %rbx

  // Restore the frame pointer
  pop    %rbp

  // Return
  ret

  .cfi_endproc
  .size RunHashTest512, . - RunHashTest512


  .global RunHashTest256
  .type RunHashTest256, @function
RunHashTest256:
  .cfi_startproc

  // Set the frame pointer
  push   %rbp
  mov    %rsp, %rbp

  // Save callee saved registers
  push %rbx
  push %r12
  push %r13
  push %r14
  push %r15

  // Save output buffer
  push %rcx

  // arg0 / RDI: pointer to the test function
  // arg1 / RSI: number of iterations
  // arg2 / RDX: input entropy
  // arg3 / RCX: output entropy

  // HACK: clear TMP vector registers
  // Needed because some SSE instructions will perserve the upper bits of a
  // register.
  vpxor  %ymm0, %ymm0, %ymm0
  vpxor  %ymm1, %ymm1, %ymm1
  vpxor  %ymm2, %ymm2, %ymm2
  vpxor  %ymm3, %ymm3, %ymm3
  vpxor  %ymm4, %ymm4, %ymm4
  vpxor  %ymm5, %ymm5, %ymm5
  vpxor  %ymm6, %ymm6, %ymm6
  vpxor  %ymm7, %ymm7, %ymm7

  // Load the vector entropy
  vmovdqa 0x000(%rdx), %ymm8
  vmovdqa 0x020(%rdx), %ymm9
  vmovdqa 0x040(%rdx), %ymm10
  vmovdqa 0x060(%rdx), %ymm11
  vmovdqa 0x080(%rdx), %ymm12
  vmovdqa 0x0A0(%rdx), %ymm13
  vmovdqa 0x0C0(%rdx), %ymm14
  vmovdqa 0x0E0(%rdx), %ymm15
  add $0x100, %rdx

  // Load the MMX entropy
  mov 0x00(%rdx), %mm4
  mov 0x08(%rdx), %mm5
  mov 0x10(%rdx), %mm6
  mov 0x18(%rdx), %mm7
  add $0x20, %rdx

  // Load the GP entropy
  mov 0x00(%rdx), %r9
  mov 0x08(%rdx), %r10
  mov 0x10(%rdx), %r11
  mov 0x18(%rdx), %r12
  mov 0x20(%rdx), %r13
  mov 0x28(%rdx), %r14
  mov 0x30(%rdx), %r15
  add $0x38, %rdx

  // Set the number of iterations
  mov %rsi, %r8

  // Clear the GP TMP registers
  // This is needed because 8/16-bit register writes do not zero the upper bits
  // of a GP register. The HashTest generator currently does not understand this
  // means that a 8/16-bit write effectively "reads" from the output. It is
  // unclear if the generator should be fixed, however, as this doesn't affect
  // determinisim if the registers are cleared first.
  // RDI is also affected, but we know its value will be constant (the address
  // of the test funciton).
  xor %rax, %rax
  xor %rcx, %rcx
  xor %rdx, %rdx
  xor %rbx, %rbx
  xor %rbp, %rbp
  xor %rsi, %rsi

  // Init flags
  test %al, %al

  // Invoke the test
  // TODO(ncbray): this leaves RDI dirty, should it need to be cleared?
  call *%rdi

  // Recover output buffer
  pop %rcx

  // Save the vector entropy
  vmovdqa %ymm8, 0x000(%rcx)
  vmovdqa %ymm9, 0x020(%rcx)
  vmovdqa %ymm10, 0x040(%rcx)
  vmovdqa %ymm11, 0x060(%rcx)
  vmovdqa %ymm12, 0x080(%rcx)
  vmovdqa %ymm13, 0x0A0(%rcx)
  vmovdqa %ymm14, 0x0C0(%rcx)
  vmovdqa %ymm15, 0x0E0(%rcx)
  add $0x100, %rcx

  // Store the MMX entropy
  mov %mm4, 0x00(%rcx)
  mov %mm5, 0x08(%rcx)
  mov %mm6, 0x10(%rcx)
  mov %mm7, 0x18(%rcx)
  add $0x20, %rcx

  // Save the GP entropy
  mov %r9, 0x00(%rcx)
  mov %r10, 0x08(%rcx)
  mov %r11, 0x10(%rcx)
  mov %r12, 0x18(%rcx)
  mov %r13, 0x20(%rcx)
  mov %r14, 0x28(%rcx)
  mov %r15, 0x30(%rcx)
  add $0x38, %rcx

  // Restore callee saved registers
  pop %r15
  pop %r14
  pop %r13
  pop %r12
  pop %rbx

  // Restore the frame pointer
  pop    %rbp

  // Return
  ret

  .cfi_endproc
  .size RunHashTest256, . - RunHashTest256


  .global RunHashTest128
  .type RunHashTest128, @function
RunHashTest128:
  .cfi_startproc

  // Set the frame pointer
  push   %rbp
  mov    %rsp, %rbp

  // Save callee saved registers
  push %rbx
  push %r12
  push %r13
  push %r14
  push %r15

  // Save output buffer
  push %rcx

  // arg0 / RDI: pointer to the test function
  // arg1 / RSI: number of iterations
  // arg2 / RDX: input entropy
  // arg3 / RCX: output entropy

  // TODO(ncbray): why do we need to clear the TMP registers?
  // The fact that the SSE instructions preserve the upper bits shouldn't be a
  // problem in this case, the register values seem to matter for some other
  // reason, possibly because the test generator doesn't understand the register
  // is being read for some instruction?
  pxor  %xmm0, %xmm0
  pxor  %xmm1, %xmm1
  pxor  %xmm2, %xmm2
  pxor  %xmm3, %xmm3
  pxor  %xmm4, %xmm4
  pxor  %xmm5, %xmm5
  pxor  %xmm6, %xmm6
  pxor  %xmm7, %xmm7

  // Load the vector entropy
  vmovdqa 0x00(%rdx), %xmm8
  vmovdqa 0x10(%rdx), %xmm9
  vmovdqa 0x20(%rdx), %xmm10
  vmovdqa 0x30(%rdx), %xmm11
  vmovdqa 0x40(%rdx), %xmm12
  vmovdqa 0x50(%rdx), %xmm13
  vmovdqa 0x60(%rdx), %xmm14
  vmovdqa 0x70(%rdx), %xmm15
  add $0x80, %rdx

  // Load the MMX entropy
  mov 0x00(%rdx), %mm4
  mov 0x08(%rdx), %mm5
  mov 0x10(%rdx), %mm6
  mov 0x18(%rdx), %mm7
  add $0x20, %rdx

  // Load the GP entropy
  mov 0x00(%rdx), %r9
  mov 0x08(%rdx), %r10
  mov 0x10(%rdx), %r11
  mov 0x18(%rdx), %r12
  mov 0x20(%rdx), %r13
  mov 0x28(%rdx), %r14
  mov 0x30(%rdx), %r15
  add $0x38, %rdx

  // Set the number of iterations
  mov %rsi, %r8

  // Clear the GP TMP registers
  // This is needed because 8/16-bit register writes do not zero the upper bits
  // of a GP register. The HashTest generator currently does not understand this
  // means that a 8/16-bit write effectively "reads" from the output. It is
  // unclear if the generator should be fixed, however, as this doesn't affect
  // determinisim if the registers are cleared first.
  // RDI is also affected, but we know its value will be constant (the address
  // of the test funciton).
  xor %rax, %rax
  xor %rcx, %rcx
  xor %rdx, %rdx
  xor %rbx, %rbx
  xor %rbp, %rbp
  xor %rsi, %rsi

  // Init flags
  test %al, %al

  // Invoke the test
  // TODO(ncbray): this leaves RDI dirty, should it need to be cleared?
  call *%rdi

  // Recover output buffer
  pop %rcx

  // Save the vector entropy
  vmovdqa %xmm8, 0x00(%rcx)
  vmovdqa %xmm9, 0x10(%rcx)
  vmovdqa %xmm10, 0x20(%rcx)
  vmovdqa %xmm11, 0x30(%rcx)
  vmovdqa %xmm12, 0x40(%rcx)
  vmovdqa %xmm13, 0x50(%rcx)
  vmovdqa %xmm14, 0x60(%rcx)
  vmovdqa %xmm15, 0x70(%rcx)
  add $0x80, %rcx

  // Store the MMX entropy
  mov %mm4, 0x00(%rcx)
  mov %mm5, 0x08(%rcx)
  mov %mm6, 0x10(%rcx)
  mov %mm7, 0x18(%rcx)
  add $0x20, %rcx

  // Save the GP entropy
  mov %r9, 0x00(%rcx)
  mov %r10, 0x08(%rcx)
  mov %r11, 0x10(%rcx)
  mov %r12, 0x18(%rcx)
  mov %r13, 0x20(%rcx)
  mov %r14, 0x28(%rcx)
  mov %r15, 0x30(%rcx)
  add $0x38, %rcx

  // Restore callee saved registers
  pop %r15
  pop %r14
  pop %r13
  pop %r12
  pop %rbx

  // Restore the frame pointer
  pop    %rbp

  // Return
  ret

  .cfi_endproc
  .size RunHashTest128, . - RunHashTest128
