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

// clang-format off

// SP must always be 16-byte aligned.
#define STACK_FRAME_SIZE 32

.cfi_startproc

  // The size of the context structure is larger than the immediates str/ldr
  // can encode. stp/ldp also don't accept arbitrary immediates. Therefore, we
  // cannot use a scheme similar to x86_64 where all memory operations are
  // done with immedate offsets to a base register. Instead, we designate a
  // register as a "data pointer" that we mutate as we perform memory
  // operations. This unfortunately makes the relationship between the context
  // struct layout and the instructions implicit rather than explicit.

  // Allocate the stack frame.
  sub sp, sp, STACK_FRAME_SIZE

  // Backup the scratch registers.
  // x0: scratch register / original context pointer. (sp+0)
  // x1: scratch register. (sp+8)
  // x24: data pointer.  (sp+16)
  // x30: link register / return address.  (sp+24)
  stp x0, x1, [sp]
  stp x24, x30, [sp, #16]

  // Set the data pointer to the start of the context.
  mov x24, x0

  // Save the floating point data registers.
  st1 {v0.2d, v1.2d, v2.2d, v3.2d}, [x24], #64
  st1 {v4.2d, v5.2d, v6.2d, v7.2d}, [x24], #64
  st1 {v8.2d, v9.2d, v10.2d, v11.2d}, [x24], #64
  st1 {v12.2d, v13.2d, v14.2d, v15.2d}, [x24], #64
  st1 {v16.2d, v17.2d, v18.2d, v19.2d}, [x24], #64
  st1 {v20.2d, v21.2d, v22.2d, v23.2d}, [x24], #64
  st1 {v24.2d, v25.2d, v26.2d, v27.2d}, [x24], #64
  st1 {v28.2d, v29.2d, v30.2d, v31.2d}, [x24], #64

  // Save the floating point status and control registers.
  mrs x0, fpsr
  mrs x1, fpcr
  stp x0, x1, [x24], #16

  // Save the original x0 and x1.
  ldp x0, x1, [sp]
  stp x0, x1, [x24], #16

  // Save untouched general purpose registers.
  stp x2, x3, [x24], #16
  stp x4, x5, [x24], #16
  stp x6, x7, [x24], #16
  stp x8, x9, [x24], #16
  stp x10, x11, [x24], #16

  stp x12, x13, [x24], #16
  stp x14, x15, [x24], #16
  stp x16, x17, [x24], #16
  stp x18, x19, [x24], #16
  stp x20, x21, [x24], #16
  stp x22, x23, [x24], #16

  // Save the original x24 and untouched x25.
  ldr x0, [sp, #16]
  stp x0, x25, [x24], #16

  // Save more untouched general purpose registers.
  stp x26, x27, [x24], #16
  stp x28, x29, [x24], #16

  // Save x30 and SP.
  // No calls have been performed, yet, so x30 should be untouched.
  // The original SP can be derived from the current SP.
  add x0, sp, STACK_FRAME_SIZE
  stp x30, x0, [x24], #16

  // Save PC and PSTATE.
  // x30 is the link register, which is the PC we want to return to.
  // NZCV flags are the subset of pstate visible from EL0.
  // We should have not performed any flag setting operations so far, so NZCV
  // should still be its original value.
  // TODO: DAIF may also be available?
  mrs x0, nzcv
  stp x30, x0, [x24], #16

  // Save TPIDR_EL0 and TPIDRRO_EL0.
  mrs x0, tpidr_el0
  mrs x1, tpidrro_el0
  stp x0, x1, [x24], #16

  // Restore state and return.
  ldp x24, x30, [sp, #16]
  add sp, sp, STACK_FRAME_SIZE
  ret

  .cfi_endproc
