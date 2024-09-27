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

.cfi_startproc

  // Allocate the stack frame.
  sub sp, sp, 32

  // Set x25 to point to FPRegs and x24 to point to GRegs.
  ldp x25, x24, [x0, #0]

  // Clear additional registers (e.g. SVE) that do not need to be restored from
  // ucontext. We do this before restoring the floating point registers because
  // the bottom 128-bits of the SVE z registers are shared with their
  // corresponding floating point registers.
  bl ClearRegisterGroups

  // Restore the floating point data registers.
  ld1 {v0.2d, v1.2d, v2.2d, v3.2d}, [x25], #64
  ld1 {v4.2d, v5.2d, v6.2d, v7.2d}, [x25], #64
  ld1 {v8.2d, v9.2d, v10.2d, v11.2d}, [x25], #64
  ld1 {v12.2d, v13.2d, v14.2d, v15.2d}, [x25], #64
  ld1 {v16.2d, v17.2d, v18.2d, v19.2d}, [x25], #64
  ld1 {v20.2d, v21.2d, v22.2d, v23.2d}, [x25], #64
  ld1 {v24.2d, v25.2d, v26.2d, v27.2d}, [x25], #64
  ld1 {v28.2d, v29.2d, v30.2d, v31.2d}, [x25], #64

  // Restore the floating point status and control registers.
  ldp x0, x1, [x25], #16
  msr fpsr, x0
  // TODO conditional fpcr restore to avoid unnecessary stalls.
  msr fpcr, x1
  // x25 is free after restoring FPRegs.

  ldp x0, x1, [x24], #16
  // We still need x0 and x1 as scratch registers, so save the final values for
  // later.
  stp x0, x1, [sp, #0]

  ldp x2, x3, [x24], #16
  ldp x4, x5, [x24], #16
  ldp x6, x7, [x24], #16
  ldp x8, x9, [x24], #16
  ldp x10, x11, [x24], #16

  ldp x12, x13, [x24], #16
  ldp x14, x15, [x24], #16
  ldp x16, x17, [x24], #16
  ldp x18, x19, [x24], #16
  ldp x20, x21, [x24], #16
  ldp x22, x23, [x24], #16

  // We still need x24, save for later.
  ldp x0, x25, [x24], #16
  str x0, [sp, #16]

  ldp x26, x27, [x24], #16
  ldp x28, x29, [x24], #16

  // Save stack pointer for later.
  ldp x30, x0, [x24], #16
  str x0, [sp, #24]

  // Overwrite x30 with pc.
  // We can't jump to an address without holding it in a register, so sacrifice
  // the link register since it is the same as the program counter when we're
  // called from normal C code.
  ldp x30, x0, [x24], #16
  msr nzcv, x0

  // Restore TLS pointer.
  // Note: TPIDRRO_EL0 cannot be set from a 64-bit process.
  ldp x0, x1, [x24], #16
  msr tpidr_el0, x0

  // There does not appear to be a single instruction that can load the stack
  // pointer from memory. This means there will be at least one dirty register
  // holding a copy of the stack pointer after the stack pointer is restored.
  // To work around this, we are storing the final value of the temp register we
  // are using to restore the stack pointer (x24) on the new stack and restoring
  // it afterwards.
  // Alternatively, we could use a scratch register and live with it being a
  // copy of SP rather than getting restored.

  // Load the final values of x24 and sp intro x0 and x24.
  ldp x0, x24, [sp, #16]
  // Store final x24 value just above the final sp.
  str x0, [x24, #-8]
  // Restore the scratch registers.
  ldp x0, x1, [sp, #0]
  // Restore final sp
  mov sp, x24
  // Restore final x24 from the final sp.
  ldr x24, [sp, #-8]

  // Clean up the scratch space we used on the new stack so that the initial
  // state can be all zeros. This means a proxy that sets up the execution state
  // by different means should see the same initial memory state as the runner.
  str xzr, [sp, #-8]

  // There does not appear to be a way to branch to an arbitrary address without
  // holding it in a register. This means there will always be a dirty register
  // that points to the address we're branching to after the branch.
  ret

  .cfi_endproc
