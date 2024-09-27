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

 // Snap exit point implementation for aarch64
 //
 // After execution, a Snap calls a pre-defined exit address that jumps to
 // here. The exit point saves register state and jumps back immediately to the
 // runner via RunerReentry().
 //
 // This code is not thread-safe as it uses some globals without locks.

  .text
  .align 16
  .global SnapExitImpl
  .type SnapExitImpl, @function

SnapExitImpl:

  # On entry all the registers should be as they were when exiting the snap
  # except the PC (we are here now), x0 because we needed a scratch register to
  # contain arbitrary addresses to branch to, and x30 because it contains the PC
  # at the end of the exit sequence.  The original values of x0 and x30 were
  # stored at sp-16 and sp-8 respectively.

  # We are switching to a new stack to minimize the requirements we place on the
  # state of the stack on renetry. We will also be jumping to C code later,
  # which will have an unpredictable demand for stack space.
  # We can't actually swap to the new stack, however, until we copy off the two
  # saved values. Copying off these values is complicated by the fact we're
  # starting with a single scratch register, and that register needs to contain
  # the address of the new stack.

  # Calculate the address of the new stack.
  adrp x0, .LSnapExitStackEnd
  add x0, x0, :lo12:.LSnapExitStackEnd

  # Allocate a 32-byte stack frame.
  sub x0, x0, #32

  # Store the program counter on snap exit onto the new stack.
  str x30, [x0, #0]
  # x30 can now be used.

  # Store original stack pointer on the new stack.
  # Requires a scratch register because str cannot encode sp as the source reg.
  mov x30, sp
  str x30, [x0, #8]

  # Store original x0 on new stack.
  # Not using ldp / stp because we only have one scratch register.
  ldr x30, [sp, #-16]
  str x30, [x0, #16]

  # Store the original x30 on new stack.
  ldr x30, [sp, #-8]
  str x30, [x0, #24]

  # Switch to new stack.
  mov sp, x0

  # The stack frame is now: [pc, sp, x0, x30]

  # Point x0 to the global we want to save the context into.
  adrp x0, snap_exit_context
  add x0, x0, :lo12:snap_exit_context

  # Save the context.
  # x0 cannot be correct because it needs to point to the context memory.
  # x30 cannot be correct because it needs to contain the return address.
  # pc cannot be correct because we are no longer in the snap.
  # sp cannot be correct because we are using a new stack.
  # Note: if the text segment gets too big, the compiler may insert a veneer
  # here that could smash x16 or x17.  At this point this seems unlikely, so
  # we are not (yet) going through the motions to save them.
  bl SaveUContextNoSyscalls

  # Point x0 to the buffer for additional registers currently not handled by
  # SaveUContextNoSyscalls.
  adrp x0, snap_exit_register_group_io_buffer
  add x0, x0, :lo12:snap_exit_register_group_io_buffer

  # Save these additional registers (in order to calculate a checksum).
  bl SaveRegisterGroupsToBuffer

  # Jump to RunnerReentry(x0, x30, pc, sp)
  # We're defering fixup of the incorrect registers to C because it avoids a
  # bunch of gnarly pointer calculations in ASM.
  ldp x2, x3, [sp], #16
  ldp x0, x1, [sp], #16
  b RunnerReentry

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
