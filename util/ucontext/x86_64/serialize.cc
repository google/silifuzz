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

#include "./util/ucontext/serialize.h"

namespace silifuzz {

namespace serialize_internal {

ssize_t SerializeGRegs(const GRegSet& gregs, void* data, size_t data_size) {
  // Note: there are no guarantees this pointer is correctly aligned, but that
  // should be a performance pitfall and not correctness.
  user_regs_struct* user_gregs = reinterpret_cast<user_regs_struct*>(data);

  // Is there enough space?
  if (data_size < sizeof(*user_gregs)) {
    return -1;
  }

  // 0-out it all to make all bytes of user_regs_struct well-defined:
  // 0-out parts that do not correspond to anything in GRegSet
  // and the padding between the fields if any:
  memset(user_gregs, 0, sizeof(*user_gregs));

  user_gregs->r8 = gregs.r8;
  user_gregs->r9 = gregs.r9;
  user_gregs->r10 = gregs.r10;
  user_gregs->r11 = gregs.r11;
  user_gregs->r12 = gregs.r12;
  user_gregs->r13 = gregs.r13;
  user_gregs->r14 = gregs.r14;
  user_gregs->r15 = gregs.r15;

  user_gregs->rdi = gregs.rdi;
  user_gregs->rsi = gregs.rsi;
  user_gregs->rbp = gregs.rbp;
  user_gregs->rbx = gregs.rbx;
  user_gregs->rdx = gregs.rdx;
  user_gregs->rax = gregs.rax;
  user_gregs->rcx = gregs.rcx;
  user_gregs->rsp = gregs.rsp;
  user_gregs->rip = gregs.rip;
  user_gregs->eflags = gregs.eflags;
  user_gregs->fs_base = gregs.fs_base;
  user_gregs->gs_base = gregs.gs_base;

  user_gregs->orig_rax = user_gregs->rax;  // for lack of anything else

  user_gregs->cs = gregs.cs;
  user_gregs->gs = gregs.gs;
  user_gregs->fs = gregs.fs;
  user_gregs->ss = gregs.ss;
  user_gregs->ds = gregs.ds;
  user_gregs->es = gregs.es;

  return sizeof(*user_gregs);
}

ssize_t DeserializeGRegs(const void* data, size_t data_size, GRegSet* gregs) {
  // Note: there are no guarantees this pointer is correctly aligned, but that
  // should be a performance pitfall and not correctness.
  const user_regs_struct* user_gregs =
      reinterpret_cast<const user_regs_struct*>(data);

  // Is there enough data?
  if (data_size < sizeof(*user_gregs)) {
    return -1;
  }

  // 0-out it all to make all bytes of GRegSet well-defined:
  // 0-out GRegSet::padding and the padding between the fields if any:
  memset(gregs, 0, sizeof(*gregs));

  gregs->r8 = user_gregs->r8;
  gregs->r9 = user_gregs->r9;
  gregs->r10 = user_gregs->r10;
  gregs->r11 = user_gregs->r11;
  gregs->r12 = user_gregs->r12;
  gregs->r13 = user_gregs->r13;
  gregs->r14 = user_gregs->r14;
  gregs->r15 = user_gregs->r15;

  gregs->rdi = user_gregs->rdi;
  gregs->rsi = user_gregs->rsi;
  gregs->rbp = user_gregs->rbp;
  gregs->rbx = user_gregs->rbx;
  gregs->rdx = user_gregs->rdx;
  gregs->rax = user_gregs->rax;
  gregs->rcx = user_gregs->rcx;
  gregs->rsp = user_gregs->rsp;
  gregs->rip = user_gregs->rip;
  gregs->eflags = user_gregs->eflags;
  gregs->fs_base = user_gregs->fs_base;
  gregs->gs_base = user_gregs->gs_base;

  gregs->cs = user_gregs->cs;
  gregs->gs = user_gregs->gs;
  gregs->fs = user_gregs->fs;
  gregs->ss = user_gregs->ss;
  gregs->ds = user_gregs->ds;
  gregs->es = user_gregs->es;

  return sizeof(*user_gregs);
}

// FPRegSet in UContext and struct user_fpregs_struct have exact same
// layout, just slightly different field and type names, so we byte-copy.
static_assert(sizeof(FPRegSet) == sizeof(struct user_fpregs_struct),
              "fpregs structs do not match");

ssize_t SerializeFPRegs(const FPRegSet& fpregs, void* data, size_t data_size) {
  // Is there enough space?
  if (data_size < sizeof(struct user_fpregs_struct)) {
    return -1;
  }
  memcpy(data, &fpregs, sizeof(struct user_fpregs_struct));
  return sizeof(struct user_fpregs_struct);
}

ssize_t DeserializeFPRegs(const void* data, size_t data_size,
                          FPRegSet* fpregs) {
  // Is there enough data?
  if (data_size < sizeof(struct user_fpregs_struct)) {
    return -1;
  }
  memcpy(fpregs, data, sizeof(struct user_fpregs_struct));
  return sizeof(struct user_fpregs_struct);
}

}  // namespace serialize_internal

}  // namespace silifuzz
