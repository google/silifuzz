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

#include <sys/types.h>

#include <cstring>

#include "./util/checks.h"
#include "./util/ucontext/simple_serialize.h"
#include "./util/ucontext/ucontext_types.h"

#if defined(__x86_64__)
#include <sys/user.h>  // for user_regs_struct and user_fpregs_struct
#endif

namespace silifuzz {

namespace serialize_internal {

static constexpr uint16_t kLegacyGRegsSize = 216;
static constexpr uint16_t kLegacyFPRegsSize = 512;

// Static asserts that depend on libc.
#if defined(__x86_64__)
// FPRegSet in UContext and struct user_fpregs_struct have exact same
// layout, just slightly different field and type names, so we can byte-copy.
static_assert(sizeof(FPRegSet<X86_64>) == sizeof(struct user_fpregs_struct),
              "fpregs structs do not match");
static_assert(kLegacyFPRegsSize == sizeof(struct user_fpregs_struct),
              "kLegacyFPRegsSize is wrong");

// The serialization buffer should be able to contain a user_regs_struct.
static_assert(SerializedSizeMax<GRegSet<X86_64>>() >=
                  sizeof(struct user_regs_struct),
              "SerializedSizeMax is wrong for GRegSet<X86_64>");
static_assert(kLegacyGRegsSize == sizeof(struct user_regs_struct),
              "kLegacyGRegsSize is wrong");
#endif

static_assert(SerializedSizeMax<FPRegSet<X86_64>>() >= sizeof(FPRegSet<X86_64>),
              "SerializedSizeMax is wrong for FPRegSet<X86_64>");

ssize_t SerializeLegacyGRegs(const GRegSet<X86_64>& gregs, void* data,
                             size_t data_size) {
#if defined(__x86_64__)
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
#else
  // TODO port to other platforms
  LOG_FATAL("Serializing legacy x86_64 GRegSet only supported on x86_64.");
  return -1;
#endif
}

ssize_t DeserializeLegacyGRegs(const void* data, size_t data_size,
                               GRegSet<X86_64>* gregs) {
#if defined(__x86_64__)
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
#else
  // TODO(ncbray) port to other platforms.
  LOG_FATAL("Deserializing legacy x86_64 GRegSet only supported on x86_64.");
  return -1;
#endif
}

bool MayBeLegacySerializedGRegs(const void* data, size_t data_size) {
  return data_size == kLegacyGRegsSize;
}

ssize_t SerializeLegacyFPRegs(const FPRegSet<X86_64>& fpregs, void* data,
                              size_t data_size) {
  // Is there enough space?
  if (data_size < sizeof(fpregs)) {
    return -1;
  }
  memcpy(data, &fpregs, sizeof(fpregs));
  return sizeof(fpregs);
}

ssize_t DeserializeLegacyFPRegs(const void* data, size_t data_size,
                                FPRegSet<X86_64>* fpregs) {
  // Is there enough data?
  if (data_size < sizeof(*fpregs)) {
    return -1;
  }
  memcpy(fpregs, data, sizeof(*fpregs));
  return sizeof(*fpregs);
}

bool MayBeLegacySerializedFPRegs(const void* data, size_t data_size) {
  return data_size == kLegacyFPRegsSize;
}

static_assert(sizeof(header) == kHeaderSize, "Header struct is wrong size.");

static_assert(SerializedSizeMax<GRegSet<X86_64>>() >=
                  sizeof(header) + sizeof(GRegSet<X86_64>),
              "SerializedSizeMax is wrong.");
static_assert(SerializedSizeMax<FPRegSet<X86_64>>() >=
                  sizeof(header) + sizeof(FPRegSet<X86_64>),
              "SerializedSizeMax is wrong.");

// "ig" in little endian.
static constexpr uint16_t kX86_64GRegsMagic = 0x6769;

// "if" in little endian.
static constexpr uint16_t kX86_64FPRegsMagic = 0x6669;

template <>
ssize_t SerializeGRegs(const GRegSet<X86_64>& gregs, void* data,
                       size_t data_size) {
  ssize_t result = SimpleSerialize(gregs, kX86_64GRegsMagic, data, data_size);
  // As long as we support the legacy serialization formats, the new
  // serialization formats must be designed to always produce a different
  // serialized size.
  CHECK_NE(result, kLegacyGRegsSize);
  return result;
}

template <>
ssize_t DeserializeGRegs(const void* data, size_t data_size,
                         GRegSet<X86_64>* gregs) {
  if (MayBeLegacySerializedGRegs(data, data_size)) {
    return DeserializeLegacyGRegs(data, data_size, gregs);
  }
  return SimpleDeserialize(kX86_64GRegsMagic, data, data_size, gregs);
}

template <>
bool MayBeSerializedGRegs<X86_64>(const void* data, size_t data_size) {
  return MayBeLegacySerializedGRegs(data, data_size) ||
         MayBeSimpleSerialized<GRegSet<X86_64>>(kX86_64GRegsMagic, data,
                                                data_size);
}

template <>
ssize_t SerializeFPRegs(const FPRegSet<X86_64>& fpregs, void* data,
                        size_t data_size) {
  ssize_t result = SimpleSerialize(fpregs, kX86_64FPRegsMagic, data, data_size);
  // As long as we support the legacy serialization formats, the new
  // serialization formats must be designed to always produce a different
  // serialized size.
  CHECK_NE(result, kLegacyFPRegsSize);
  return result;
}

template <>
ssize_t DeserializeFPRegs(const void* data, size_t data_size,
                          FPRegSet<X86_64>* fpregs) {
  if (MayBeLegacySerializedFPRegs(data, data_size)) {
    return DeserializeLegacyFPRegs(data, data_size, fpregs);
  }
  return SimpleDeserialize(kX86_64FPRegsMagic, data, data_size, fpregs);
}

template <>
bool MayBeSerializedFPRegs<X86_64>(const void* data, size_t data_size) {
  return MayBeLegacySerializedFPRegs(data, data_size) ||
         MayBeSimpleSerialized<FPRegSet<X86_64>>(kX86_64FPRegsMagic, data,
                                                 data_size);
}

}  // namespace serialize_internal

}  // namespace silifuzz
