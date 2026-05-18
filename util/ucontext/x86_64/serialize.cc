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

#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/ucontext/simple_serialize.h"
#include "./util/ucontext/ucontext_types.h"

#if defined(__x86_64__)
#include <sys/user.h>  // for user_regs_struct and user_fpregs_struct
#endif

namespace silifuzz {

namespace serialize_internal {

// Static asserts that depend on libc.
#if defined(__x86_64__)
// FPRegSet in UContext and struct user_fpregs_struct have exact same
// layout, just slightly different field and type names, so we can byte-copy.
static_assert(sizeof(FPRegSet<X86_64>) == sizeof(struct user_fpregs_struct),
              "fpregs structs do not match");

static_assert(SerializedSizeMax<GRegSet<X86_64>>() >=
                  sizeof(header) + sizeof(GRegSet<X86_64>),
              "SerializedSizeMax is wrong for GRegSet<X86_64>");
#endif

static_assert(SerializedSizeMax<FPRegSet<X86_64>>() >= sizeof(FPRegSet<X86_64>),
              "SerializedSizeMax is wrong for FPRegSet<X86_64>");

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
  return SimpleSerialize(gregs, kX86_64GRegsMagic, data, data_size);
}

template <>
ssize_t DeserializeGRegs(const void* data, size_t data_size,
                         GRegSet<X86_64>* gregs) {
  return SimpleDeserialize(kX86_64GRegsMagic, data, data_size, gregs);
}

template <>
bool MayBeSerializedGRegs<X86_64>(const void* data, size_t data_size) {
  return MayBeSimpleSerialized<GRegSet<X86_64>>(kX86_64GRegsMagic, data,
                                                data_size);
}

template <>
ssize_t SerializeFPRegs(const FPRegSet<X86_64>& fpregs, void* data,
                        size_t data_size) {
  return SimpleSerialize(fpregs, kX86_64FPRegsMagic, data, data_size);
}

template <>
ssize_t DeserializeFPRegs(const void* data, size_t data_size,
                          FPRegSet<X86_64>* fpregs) {
  return SimpleDeserialize(kX86_64FPRegsMagic, data, data_size, fpregs);
}

template <>
bool MayBeSerializedFPRegs<X86_64>(const void* data, size_t data_size) {
  return MayBeSimpleSerialized<FPRegSet<X86_64>>(kX86_64FPRegsMagic, data,
                                                 data_size);
}

}  // namespace serialize_internal

}  // namespace silifuzz
