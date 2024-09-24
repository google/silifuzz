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

#include <cstdint>
#include <cstring>

#include "./util/arch.h"
#include "./util/ucontext/simple_serialize.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

namespace serialize_internal {

static_assert(sizeof(header) == kHeaderSize, "Header struct is wrong size.");

static_assert(SerializedSizeMax<GRegSet<AArch64>>() ==
                  sizeof(header) + sizeof(GRegSet<AArch64>),
              "SerializedSizeMax is wrong.");
static_assert(SerializedSizeMax<FPRegSet<AArch64>>() ==
                  sizeof(header) + sizeof(FPRegSet<AArch64>),
              "SerializedSizeMax is wrong.");

// "ag" in little endian.
static constexpr uint16_t kAarch64GRegsMagic = 0x6761;

// "af" in little endian.
static constexpr uint16_t kAarch64FPRegsMagic = 0x6661;

template <>
ssize_t SerializeGRegs(const GRegSet<AArch64>& gregs, void* data,
                       size_t data_size) {
  return SimpleSerialize(gregs, kAarch64GRegsMagic, data, data_size);
}

template <>
ssize_t DeserializeGRegs(const void* data, size_t data_size,
                         GRegSet<AArch64>* gregs) {
  return SimpleDeserialize(kAarch64GRegsMagic, data, data_size, gregs);
}

template <>
bool MayBeSerializedGRegs<AArch64>(const void* data, size_t data_size) {
  return MayBeSimpleSerialized<GRegSet<AArch64>>(kAarch64GRegsMagic, data,
                                                 data_size);
}

template <>
ssize_t SerializeFPRegs(const FPRegSet<AArch64>& fpregs, void* data,
                        size_t data_size) {
  return SimpleSerialize(fpregs, kAarch64FPRegsMagic, data, data_size);
}

template <>
ssize_t DeserializeFPRegs(const void* data, size_t data_size,
                          FPRegSet<AArch64>* fpregs) {
  return SimpleDeserialize(kAarch64FPRegsMagic, data, data_size, fpregs);
}

template <>
bool MayBeSerializedFPRegs<AArch64>(const void* data, size_t data_size) {
  return MayBeSimpleSerialized<FPRegSet<AArch64>>(kAarch64FPRegsMagic, data,
                                                  data_size);
}

}  // namespace serialize_internal

}  // namespace silifuzz
