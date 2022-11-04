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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_SERIALIZE_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_SERIALIZE_H_

#include <sys/types.h>

#include <cstdint>

#include "absl/base/attributes.h"
#include "./util/ucontext/ucontext_types.h"

#if !defined(SILIFUZZ_BUILD_FOR_NOLIBC)
#include <string>

#include "./util/checks.h"
#endif

namespace silifuzz {

namespace serialize_internal {

constexpr size_t kHeaderSize = 8;

template <typename T>
constexpr size_t SerializedSizeMax();

template <>
constexpr size_t SerializedSizeMax<GRegSet<X86_64>>() {
  // Note that the legacy serialization format is larger because it encodes
  // every field as a 64-bit integer and also contains an extra field.
  // 216 vs 8 + 176.
  return 216;  // sizeof(struct user_regs_struct)
}

template <>
constexpr size_t SerializedSizeMax<FPRegSet<X86_64>>() {
  return kHeaderSize + sizeof(FPRegSet<X86_64>);
}

template <>
constexpr size_t SerializedSizeMax<GRegSet<AArch64>>() {
  return kHeaderSize + sizeof(GRegSet<AArch64>);
}

template <>
constexpr size_t SerializedSizeMax<FPRegSet<AArch64>>() {
  return kHeaderSize + sizeof(FPRegSet<AArch64>);
}

// Convert GRegsSet into bytes that can be stored in a snapshot proto.
// The format is different for each architechture. The serialized bytes are
// intended to be opaque and processed only by serialization functions.
template <typename Arch>
ABSL_MUST_USE_RESULT ssize_t SerializeGRegs(const GRegSet<Arch>& gregs,
                                            void* data, size_t data_size);

// Convert bytes from a snapshot proto into GRegsSet.
template <typename Arch>
ABSL_MUST_USE_RESULT ssize_t DeserializeGRegs(const void* data,
                                              size_t data_size,
                                              GRegSet<Arch>* gregs);

// Indicates that the data may be serialized registers for the specified
// architecture. If this function returns true, it may deserialize. If this
// function returns false, it will certainly not deserialize.
template <typename Arch>
ABSL_MUST_USE_RESULT bool MayBeSerializedGRegs(const void* data,
                                               size_t data_size);

// Convert FPRegsSet into bytes that can be stored in a snapshot proto.
template <typename Arch>
ABSL_MUST_USE_RESULT ssize_t SerializeFPRegs(const FPRegSet<Arch>& fpregs,
                                             void* data, size_t data_size);

// Convert bytes from a snapshot proto into FPRegsSet.
template <typename Arch>
ABSL_MUST_USE_RESULT ssize_t DeserializeFPRegs(const void* data,
                                               size_t data_size,
                                               FPRegSet<Arch>* fpregs);

// See MayBeSerializedGRegs
template <typename Arch>
ABSL_MUST_USE_RESULT bool MayBeSerializedFPRegs(const void* data,
                                                size_t data_size);

#if defined(__x86_64__)

// For testing only.
ABSL_MUST_USE_RESULT ssize_t SerializeLegacyGRegs(const GRegSet<X86_64>& gregs,
                                                  void* data, size_t data_size);
ABSL_MUST_USE_RESULT ssize_t SerializeLegacyFPRegs(
    const FPRegSet<X86_64>& fpregs, void* data, size_t data_size);

#endif
}  // namespace serialize_internal

template <typename T>
struct Serialized {
  char data[serialize_internal::SerializedSizeMax<T>()];
  size_t size;
};

template <typename Arch>
inline ABSL_MUST_USE_RESULT bool SerializeGRegs(
    const GRegSet<Arch>& src, Serialized<GRegSet<Arch>>* dst) {
  ssize_t sz =
      serialize_internal::SerializeGRegs(src, dst->data, sizeof(dst->data));
  if (sz < 0) {
    return false;
  }
  dst->size = sz;
  return true;
}

template <typename Arch>
inline ABSL_MUST_USE_RESULT bool SerializeFPRegs(
    const FPRegSet<Arch>& src, Serialized<FPRegSet<Arch>>* dst) {
  ssize_t sz =
      serialize_internal::SerializeFPRegs(src, dst->data, sizeof(dst->data));
  if (sz < 0) {
    return false;
  }
  dst->size = sz;
  return true;
}

#if !defined(SILIFUZZ_BUILD_FOR_NOLIBC)
// A wrapper for serializing the register set into a string object.
// Not suitable for the nolibc case because it requires dynamic allocation.
template <typename Arch>
inline ABSL_MUST_USE_RESULT bool SerializeGRegs(const GRegSet<Arch>& src,
                                                std::string* dst) {
  CHECK(dst->empty());
  Serialized<GRegSet<Arch>> tmp;
  if (!SerializeGRegs(src, &tmp)) {
    return false;
  }
  dst->append(tmp.data, tmp.size);
  return true;
}

// A wrapper for deserializing data held in a string object.
// Returns false on error or if not all the bytes were consumed.
// See SerializeGRegs for other details.
template <typename Arch>
inline ABSL_MUST_USE_RESULT bool DeserializeGRegs(const std::string& src,
                                                  GRegSet<Arch>* dst) {
  return serialize_internal::DeserializeGRegs(src.data(), src.size(), dst) ==
         src.size();
}

// A wrapper converting a string input into a pointer / size pair.
template <typename Arch>
inline ABSL_MUST_USE_RESULT bool MayBeSerializedGRegs(const std::string& src) {
  return serialize_internal::MayBeSerializedGRegs<Arch>(src.data(), src.size());
}

// See SerializeGRegs
template <typename Arch>
inline ABSL_MUST_USE_RESULT bool SerializeFPRegs(const FPRegSet<Arch>& src,
                                                 std::string* dst) {
  CHECK(dst->empty());
  Serialized<FPRegSet<Arch>> tmp;
  if (!SerializeFPRegs(src, &tmp)) {
    return false;
  }
  dst->append(tmp.data, tmp.size);
  return true;
}

// See DeserializeGRegs
template <typename Arch>
inline ABSL_MUST_USE_RESULT bool DeserializeFPRegs(const std::string& src,
                                                   FPRegSet<Arch>* dst) {
  return serialize_internal::DeserializeFPRegs(src.data(), src.size(), dst) ==
         src.size();
}

// See MayBeSerializedGRegs
template <typename Arch>
inline ABSL_MUST_USE_RESULT bool MayBeSerializedFPRegs(const std::string& src) {
  return serialize_internal::MayBeSerializedFPRegs<Arch>(src.data(),
                                                         src.size());
}

#endif

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_SERIALIZE_H_
