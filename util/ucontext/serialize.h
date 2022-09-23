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
#include <sys/user.h>  // for user_regs_struct and user_fpregs_struct

#include <cstdint>

#include "absl/base/attributes.h"
#include "./util/ucontext/ucontext_types.h"

#if !defined(SILIFUZZ_BUILD_FOR_NOLIBC)
#include <string>

#include "./util/checks.h"
#endif

namespace silifuzz {

namespace serialize_internal {

// TODO(ncbray) make arch generic by decoupling the x86_64 sizes from libc.

// How big of a buffer must you provide to guarantee serialization never fails?
#if defined(__x86_64__)
constexpr size_t kSerializeGRegsMaxSize = sizeof(struct user_regs_struct);
constexpr size_t kSerializeFPRegsMaxSize = sizeof(struct user_fpregs_struct);
#elif defined(__aarch64__)
// See aarch64/serialize.cc to understand how these values are derived.
// The definition here is opaque because we don't want to expose the internal
// data structures.
constexpr size_t kSerializeGRegsMaxSize = 8 + sizeof(GRegSet<AArch64>);
constexpr size_t kSerializeFPRegsMaxSize = 8 + sizeof(FPRegSet<AArch64>);
#else
#error "Unsupported architecture"
#endif

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

// Convert FPRegsSet into bytes that can be stored in a snapshot proto.
template <typename Arch>
ABSL_MUST_USE_RESULT ssize_t SerializeFPRegs(const FPRegSet<Arch>& fpregs,
                                             void* data, size_t data_size);

// Convert bytes from a snapshot proto into FPRegsSet.
template <typename Arch>
ABSL_MUST_USE_RESULT ssize_t DeserializeFPRegs(const void* data,
                                               size_t data_size,
                                               FPRegSet<Arch>* fpregs);
}  // namespace serialize_internal

struct SerializedGRegs {
  char data[serialize_internal::kSerializeGRegsMaxSize];
  size_t size;
};

template <typename Arch>
inline ABSL_MUST_USE_RESULT bool SerializeGRegs(const GRegSet<Arch>& src,
                                                SerializedGRegs* dst) {
  ssize_t sz =
      serialize_internal::SerializeGRegs(src, dst->data, sizeof(dst->data));
  if (sz < 0) {
    return false;
  }
  dst->size = sz;
  return true;
}

struct SerializedFPRegs {
  char data[serialize_internal::kSerializeFPRegsMaxSize];
  size_t size;
};

template <typename Arch>
inline ABSL_MUST_USE_RESULT bool SerializeFPRegs(const FPRegSet<Arch>& src,
                                                 SerializedFPRegs* dst) {
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
  char tmp[serialize_internal::kSerializeGRegsMaxSize];
  ssize_t sz = serialize_internal::SerializeGRegs(src, tmp, sizeof(tmp));
  if (sz < 0) {
    return false;
  }
  dst->append(tmp, sz);
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

// See SerializeGRegs
template <typename Arch>
inline ABSL_MUST_USE_RESULT bool SerializeFPRegs(const FPRegSet<Arch>& src,
                                                 std::string* dst) {
  CHECK(dst->empty());
  char tmp[serialize_internal::kSerializeFPRegsMaxSize];
  ssize_t sz = serialize_internal::SerializeFPRegs(src, tmp, sizeof(tmp));
  if (sz < 0) {
    return false;
  }
  dst->append(tmp, sz);
  return true;
}

// See DeserializeGRegs
template <typename Arch>
inline ABSL_MUST_USE_RESULT bool DeserializeFPRegs(const std::string& src,
                                                   FPRegSet<Arch>* dst) {
  return serialize_internal::DeserializeFPRegs(src.data(), src.size(), dst) ==
         src.size();
}
#endif

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_SERIALIZE_H_
