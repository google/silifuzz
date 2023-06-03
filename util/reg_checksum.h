// Copyright 2023 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_REG_CHECKSUM_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_REG_CHECKSUM_H_

#include <unistd.h>

#include <cstddef>
#include <cstdint>

#include "./util/reg_group_set.h"

namespace silifuzz {

// A POD struct tagged with architecture containing register checksum
// information. This is meant to use as a dumb container. It supports
// serialization and deserialization so that checksum information is
// opaque and does not expose architecture details to higher level
// structure like Snapshot class and Snapshot proto, which only handle
// the serialized form.
//
// We use a POD struct instead of a class with private data members with access
// control. Doing so makes it easy to add this to the Snap data structure.
template <typename Arch>
struct RegisterChecksum {
  // Register groups included in checksum computation.
  RegisterGroupSet<Arch> register_groups;

  // Checksum value.  We may use an algorithm that produce a result narrower
  // than 64 bits.
  uint64_t checksum;
};

// Returns the serialized size of a register checksum struct.
template <typename Arch>
ssize_t SerializedSize();

// Serializes a RegisterChecksum struct `src` to bytes in buffer at `dst`
// with capacity of `n`.  Returns the number of serialized bytes if succeeded.
// Otherwise returns -1.
template <typename Arch>
ssize_t Serialize(const RegisterChecksum<Arch>& src, uint8_t* dst, size_t n);

// Deserialize `n` bytes pointed by `src` into a RegisterChecksum struct `*dst`.
// Returns number of bytes read from `src` if succeeded.  Otherwise return -1.
template <typename Arch>
ssize_t Deserialize(const uint8_t* src, size_t n, RegisterChecksum<Arch>& dst);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_REG_CHECKSUM_H_
