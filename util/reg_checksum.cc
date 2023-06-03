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

#include "./util/reg_checksum.h"

#include <endian.h>

#include <cstdint>
#include <cstring>

#include "absl/base/internal/endian.h"
#include "./util/arch.h"

namespace silifuzz {

namespace internal {

constexpr char kRegisterChecksumMagic[] = {'R', 'C'};

// Header for a serialized RegisterChecksum
struct RegisterChecksumHeader {
  uint8_t magic[sizeof(kRegisterChecksumMagic)];
  uint8_t arch;
  uint8_t version;  // currently only version 0 is supported.
  uint32_t unused;
};
static_assert(sizeof(RegisterChecksumHeader) == 8);

}  // namespace internal

template <typename Arch>
ssize_t SerializedSize() {
  return sizeof(internal::RegisterChecksumHeader) +
         sizeof(RegisterChecksum<Arch>);
}

template <typename Arch>
ssize_t Serialize(const RegisterChecksum<Arch>& src, uint8_t* dst, size_t n) {
  constexpr size_t kHeaderSize = sizeof(internal::RegisterChecksumHeader);
  uint64_t le_uint64[2];
  size_t kSerializedSize = kHeaderSize + sizeof(le_uint64);
  if (n < kSerializedSize) {
    return -1;
  }

  internal::RegisterChecksumHeader header{};
  memcpy(header.magic, internal::kRegisterChecksumMagic, sizeof(header.magic));
  header.arch = static_cast<uint8_t>(Arch::architecture_id);
  header.version = 0;
  memcpy(dst, &header, sizeof(header));

  le_uint64[0] = absl::little_endian::FromHost(src.register_groups.Serialize());
  le_uint64[1] = absl::little_endian::FromHost(src.checksum);
  memcpy(dst + kHeaderSize, &le_uint64, sizeof(le_uint64));

  return kSerializedSize;
}

template <typename Arch>
ssize_t Deserialize(const uint8_t* src, size_t n, RegisterChecksum<Arch>& dst) {
  constexpr size_t kHeaderSize = sizeof(internal::RegisterChecksumHeader);
  uint64_t le_uint64[2];
  size_t kSerializedSize = kHeaderSize + sizeof(le_uint64);
  if (n < kSerializedSize) {
    return -1;
  }

  if (n < kSerializedSize) {
    return -1;
  }

  // Read and verify header.
  internal::RegisterChecksumHeader header;
  memcpy(&header, src, kHeaderSize);
  if (memcmp(header.magic, internal::kRegisterChecksumMagic,
             sizeof(internal::kRegisterChecksumMagic)) != 0) {
    return -1;
  }
  if (header.arch != static_cast<uint8_t>(Arch::architecture_id)) {
    return -1;
  }
  if (header.version != 0) {
    return -1;
  }

  memcpy(&le_uint64, src + kHeaderSize, sizeof(le_uint64));
  // Convert little-endian serialized data back to host byte-order.
  dst.register_groups = RegisterGroupSet<Arch>::Deserialize(
      absl::little_endian::ToHost(le_uint64[0]));
  dst.checksum = absl::little_endian::ToHost(le_uint64[1]);
  return kSerializedSize;
}

template ssize_t SerializedSize<X86_64>();
template ssize_t SerializedSize<AArch64>();

template ssize_t Serialize<X86_64>(const RegisterChecksum<X86_64>& src,
                                   uint8_t* dst, size_t n);
template ssize_t Serialize<AArch64>(const RegisterChecksum<AArch64>& src,
                                    uint8_t* dst, size_t n);

template ssize_t Deserialize<X86_64>(const uint8_t* src, size_t n,
                                     RegisterChecksum<X86_64>& dst);
template ssize_t Deserialize<AArch64>(const uint8_t* src, size_t n,
                                      RegisterChecksum<AArch64>& dst);

}  // namespace silifuzz
