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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_SIMPLE_SERIALIZE_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_SIMPLE_SERIALIZE_H_

#include <cstdint>
#include <cstring>

#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

namespace serialize_internal {

// Note: currently the serialization code is factored a header and shared
// between multiple use cases, but as soon as we need to do any versioning it
// will likely need to be inlined and customized.

struct header {
  uint16_t magic;
  uint16_t version;
  uint8_t reserved[4];
};

// `src` is the data being serialized.
// `magic` is a 16-bit value to be written at the beginning of the serialized
// data to help indentify it.
// `dst` is the buffer the serialized data will be written to.
// `dst_size` is the maximum amount of data that can be written to `dst`.
// Returns the number of bytes written on success.
// Returns -1 on failiure.
template <typename T>
ssize_t SimpleSerialize(const T& src, uint16_t magic, void* dst,
                        size_t dst_size) {
  uint8_t* begin = reinterpret_cast<uint8_t*>(dst);
  uint8_t* current = begin;
  uint8_t* end = current + dst_size;

  // Is there enough space for the header?
  if (end - current < sizeof(header)) {
    LOG_ERROR("Buffer too small to contain header: ", IntStr(end - current));
    return -1;
  }

  // Create header
  header hdr = {magic, 0, {0, 0, 0, 0}};

  // Serialize header
  memcpy(current, &hdr, sizeof(header));
  current += sizeof(header);

  // Is there enough space for the data?
  if (end - current < sizeof(src)) {
    LOG_ERROR("Buffer too small to contain data: ", IntStr(end - current));
    return -1;
  }

  // Serialize data
  memcpy(current, &src, sizeof(src));
  current += sizeof(src);

  return current - begin;
}

// `expected_magic` is a 16-bit value that should be at the beginning of the
// serialized data.
// `src` is the data being deserialized.
// `src_size` is the maximum amount of data that can be read from `src`.
// `dst` is the struct the deserialized data will be written to.
// Returns the number of bytes read on success.
// Returns -1 on failiure.
template <typename T>
ssize_t SimpleDeserialize(uint16_t expected_magic, const void* src,
                          size_t src_size, T* dst) {
  const uint8_t* begin = reinterpret_cast<const uint8_t*>(src);
  const uint8_t* current = begin;
  const uint8_t* end = current + src_size;

  // Is there enough space for the header?
  if (end - current < sizeof(header)) {
    LOG_ERROR("Too little data: ", IntStr(end - current));
    return -1;
  }

  // Deserialize the header.
  header hdr;
  memcpy(&hdr, current, sizeof(header));
  current += sizeof(header);

  if (hdr.magic != expected_magic) {
    LOG_ERROR("Bad magic: ", HexStr(hdr.magic));
    return -1;
  }

  if (hdr.version != 0) {
    LOG_ERROR("Bad version: ", HexStr(hdr.version));
    return -1;
  }

  // Is there enough data for this to be a valid payload?
  if (end - current < sizeof(*dst)) {
    LOG_ERROR("Too little data: ", IntStr(end - current));
    return -1;
  }

  // Deserialize the payload.
  memcpy(dst, current, sizeof(*dst));
  current += sizeof(*dst);

  return current - begin;
}

}  // namespace serialize_internal
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_SIMPLE_SERIALIZE_H_
