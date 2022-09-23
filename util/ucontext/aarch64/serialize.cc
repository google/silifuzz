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

#include <cstdint>
#include <cstring>

#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

namespace serialize_internal {

struct header {
  uint16_t magic;
  uint16_t version;
  uint8_t reserved[4];
};

static_assert(sizeof(header) == 8, "Header struct is wrong size.");
static_assert(kSerializeGRegsMaxSize ==
                  sizeof(header) + sizeof(GRegSet<AArch64>),
              "GRegsMaxSize is wrong.");
static_assert(kSerializeFPRegsMaxSize ==
                  sizeof(header) + sizeof(FPRegSet<AArch64>),
              "FPRegsMaxSize is wrong.");

static constexpr uint16_t kAarch64GRegsMagic = 0x6167;
static constexpr uint16_t kAarch64FPRegsMagic = 0x6166;

template <>
ssize_t SerializeGRegs(const GRegSet<AArch64>& gregs, void* data,
                       size_t data_size) {
  uint8_t* begin = reinterpret_cast<uint8_t*>(data);
  uint8_t* current = begin;
  uint8_t* end = current + data_size;

  // Is there enough space for the header?
  if (end - current < sizeof(header)) {
    LOG_ERROR("Buffer too small to contain header: ", IntStr(end - current));
    return -1;
  }

  // Create header
  header hdr = {kAarch64GRegsMagic, 0, {0, 0, 0, 0}};

  // Serialize header
  memcpy(current, &hdr, sizeof(header));
  current += sizeof(header);

  // Is there enough space for the data?
  if (end - current < sizeof(gregs)) {
    LOG_ERROR("Buffer too small to contain GRegSet data: ",
              IntStr(end - current));
    return -1;
  }

  // Serialize data
  memcpy(current, &gregs, sizeof(gregs));
  current += sizeof(gregs);

  return current - begin;
}

template <>
ssize_t DeserializeGRegs(const void* data, size_t data_size,
                         GRegSet<AArch64>* gregs) {
  const uint8_t* begin = reinterpret_cast<const uint8_t*>(data);
  const uint8_t* current = begin;
  const uint8_t* end = current + data_size;

  // Is there enough space for the header?
  if (end - current < sizeof(header)) {
    LOG_ERROR("Too little data: ", IntStr(end - current));
    return -1;
  }

  // Deserialize the header.
  header hdr;
  memcpy(&hdr, current, sizeof(header));
  current += sizeof(header);

  if (hdr.magic != kAarch64GRegsMagic) {
    LOG_ERROR("Bad magic: ", HexStr(hdr.magic));
    return -1;
  }

  if (hdr.version != 0) {
    LOG_ERROR("Bad version: ", HexStr(hdr.version));
    return -1;
  }

  // Is there enough space for the payload?
  if (end - current < sizeof(*gregs)) {
    LOG_ERROR("Too little data: ", IntStr(end - current));
    return -1;
  }

  // Deserialize the payload.
  memcpy(gregs, current, sizeof(*gregs));
  current += sizeof(*gregs);

  return current - begin;
}

template <>
ssize_t SerializeFPRegs(const FPRegSet<AArch64>& fpregs, void* data,
                        size_t data_size) {
  uint8_t* begin = reinterpret_cast<uint8_t*>(data);
  uint8_t* current = begin;
  uint8_t* end = current + data_size;

  // Is there enough space for the header?
  if (end - current < sizeof(header)) {
    LOG_ERROR("Buffer too small to contain header: ", IntStr(end - current));
    return -1;
  }

  // Create header
  header hdr = {kAarch64FPRegsMagic, 0, {0, 0, 0, 0}};

  // Serialize header
  memcpy(current, &hdr, sizeof(header));
  current += sizeof(header);

  // Is there enough space for the data?
  if (end - current < sizeof(fpregs)) {
    LOG_ERROR("Buffer too small to contain FPRegSet data: ",
              IntStr(end - current));
    return -1;
  }

  // Serialize data
  memcpy(current, &fpregs, sizeof(fpregs));
  current += sizeof(fpregs);

  return current - begin;
}

template <>
ssize_t DeserializeFPRegs(const void* data, size_t data_size,
                          FPRegSet<AArch64>* fpregs) {
  const uint8_t* begin = reinterpret_cast<const uint8_t*>(data);
  const uint8_t* current = begin;
  const uint8_t* end = current + data_size;

  // Is there enough space for the header?
  if (end - current < sizeof(header)) {
    LOG_ERROR("Too little data: ", IntStr(end - current));
    return -1;
  }

  // Deserialize the header.
  header hdr;
  memcpy(&hdr, current, sizeof(header));
  current += sizeof(header);

  if (hdr.magic != kAarch64FPRegsMagic) {
    LOG_ERROR("Bad magic: ", HexStr(hdr.magic));
    return -1;
  }

  if (hdr.version != 0) {
    LOG_ERROR("Bad version: ", HexStr(hdr.version));
    return -1;
  }

  // Is there enough space for the payload?
  if (end - current < sizeof(*fpregs)) {
    LOG_ERROR("Too little data: ", IntStr(end - current));
    return -1;
  }

  // Deserialize the payload.
  memcpy(fpregs, current, sizeof(*fpregs));
  current += sizeof(*fpregs);

  return current - begin;
}

}  // namespace serialize_internal

}  // namespace silifuzz
