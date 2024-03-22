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

#include "./snap/snap_checksum.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "./snap/snap.h"
#include "./util/crc32c.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

void MemoryChecksumCalculator::AddData(const void* data, size_t size) {
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data);
  checksum_ = crc32c(checksum_, bytes, size);
}

uint32_t CalculateMemoryChecksum(const void* data, size_t size) {
  MemoryChecksumCalculator checksum;
  checksum.AddData(data, size);
  return checksum.Checksum();
}

const size_t kSnapCorpusChecksumBegin = offsetof(SnapCorpusHeader, checksum);

const size_t kSnapCorpusChecksumEnd =
    kSnapCorpusChecksumBegin + sizeof(SnapCorpusHeader::checksum);

// This function incrementally calculates the checksum of the data, skipping a
// hole where the checksum is or will be stored.
void CorpusChecksumCalculator::AddData(const void* data, size_t size) {
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(data);
  {
    // The range of data that exists before the hole.
    size_t before_begin = std::min(corpus_offset_, kSnapCorpusChecksumBegin);
    size_t before_end =
        std::min(corpus_offset_ + size, kSnapCorpusChecksumBegin);
    size_t before_size = before_end - before_begin;
    if (before_size) {
      checksum_ = crc32c(checksum_, bytes + (before_begin - corpus_offset_),
                         before_size);
    }
  }

  {
    // The range of data that exists after the hole.
    size_t after_begin = std::max(corpus_offset_, kSnapCorpusChecksumEnd);
    size_t after_end = std::max(corpus_offset_ + size, kSnapCorpusChecksumEnd);
    size_t after_size = after_end - after_begin;
    if (after_size) {
      checksum_ =
          crc32c(checksum_, bytes + (after_begin - corpus_offset_), after_size);
    }
  }

  corpus_offset_ += size;
}

template <typename Arch>
SnapRegisterMemoryChecksum<Arch> CalculateRegisterMemoryChecksum(
    const UContextView<Arch>& view) {
  SnapRegisterMemoryChecksum<Arch> checksum;
  checksum.fpregs_checksum = CalculateMemoryChecksum(*view.fpregs);
  checksum.gregs_checksum = CalculateMemoryChecksum(*view.gregs);
  return checksum;
}

template SnapRegisterMemoryChecksum<AArch64>
CalculateRegisterMemoryChecksum<AArch64>(const UContextView<AArch64>& view);

template SnapRegisterMemoryChecksum<X86_64>
CalculateRegisterMemoryChecksum<X86_64>(const UContextView<X86_64>& view);

}  // namespace silifuzz
