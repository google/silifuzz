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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_SNAP_CHECKSUM_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_SNAP_CHECKSUM_H_

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "absl/strings/string_view.h"
#include "./snap/snap.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

// A class for incrementally calculating the checksum of arbitrary memory.
class MemoryChecksumCalculator {
 public:
  MemoryChecksumCalculator() : checksum_(0) {}
  void AddData(const void* data, size_t size);
  void AddData(absl::string_view data) { AddData(data.data(), data.size()); }
  uint32_t Checksum() const { return checksum_; }

 private:
  uint32_t checksum_;
};

// A single-shot wrapper for the checksum calculator.
uint32_t CalculateMemoryChecksum(const void* data, size_t size);

template <typename T>
uint32_t CalculateMemoryChecksum(const T& data) {
  // Prevent an easy accidental misuse.
  static_assert(!std::is_pointer_v<T>, "Should not be checksumming pointers.");
  return CalculateMemoryChecksum(&data, sizeof(data));
}

// A class for incrementally calculating the corpus checksum.
// This is a normal checksum calculation, except that the bytes in the corpus
// that contain the checksum of the corpus are skipped.
// This lets us calculate the checksum and then write the value back to the
// corpus without invalidating the checksum.
class CorpusChecksumCalculator {
 public:
  CorpusChecksumCalculator() : corpus_offset_(0), checksum_(0) {}
  void AddData(const void* data, size_t size);
  void AddData(absl::string_view data) { AddData(data.data(), data.size()); }
  uint32_t Checksum() const { return checksum_; }

 private:
  size_t corpus_offset_;
  uint32_t checksum_;
};

// Computes SnapRegisterMemoryChecksum from `view`. See snap.h for details.
template <typename Arch>
SnapRegisterMemoryChecksum<Arch> CalculateRegisterMemoryChecksum(
    const UContextView<Arch>& view);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_SNAP_CHECKSUM_H_
