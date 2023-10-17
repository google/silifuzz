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

#include "absl/strings/string_view.h"

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

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_SNAP_CHECKSUM_H_
