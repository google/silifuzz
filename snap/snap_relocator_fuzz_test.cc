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

#include <cstring>
#include <utility>

#include "fuzztest/fuzztest.h"
#include "./snap/snap_relocator.h"
#include "./util/arch.h"
#include "./util/mmapped_memory_ptr.h"

namespace silifuzz {
namespace {
using ::fuzztest::Arbitrary;

void RelocateRandomBytes(const std::string& bytes) {
  MmappedMemoryPtr<char> relocatable;
  if (bytes.empty()) {
    relocatable = MakeMmappedMemoryPtr<char>(nullptr, 0);
  } else {
    relocatable = AllocateMmappedBuffer<char>(bytes.size());
    memcpy(relocatable.get(), bytes.data(), bytes.size());
  }

  // This should not crash.
  SnapRelocatorError error;
  // Skip validation since the corpus is random data.
  auto corpus = SnapRelocator<Host>::RelocateCorpus(std::move(relocatable),
                                                    false, &error);
}

constexpr size_t kMaxRandomCorpusSize = 1 << 16;

FUZZ_TEST(SnapRelocatorTest, RelocateRandomBytes)
    .WithDomains(Arbitrary<std::string>().WithMaxSize(kMaxRandomCorpusSize));

}  // namespace
}  // namespace silifuzz
