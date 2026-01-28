// Copyright 2026 The Silifuzz Authors.
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

#include "./fuzzer/hashtest/runnable_corpus.h"

#include <sys/mman.h>

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

#include "absl/log/check.h"
#include "third_party/cityhash/city.h"
#include "./fuzzer/hashtest/entropy.h"
#include "./util/page_util.h"

namespace silifuzz {
//

MemoryMapping::~MemoryMapping() {
  if (ptr_ != nullptr) {
    CHECK_EQ(munmap(ptr_, allocated_size_), 0);
  }
}

uint64_t Test::TestContentHash(const MemoryMapping& mapping) const {
  size_t test_length =
      GetTestLength(code, mapping.Ptr(), mapping.AllocatedSize());
  return CityHash64(reinterpret_cast<const char*>(code), test_length);
}

void RunnableCorpus::PrintCorpusValuesForEqualityChecking() {
  for (int i = 0; i < inputs.size(); ++i) {
    std::cout << "input idx: " << i << "\tseed: " << inputs[i].seed
              << "\tentropy_hash: " << inputs[i].BufferHash() << std::endl;
  }
  for (int i = 0; i < tests.size(); ++i) {
    std::cout << "test idx: " << i << "\tseed: " << tests[i].seed
              << "\thash: " << tests[i].TestContentHash(mapping) << std::endl;
  }

  for (int i = 0; i < end_states.size(); ++i) {
    std::cout << "end_state idx: " << i << "\thash: " << end_states[i].hash
              << std::endl;
  }
}

size_t GetTestLength(const void* test_code, const void* start_of_allocation,
                     size_t allocation_size) {
  const uint8_t* max_address =
      reinterpret_cast<const uint8_t*>(start_of_allocation) + allocation_size;
  const uint8_t* first_valid_code_pointer =
      reinterpret_cast<const uint8_t*>(test_code);
  const uint8_t* latest_valid_code_pointer = first_valid_code_pointer;
  const uint8_t* current_pointer = latest_valid_code_pointer;
  constexpr size_t kMaxZeroBytes = 16;
  for (int i = 0; i < kMaxTestBytes; ++i) {
    // If we ever see more than 16 bytes of all zeros (roughly 2 64 bit
    // constants) assume that we hit the end of a test.
    if (current_pointer - latest_valid_code_pointer > kMaxZeroBytes) {
      return latest_valid_code_pointer - first_valid_code_pointer + 1;
    }
    if (*current_pointer != 0) {
      latest_valid_code_pointer = current_pointer;
    }
    ++current_pointer;
    if (current_pointer >= max_address) {
      return latest_valid_code_pointer - first_valid_code_pointer + 1;
    }
  }
  return kMaxTestBytes;
}

}  // namespace silifuzz
