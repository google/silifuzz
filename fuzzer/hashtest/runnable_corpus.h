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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_RUNNABLE_CORPUS_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_RUNNABLE_CORPUS_H_

#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#include "./fuzzer/hashtest/corpus_config.h"  // For Input
#include "./fuzzer/hashtest/run_config.h"

namespace silifuzz {

// We allocate this amount of executable memory per test.
constexpr inline size_t kMaxTestBytes = 2048;

// Machine instructions for a test.
struct Test {
  // The seed that was used to generate the test.
  // Provides a semi-stable name for the test (the test generation algorithm may
  // be improved from time to time).
  uint64_t seed;

  // The entry point of the test. Jump here to run the test.
  // This is a borrowed reference to memory owned by the RunnableCorpus struct.
  void* code;
};

class MemoryMapping {
 public:
  MemoryMapping(void* ptr, size_t allocated_size, size_t used_size)
      : ptr_(ptr), allocated_size_(allocated_size), used_size_(used_size) {}

  ~MemoryMapping();

  // No copy.
  MemoryMapping(const MemoryMapping&) = delete;
  MemoryMapping& operator=(const MemoryMapping&) = delete;

  // Move allowed.
  MemoryMapping(const MemoryMapping&&) = default;
  MemoryMapping& operator=(const MemoryMapping&&) = default;

  void* Ptr() const { return ptr_; }

  size_t AllocatedSize() const { return allocated_size_; }

  void SetUsedSize(size_t used) { used_size_ = used; }
  size_t UsedSize() const { return used_size_; }

 private:
  void* ptr_;
  size_t allocated_size_;
  size_t used_size_;
};

// The expected end state of a test + input.
struct EndState {
  // This field contains the hash of the entropy pool when the test exits.
  // For an individual test, it would be faster to store the entire end state
  // entropy struct and memcmp it. This uses 79x the memory of a hash, however,
  // which can quickly become an issue as the number of tests and inputs
  // increases. Memory bandwidth is also becomes more important for
  // multi-threaded testing. The cost of hashing can easily pay for itself.
  uint64_t hash;

  // It's astronomically unlikely for the hash to be zero, so use this value to
  // mark an end state that could not be computed. We could also store this as a
  // separate bool, but that would double the memory usage.
  void SetCouldNotBeComputed() { hash = 0; }

  bool CouldNotBeComputed() const { return hash == 0; }
};

// A collection of tests and information on how they should be run.
struct RunnableCorpus {
  MemoryMapping mapping;
  std::vector<Test> tests;
  std::vector<Input> inputs;

  // Empty until generated.
  std::vector<EndState> end_states;

  size_t MemoryUse() {
    return sizeof(RunnableCorpus) + tests.size() * sizeof(Test) +
           mapping.UsedSize() + sizeof(Input) * inputs.size() +
           sizeof(EndState) * end_states.size();
  }
};

// TODO(b/473040142): Move these functions or their replacements into
// testgeneration directory.

// Allocates the  memory needed for a corpus, and sets the seed of the initial
// corpus
RunnableCorpus AllocateCorpus(std::mt19937_64& rng, size_t num_tests);

// Set the amount of memory used by the corpus and mark the memory as
// read-only and executable.
void FinalizeCorpus(RunnableCorpus& corpus, size_t used_size);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_RUNNABLE_CORPUS_H_
