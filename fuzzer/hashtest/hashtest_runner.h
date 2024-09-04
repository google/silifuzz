// Copyright 2024 The Silifuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_HASHTEST_RUNNER_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_HASHTEST_RUNNER_H_

#include <cstddef>
#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "absl/synchronization/mutex.h"
#include "absl/types/span.h"
#include "./fuzzer/hashtest/instruction_pool.h"
#include "./fuzzer/hashtest/synthesize_base.h"

namespace silifuzz {

// Extract 64-bits worth of entropy from an arbitrary RNG.
template <typename R>
inline uint64_t GetSeed(R& rng) {
  std::uniform_int_distribution<uint64_t> dis;
  return dis(rng);
}

// Format a seed for printing in a consistent, zero-padded way.
std::string FormatSeed(uint64_t seed);

// TODO(ncbray): should there be 8 GP entropy registers? The loop counter was
// carved out of the entropy pool, resulting in 7 registers.
// TODO(ncbray): should rbp be reserved as a frame pointer?
inline constexpr size_t kGPEntropyRegs = 7;
inline constexpr size_t kVecEntropyRegs = 8;
inline constexpr size_t kMaskEntropyRegs = 4;
inline constexpr size_t kMMXEntropyRegs = 4;

inline constexpr size_t kEntropyBytes512 =
    (kVecEntropyRegs * 512 + kMaskEntropyRegs * 64 + kGPEntropyRegs * 64 +
     kMMXEntropyRegs * 64) /
    8;

inline constexpr size_t kEntropyBytes256 =
    (kVecEntropyRegs * 256 + kGPEntropyRegs * 64 + kMMXEntropyRegs * 64) / 8;

// A buffer for holding the initial or final state of a test.
// The number of bytes used depends on the microarch.
struct EntropyBuffer {
  // Alignment required for fast vector register load/store.
  uint8_t bytes[kEntropyBytes512] __attribute__((aligned(64)));

  size_t NumBytes(size_t vector_width) const {
    return vector_width == 512 ? kEntropyBytes512 : kEntropyBytes256;
  }
};

// Fill the buffer with random bytes.
void RandomizeEntropyBuffer(uint64_t seed, EntropyBuffer& buffer);

// Initial state for a test.
struct Input {
  uint64_t seed;
  EntropyBuffer entropy;
};

// Machine instructions for a test.
struct Test {
  // The seed that was used to generate the test.
  // Provides a semi-stable name for the test (the test generation algorithm may
  // be improved from time to time).
  uint64_t seed;

  // The entry point of the test. Jump here to run the test.
  // This is a borrowed reference to memory owned by the Corpus struct.
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

// A collection of tests.
struct Corpus {
  std::vector<Test> tests;
  MemoryMapping mapping;

  size_t MemoryUse() {
    return sizeof(Corpus) + tests.size() * sizeof(Test) + mapping.UsedSize();
  }
};

// We allocate this amount of executable memory per test.
constexpr inline size_t kMaxTestBytes = 1024;

// Created a corpus of the specified size and generate the test seeds.
Corpus AllocateCorpus(Rng& rng, size_t num_tests);

// Synthesize the code for each test into `code_buffer`.
// `code_buffer` must be at least `tests`.size() * kMaxTestsBytes bytes large.
// Assumes each test already has a valid seed.
// Returns the amount of memory used by the generated tests.
size_t SynthesizeTests(absl::Span<Test> tests, uint8_t* code_buffer,
                       xed_chip_enum_t chip, const InstructionPool& ipool);

// Do the final steps to make the corpus useable.
void FinalizeCorpus(Corpus& corpus, size_t used_size);

// The configuration for running a single test.
struct TestConfig {
  size_t vector_width;
  size_t num_iterations;
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

// For each test and input, compute the end state.
// end_states.size() should be tests.size() * inputs.size().
// For test "t" and input "i", the end state will be stored at index:
// t * inputs.size() + i.
void ComputeEndStates(absl::Span<const Test> tests, const TestConfig& config,
                      absl::Span<const Input> inputs,
                      absl::Span<EndState> end_states);

// Given three lists of independently computed end states, determine which end
// state we belive is correct and copy it to `end_state`. If it is unclear which
// end state is correct, mark the entry in `end_state` as bad, and skip running
// that test in the future.
// Returns the number of end states that could not be reconciled.
size_t ReconcileEndStates(absl::Span<EndState> end_state,
                          absl::Span<const EndState> other1,
                          absl::Span<const EndState> other2);

// All the information we want to remember about each hit.
struct Hit {
  // CPU the hit occurred on.
  int cpu;
  // A unique identifier in the range [0, num_tests_generated) where
  // num_tests_generated is the total number of tests generated during this
  // invocation of the runner. (Each test has a unique index.)
  size_t test_index;
  // A unique identifier that should be stable between runs, but is not densely
  // packed like test_index.
  uint64_t test_seed;
  // A unique identifier in the range [0, num_inputs_generated) where
  // num_inputs_generated is the total number of inputs generated during this
  // invocation of the runner. (Each input has a unique index.)
  size_t input_index;
  // A unique identifier that should be stable between runs.
  uint64_t input_seed;
};

// An interface for reporting the results of test execution.
struct ResultReporter {
  void ReportHit(int cpu, size_t test_index, const Test& test,
                 size_t input_index, const Input& input);

  // It's usually much more compact to collect each hit rather than keep
  // per-test statistics. We can always recreate those statistics later from the
  // hits.
  std::vector<Hit> hits;

  absl::Mutex mutex;
};

// The configuration for running multiple tests.
struct RunConfig {
  // How should the test be run?
  TestConfig test;

  // How many tests should you alternate between?
  size_t batch_size;

  // How many times should you run each test + input?
  size_t num_repeat;
};

// Run each test with each input, and check the end state.
// For test "t" and input "i", the end state will be at index:
//  t * inputs.size() + i.
// Tests will executed in an interleaved order and repeated according to the
// `config`.
void RunTests(absl::Span<const Test> tests, absl::Span<const Input> inputs,
              absl::Span<const EndState> end_states, const RunConfig& config,
              size_t test_offset, ResultReporter& result);

// Internal function, exported for testing.
void RunHashTest(void* test, const TestConfig& config,
                 const EntropyBuffer& input, EntropyBuffer& output);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_HASHTEST_RUNNER_H_
