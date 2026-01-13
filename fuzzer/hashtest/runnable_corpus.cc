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
#include <random>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "./fuzzer/hashtest/entropy.h"
#include "./util/page_util.h"

namespace silifuzz {
MemoryMapping::~MemoryMapping() {
  if (ptr_ != nullptr) {
    CHECK_EQ(munmap(ptr_, allocated_size_), 0);
  }
}

RunnableCorpus AllocateCorpus(std::mt19937_64& rng, size_t num_tests) {
  size_t mapping_size = RoundUpToPageAlignment(kMaxTestBytes * num_tests);
  void* ptr = mmap(0, mapping_size, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  // TODO(danieljsnyder): handle error gracefully.
  CHECK_NE(ptr, MAP_FAILED);

  std::vector<Test> tests(num_tests);
  for (size_t i = 0; i < num_tests; ++i) {
    // Initialize the test seeds now to prevent partitioning or parallelization
    // from affecting the outcome of test generation.
    tests[i].seed = GetSeed(rng);
  }

  return RunnableCorpus{
      .mapping = MemoryMapping(ptr, mapping_size, 0),
      .tests = std::move(tests),
  };
}

void FinalizeCorpus(RunnableCorpus& corpus, size_t used_size) {
  // Make test memory read-only and executable.
  // TODO(danieljsnyder): handle error gracefully.
  CHECK_EQ(0, mprotect(corpus.mapping.Ptr(), corpus.mapping.AllocatedSize(),
                       PROT_READ | PROT_EXEC));
  corpus.mapping.SetUsedSize(used_size);
}

}  // namespace silifuzz
