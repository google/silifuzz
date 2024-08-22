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

#include "./fuzzer/hashtest/hashtest_runner.h"

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <random>

#include "absl/log/check.h"
#include "./fuzzer/hashtest/hashtest_runner_widgits.h"
#include "./fuzzer/hashtest/synthesize_base.h"

namespace silifuzz {

void RandomizeEntropyBuffer(uint64_t seed, EntropyBuffer& buffer) {
  std::independent_bits_engine<Rng, sizeof(uint8_t) * 8, uint8_t> engine(seed);
  std::generate(std::begin(buffer.bytes), std::end(buffer.bytes), engine);
}

void RunHashTest(void* test, const TestConfig& config,
                 const EntropyBuffer& input, EntropyBuffer& output) {
  if (config.vector_width == 512) {
    RunHashTest512(test, config.num_iterations, &input, &output);
  } else if (config.vector_width == 256) {
    RunHashTest256(test, config.num_iterations, &input, &output);
  } else {
    CHECK(false) << "Unsupported vector width: " << config.vector_width;
  }
}
}  // namespace silifuzz
