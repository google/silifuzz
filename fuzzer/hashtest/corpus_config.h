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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_CORPUS_CONFIG_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_CORPUS_CONFIG_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "absl/types/span.h"
#include "./fuzzer/hashtest/entropy.h"
#include "./fuzzer/hashtest/run_config.h"
#include "./fuzzer/hashtest/testgeneration/synthesis_config.h"

namespace silifuzz {
// Initial state for a test.
struct Input {
  uint64_t seed = 0;
  EntropyBuffer entropy;
};

// All the configuration needed to run a single corpus.
struct CorpusConfig {
  // A human readable name used to identify this corpus.
  std::string name;

  // A list of strings identifying what experiments are active.
  std::vector<std::string> tags;

  // The chip to generate tests for.
  xed_chip_enum_t chip;

  // Settings for test synthesis.
  SynthesisConfig synthesis_config;

  // The number of tests to generate.
  size_t num_tests = 0;

  // Test entry states.
  absl::Span<const Input> inputs;

  // How the tests should be run.
  RunConfig run_config;
};
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_CORPUS_CONFIG_H_
