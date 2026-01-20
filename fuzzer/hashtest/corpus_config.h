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
#include <functional>
#include <string>
#include <vector>

#include "./fuzzer/hashtest/run_config.h"
#include "./fuzzer/hashtest/testgeneration/candidate.h"
#include "./fuzzer/hashtest/testgeneration/corpus_generator.h"

namespace silifuzz {

// All the configuration needed to run a single corpus.
struct CorpusConfig {
  // A human readable name used to identify this corpus.
  std::string name;

  // A list of strings identifying what experiments are active.
  std::vector<std::string> tags;

  // Config used to generate this corpus
  GenerationConfig generation_config;

  // Filter for set of instructions that can be used to create test content. By
  // default accepts all instructions.
  std::function<bool(const InstructionCandidate&)> instruction_filter =
      [](const InstructionCandidate&) { return true; };

  // How the tests should be run.
  RunConfig run_config;
};
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_CORPUS_CONFIG_H_
