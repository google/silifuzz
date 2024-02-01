// Copyright 2023 The Silifuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_MUTATOR_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_MUTATOR_H_

#include <cstddef>
#include <limits>
#include <random>
#include <vector>

#include "./fuzzer/program.h"

namespace silifuzz {

template <typename Arch>
class ProgramMutator {
 public:
  ProgramMutator(uint64_t seed,
                 size_t max_len = std::numeric_limits<size_t>::max())
      : rng_(seed), max_len_(max_len) {}

  void Mutate(const std::vector<const std::vector<uint8_t> *> &inputs,
              size_t num_mutants, std::vector<std::vector<uint8_t>> &mutants);

 private:
  void GenerateSingleOutput(const Program<Arch> &input,
                            std::vector<uint8_t> &output);

  MutatorRng rng_;
  size_t max_len_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_MUTATOR_H_
