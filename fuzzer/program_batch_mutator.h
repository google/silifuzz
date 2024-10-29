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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_BATCH_MUTATOR_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_BATCH_MUTATOR_H_

#include <cstddef>
#include <cstdint>
#include <limits>
#include <vector>

#include "./fuzzer/program.h"
#include "./fuzzer/program_mutator.h"

namespace silifuzz {

template <typename Arch>
class ProgramBatchMutator {
 public:
  // `seed` is used to initialized the mutator's RNG.
  // `crossover_weight` determines how much crossover the mutator performs.
  // 0.0 => no crossover / 1.0 => only crossover
  // `max_len` is the largest size (in bytes) that the output should be.
  ProgramBatchMutator(uint64_t seed, double crossover_weight,
                      size_t max_len = std::numeric_limits<size_t>::max());

  void Mutate(const std::vector<const std::vector<uint8_t> *> &inputs,
              size_t num_mutants, std::vector<std::vector<uint8_t>> &mutants);

 private:
  void GenerateSingleOutput(const Program<Arch> &input,
                            const Program<Arch> &other,
                            std::vector<uint8_t> &output);

  MutatorRng rng_;
  size_t max_len_;

  ProgramMutatorPtr<Arch> mutator_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_BATCH_MUTATOR_H_
