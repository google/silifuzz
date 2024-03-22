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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_MUTATOR_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_MUTATOR_H_

#include <cstddef>
#include <memory>
#include <random>
#include <vector>

#include "./fuzzer/program.h"

namespace silifuzz {

// Abstract base class for an operation that mutates a program.
// This allows simple mutation operations to be parameterized and composed into
// more complex mutation policies.
template <typename Arch_>
class ProgramMutator {
 public:
  ProgramMutator() = default;
  virtual ~ProgramMutator() = default;

  // Disallow copy.
  ProgramMutator(ProgramMutator&) = delete;
  ProgramMutator(const ProgramMutator&) = delete;

  // Allow move.
  ProgramMutator(ProgramMutator&&) = default;
  ProgramMutator(const ProgramMutator&&) = default;

  // Mutate `program` in place.
  // `other` is an additional program that instructions can be copied from.
  // Note that `other` may be aliased to `program`.
  virtual bool Mutate(MutatorRng& rng, Program<Arch_>& program,
                      const Program<Arch_>& other) = 0;

  using Arch = Arch_;
};

template <typename Arch>
using ProgramMutatorPtr = std::unique_ptr<ProgramMutator<Arch>>;

// Take an r-value and move the contents into a heap-allocated object held by
// a unique_ptr.
template <typename Mutator>
ProgramMutatorPtr<typename Mutator::Arch> MoveIntoPtr(Mutator&& mutator) {
  return ProgramMutatorPtr<typename Mutator::Arch>(
      new Mutator(std::forward<Mutator>(mutator)));
}

// Retry the mutation until it succeeds, up to `retry_limit` times.
template <typename Arch>
class RetryMutation : public ProgramMutator<Arch> {
 public:
  template <typename Child>
  RetryMutation(size_t retry_limit, Child&& mutator)
      : retry_limit_(retry_limit),
        mutator_(MoveIntoPtr(std::forward<Child>(mutator))) {}

  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) {
    for (size_t i = 0; i < retry_limit_; ++i) {
      if (mutator_->Mutate(rng, program, other)) {
        return true;
      }
    }
    return false;
  }

 private:
  size_t retry_limit_;
  ProgramMutatorPtr<Arch> mutator_;
};

// Repeatedly apply a mutation 0-N times, with the exact count based on a
// `repetition_weights`.
// Note that the first weight corresponds to repeating zero times / failing.
// Note that the number of times the mutation is repeated is not affected by if
// the mutation succeeds or fails. Wrap the child mutator with RetryMutation if
// you want success for each iteration.
// If any of the attempts to apply a mutation succeeds, the entire repetition
// succeeds.
template <typename Arch>
class RepeatMutation : public ProgramMutator<Arch> {
 public:
  template <typename Child>
  RepeatMutation(const std::vector<double>& repetition_weights, Child&& mutator)
      : num_repetitions_(repetition_weights.begin(), repetition_weights.end()),
        mutator_(MoveIntoPtr(std::forward<Child>(mutator))) {}

  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) {
    size_t repeat_count = num_repetitions_(rng);
    bool mutated = false;
    for (size_t i = 0; i < repeat_count; ++i) {
      mutated |= mutator_->Mutate(rng, program, other);
    }
    return mutated;
  }

 private:
  std::discrete_distribution<size_t> num_repetitions_;
  ProgramMutatorPtr<Arch> mutator_;
};

template <typename Mutator>
struct Weighted {
  Mutator mutator;
  double weight;
};

// Select a mutation based on a weighted distribution.
template <typename Arch>
class SelectMutation : public ProgramMutator<Arch> {
 public:
  // We use a variadic template here because std::initializer_list does not mix
  // well with std::unique_ptr or other sorts of move-only objects because
  // initializer lists are read only. Constructing a vector from an initializer
  // list also runs into the same problem.
  // TODO(ncbray): support a variable number of arguments, somehow.
  template <typename... Types>
  SelectMutation(Types&&... weighted_mutators) {
    mutators_.reserve(sizeof...(weighted_mutators));
    weights_.reserve(sizeof...(weighted_mutators));
    AddMutators<Types...>(std::forward<Types>(weighted_mutators)...);
    which_mutator_ =
        std::discrete_distribution<size_t>(weights_.begin(), weights_.end());
  }

  bool Mutate(MutatorRng& rng, Program<Arch>& program,
              const Program<Arch>& other) {
    return mutators_[which_mutator_(rng)]->Mutate(rng, program, other);
  }

 private:
  // Helper for the variadic constructor - peel off the first argument, move it
  // onto the heap and into a unique_ptr, and then recuse.
  template <typename WeightedMutator, typename... Types>
  void AddMutators(WeightedMutator&& weighted_mutator, Types&&... others) {
    // Add the first argument.
    using Mutator = decltype(weighted_mutator.mutator);
    mutators_.push_back(
        MoveIntoPtr(std::forward<Mutator>(weighted_mutator.mutator)));
    weights_.push_back(weighted_mutator.weight);

    // Recurse if trailing arguments are present.
    if constexpr (sizeof...(Types)) {
      AddMutators<Types...>(std::forward<Types>(others)...);
    }
  }

  std::vector<ProgramMutatorPtr<Arch>> mutators_;
  std::vector<double> weights_;
  std::discrete_distribution<size_t> which_mutator_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_PROGRAM_MUTATOR_H_
