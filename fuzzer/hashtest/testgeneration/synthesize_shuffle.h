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

#ifndef THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_SYNTHESIZE_SHUFFLE_H_
#define THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_SYNTHESIZE_SHUFFLE_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <random>

#include "./fuzzer/hashtest/testgeneration/synthesize_base.h"

namespace silifuzz {

// Terminology:
//
// A "permute" function will shuffle the bits in a register, in some sort of
// way. Every bit in the input will be represented in the output. Rotating a
// register is an example of a permutation. Permutations are used to reduce the
// bitwise correlation between values.
// A xor A == 0, but A xor (A rotate N) == ???.
//
// A "mix" function will combine two registers. If either of the two inputs
// is held constant, then setting the other input to a unique value should
// produce a unique output value. In other words, setting either of the inputs
// to a constant will create a unique bijective mapping.
// https://en.wikipedia.org/wiki/Bijection
// Adding two registers together is an example of a mix function. If you mix
// together two _uncorrelated_ values, the entropy of the result will never be
// less that the maximum of the entropy of the inputs. If you mix correlated
// values, you can destroy entropy: a - a == 0.
//
// Permutation and mixing can be used to update an entropy pool. We can choose a
// random function (e.g. instruction) that takes entropy as inputs and produces
// an output. This output may have lower entropy than the inputs (for example
// the function may output zero in most cases) and it may be correlated with the
// inputs (for example, the function may output one of the inputs). To update
// the entropy pool, we choose an element to replace, permute that element, and
// then mix in the output of the random function. This should avoid reducing the
// entropy available in the entropy pool, no matter the nature of the random
// function.

// Functions for manipulating general purpose registers.
// Mixing and permutation will modify the destination register in place.

// Initialize the GP register `dst` with the given `value`.
void SynthesizeGPRegConstInit(uint64_t value, unsigned int dst,
                              InstructionBlock& block);

// Move `src` to `dst`.
void SynthesizeGPRegMov(unsigned int src, unsigned int dst,
                        InstructionBlock& block);

// Permute `dst` in place.
void SynthesizeGPRegPermute(std::mt19937_64& rng, unsigned int dst,
                            InstructionBlock& block);

// Mix `src` into `dst`, in place.
void SynthesizeGPRegMix(std::mt19937_64& rng, unsigned int src,
                        unsigned int dst, InstructionBlock& block);

// Functions for manipulating vector registers.
// Mixing and permutation overwrite the destination.

// Move `src` to `dst`.
void SynthesizeVecRegMov(unsigned int src, unsigned int dst,
                         RegisterPool& rpool, InstructionBlock& block);

// Permute `src` into `dst`.
void SynthesizeVecRegPermute(std::mt19937_64& rng, unsigned int src,
                             unsigned int dst, RegisterPool& rpool,
                             InstructionBlock& block);

// Mix `a` and `b` into `dst`.
void SynthesizeVecRegMix(std::mt19937_64& rng, unsigned int a, unsigned int b,
                         unsigned int dst, RegisterPool& rpool,
                         InstructionBlock& block);

// Functions for manipulating mask registers.
// Mixing and permutation overwrite the destination.

// Initialize the mask register `dst` with the given `value`.
// `tmp` is general purpose register that will be overwritten.
void SynthesizeMaskRegConstInit(uint64_t value, unsigned int dst,
                                unsigned int tmp, RegisterPool& rpool,
                                InstructionBlock& block);

// Move `src` to `dst`.
void SynthesizeMaskRegMov(unsigned int src, unsigned int dst,
                          RegisterPool& rpool, InstructionBlock& block);

// Permute `src` into `dst`.
void SynthesizeMaskRegPermute(std::mt19937_64& rng, unsigned int src,
                              unsigned int dst, RegisterPool& rpool,
                              InstructionBlock& block);

// Mix `a` and `b` into `dst`.
void SynthesizeMaskRegMix(std::mt19937_64& rng, unsigned int a, unsigned int b,
                          unsigned int dst, RegisterPool& rpool,
                          InstructionBlock& block);

// Functions for manipulating MMX registers.
// Mixing and permutation will modify the destination register in place.

// Move `src` to `dst`.
void SynthesizeMMXRegMov(unsigned int src, unsigned int dst,
                         InstructionBlock& block);

// Permute `dst` in place.
// Requires temp register `tmp`.
// If `tmp` happens to be a copy of `dst`, we can emit one fewer instructions.
void SynthesizeMMXRegPermute(std::mt19937_64& rng, unsigned int dst,
                             unsigned int tmp, bool tmp_is_copy_of_dst,
                             InstructionBlock& block);

// Mix `src` into `dst`, in place.
void SynthesizeMMXRegMix(std::mt19937_64& rng, unsigned int src,
                         unsigned int dst, InstructionBlock& block);

// Generate a completely random permutation mask.
// Exposed for testing.
// TODO(ncbray): generate permutation cycles?
template <size_t ElementBits>
size_t RandomPermutationMask(std::mt19937_64& rng) {
  constexpr size_t element_count = 1 << ElementBits;
  static_assert(ElementBits * element_count <= sizeof(size_t) * 8,
                "Mask is too wide");

  uint8_t elements[element_count];

  // Initialize the elements to [0, element_count).
  std::iota(std::begin(elements), std::end(elements), 0);

  // Randomize the order.
  std::shuffle(std::begin(elements), std::end(elements), rng);

  // Generate the mask.
  size_t mask = 0;
  unsigned int shift = 0;
  for (size_t i = 0; i < element_count; ++i) {
    mask |= static_cast<size_t>(elements[i]) << shift;
    shift += ElementBits;
  }
  return mask;
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_FUZZER_HASHTEST_TESTGENERATION_SYNTHESIZE_SHUFFLE_H_
