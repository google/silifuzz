// Copyright 2025 The SiliFuzz Authors.
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

#include "./fuzzer/hashtest/testgeneration/synthesize_shuffle.h"

#include <cstddef>
#include <functional>
#include <random>

#include "gtest/gtest.h"
#include "./fuzzer/hashtest/testgeneration/rand_util.h"
#include "./fuzzer/hashtest/testgeneration/synthesize_base.h"
#include "./instruction/xed_util.h"

extern "C" {
#include "third_party/libxed/xed-interface.h"
}

namespace silifuzz {

namespace {

TEST(SynthesizeShuffleTest, RandomPermutationMask) {
  InitXedIfNeeded();
  std::mt19937_64 rng(0);
  // Generate a bunch of random permutation masks and make sure they match
  // expected invariant.
  constexpr size_t num_bits = 2;
  constexpr size_t num_elements = 1 << num_bits;
  for (size_t i = 0; i < 1000; i++) {
    size_t mask = RandomPermutationMask<num_bits>(rng);
    bool elements[num_elements] = {};
    // Verify that each element of the mask is unique.
    // Note this also (indirectly) verifies that each element is present because
    // if they aren't all present, at least one will be non-unique.
    for (size_t i = 0; i < num_elements; i++) {
      size_t index = mask & (num_elements - 1);
      EXPECT_FALSE(elements[index]) << index;
      elements[index] = true;
      mask >>= num_bits;
    }
    // Make sure no more bits of the mask are set.
    EXPECT_EQ(mask, 0);
  }
}

void TestShuffleFunc(std::function<void(std::mt19937_64&, RegisterPool&,
                                        InstructionBlock&)>&& f) {
  std::mt19937_64 rng(0);

  // Sweep through different vector widths.
  for (size_t vec_width = 128; vec_width <= 512; vec_width *= 2) {
    RegisterPool base_rpool{};
    // Treat all registers as temporary.
    base_rpool.tmp.gp.set();
    if (vec_width >= 512) {
      base_rpool.tmp.vec.set();
    } else {
      // There are only 16 vector registers if the machine does not have AVX512.
      for (size_t i = 0; i < 16; ++i) {
        base_rpool.tmp.vec.set(i);
      }
    }
    base_rpool.tmp.mask.set();
    base_rpool.tmp.mmx.set();

    base_rpool.vec_width = vec_width;
    // Sweep through different mask widths.
    for (size_t mask_width = 16; mask_width <= 64; mask_width *= 2) {
      base_rpool.mask_width = mask_width;

      // Since the function we are testing is random, it's hard to precisely
      // define the expected behavior. Instead, we just run it a bunch of times
      // with different parameters and make sure it doesn't crash.
      for (size_t i = 0; i < 200; ++i) {
        RegisterPool rpool = base_rpool;
        InstructionBlock block{};
        f(rng, rpool, block);

        // Check that something was emitted.
        EXPECT_GE(block.num_instructions, 1);
        EXPECT_GE(block.bytes.size(), 1);

        // But not too much.
        EXPECT_LE(block.num_instructions, 5);
        EXPECT_LE(block.bytes.size(), 30);
      }
    }
  }
}

TEST(SynthesizeShuffleTest, GPRegPermute) {
  InitXedIfNeeded();
  TestShuffleFunc(
      [](std::mt19937_64& rng, RegisterPool& rpool, InstructionBlock& block) {
        SynthesizeGPRegPermute(rng, PopRandomBit(rng, rpool.tmp.gp), block);
      });
}

TEST(SynthesizeShuffleTest, GPRegMix) {
  InitXedIfNeeded();
  TestShuffleFunc(
      [](std::mt19937_64& rng, RegisterPool& rpool, InstructionBlock& block) {
        SynthesizeGPRegMix(rng, PopRandomBit(rng, rpool.tmp.gp),
                           PopRandomBit(rng, rpool.tmp.gp), block);
      });
}

TEST(SynthesizeShuffleTest, VecRegPermute) {
  InitXedIfNeeded();
  TestShuffleFunc(
      [](std::mt19937_64& rng, RegisterPool& rpool, InstructionBlock& block) {
        SynthesizeVecRegPermute(rng, PopRandomBit(rng, rpool.tmp.vec),
                                PopRandomBit(rng, rpool.tmp.vec), rpool, block);
      });
}

TEST(SynthesizeShuffleTest, VecRegMix) {
  InitXedIfNeeded();
  TestShuffleFunc(
      [](std::mt19937_64& rng, RegisterPool& rpool, InstructionBlock& block) {
        SynthesizeVecRegMix(rng, PopRandomBit(rng, rpool.tmp.vec),
                            PopRandomBit(rng, rpool.tmp.vec),
                            PopRandomBit(rng, rpool.tmp.vec), rpool, block);
      });
}

TEST(SynthesizeShuffleTest, MaskRegPermute) {
  InitXedIfNeeded();
  TestShuffleFunc([](std::mt19937_64& rng, RegisterPool& rpool,
                     InstructionBlock& block) {
    SynthesizeMaskRegPermute(rng, PopRandomBit(rng, rpool.tmp.mask),
                             PopRandomBit(rng, rpool.tmp.mask), rpool, block);
  });
}

TEST(SynthesizeShuffleTest, MaskRegMix) {
  InitXedIfNeeded();
  TestShuffleFunc(
      [](std::mt19937_64& rng, RegisterPool& rpool, InstructionBlock& block) {
        SynthesizeMaskRegMix(rng, PopRandomBit(rng, rpool.tmp.mask),
                             PopRandomBit(rng, rpool.tmp.mask),
                             PopRandomBit(rng, rpool.tmp.mask), rpool, block);
      });
}

TEST(SynthesizeShuffleTest, MMXRegPermute) {
  InitXedIfNeeded();
  TestShuffleFunc(
      [](std::mt19937_64& rng, RegisterPool& rpool, InstructionBlock& block) {
        SynthesizeMMXRegPermute(rng, PopRandomBit(rng, rpool.tmp.mmx),
                                PopRandomBit(rng, rpool.tmp.mmx),
                                RandomBool(rng), block);
      });
}

TEST(SynthesizeShuffleTest, MMXRegMix) {
  InitXedIfNeeded();
  TestShuffleFunc(
      [](std::mt19937_64& rng, RegisterPool& rpool, InstructionBlock& block) {
        SynthesizeMMXRegMix(rng, PopRandomBit(rng, rpool.tmp.mmx),
                            PopRandomBit(rng, rpool.tmp.mmx), block);
      });
}

}  // namespace
}  // namespace silifuzz
