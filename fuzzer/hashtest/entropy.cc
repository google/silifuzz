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

#include "./fuzzer/hashtest/entropy.h"

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <random>
#include <string>

#include "absl/strings/str_cat.h"

namespace silifuzz {

std::string FormatSeed(uint64_t seed) {
  return absl::StrCat(absl::Hex(seed, absl::kZeroPad16));
}

void RandomizeEntropyBuffer(uint64_t seed, EntropyBuffer& buffer) {
  std::independent_bits_engine<std::mt19937_64, sizeof(uint8_t) * 8, uint8_t>
      engine(seed);
  std::generate(std::begin(buffer.bytes), std::end(buffer.bytes), engine);
}

}  // namespace silifuzz
