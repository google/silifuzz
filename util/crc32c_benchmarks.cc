// Copyright 2024 The SiliFuzz Authors.
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

#include <cstddef>
#include <cstdint>
#include <vector>

#include "benchmark/benchmark.h"
#include "./util/crc32c.h"

namespace silifuzz {

void BM_CRC32C(benchmark::State& state) {
  size_t block_size = state.range(0);
  std::vector<uint8_t> buffer(block_size + sizeof(uint64_t), 0);
  // Align buffer pointer to 64-bit boundary.
  size_t offset = reinterpret_cast<uintptr_t>(buffer.data()) % sizeof(uint64_t);
  size_t aligned = offset ? sizeof(uint64_t) - offset : 0;
  uint32_t crc = 0;
  for (auto s : state) {
    crc = crc32c(crc, &buffer[aligned], block_size);
  }
  state.SetBytesProcessed(state.iterations() * block_size);
}

void BM_CRC32CUnaccelerated(benchmark::State& state) {
  size_t block_size = state.range(0);
  std::vector<uint8_t> buffer(block_size + sizeof(uint64_t), 0);
  // Align buffer pointer to 64-bit boundary.
  size_t offset = reinterpret_cast<uintptr_t>(buffer.data()) % sizeof(uint64_t);
  size_t aligned = offset ? sizeof(uint64_t) - offset : 0;
  uint32_t crc = 0;
  for (auto s : state) {
    crc = internal::crc32c_unaccelerated(crc, &buffer[aligned], block_size);
  }
  state.SetBytesProcessed(state.iterations() * block_size);
}

static constexpr size_t kMaxBlockSize = 1 << 16;
BENCHMARK(BM_CRC32C)->RangeMultiplier(4)->Range(1, kMaxBlockSize);
BENCHMARK(BM_CRC32CUnaccelerated)->RangeMultiplier(4)->Range(1, kMaxBlockSize);

}  // namespace silifuzz
