// Copyright 2022 The SiliFuzz Authors.
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

#include "./common/memory_state.h"

#include <string>

#include "benchmark/benchmark.h"
#include "./common/memory_mapping.h"
#include "./common/memory_perms.h"

namespace silifuzz {
namespace {

using MemoryBytesList = SnapshotTypeNames::MemoryBytesList;

MemoryBytesList MakeSequence(int step, int width, int n) {
  MemoryBytesList memory_bytes;
  for (int i = 0; i < n; ++i) {
    memory_bytes.emplace_back(step * i, std::string(width, ' '));
  }
  return memory_bytes;
}

MemoryBytesList MakePartition() { return MakeSequence(32, 32, 100); }

MemoryBytesList MakeDisjoint() { return MakeSequence(64, 32, 100); }

MemoryBytesList MakeOverlapping() { return MakeSequence(24, 32, 100); }

MemoryBytesList MakeReplacing() { return MakeSequence(0, 32, 100); }

template <auto MakeRanges>
void BM_SetMemoryBytes(benchmark::State& state) {
  MemoryBytesList memory_bytes = MakeRanges();
  for (const auto _ : state) {
    MemoryState memory_state;
    memory_state.SetMemoryMappingEmptyPermsOk(
        MemoryMapping::MakeSized(0, 6400, MemoryPerms::None()));
    memory_state.SetMemoryBytes(memory_bytes);
    benchmark::DoNotOptimize(memory_state);
  }
}

BENCHMARK(BM_SetMemoryBytes<MakePartition>);
BENCHMARK(BM_SetMemoryBytes<MakeDisjoint>);
BENCHMARK(BM_SetMemoryBytes<MakeOverlapping>);
BENCHMARK(BM_SetMemoryBytes<MakeReplacing>);

}  // namespace
}  // namespace silifuzz
