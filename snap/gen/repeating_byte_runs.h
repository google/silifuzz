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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_GEN_REPEATING_BYTE_RUNS_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_GEN_REPEATING_BYTE_RUNS_H_

#include <cstddef>
#include <cstdint>

// Splitting memory bytes for run-length compression.
#include "absl/status/statusor.h"
#include "./common/snapshot.h"
#include "./util/mem_util.h"

namespace silifuzz {

// We manipulate data in multiples of uint64_t. So we require this alignment.
inline constexpr size_t kByteRunAlignmentSize = sizeof(uint64_t);

// The minimum size of a repeating byte runs that we would split out from a
// MemoryBytes object into its own MemoryBytes object. It unprofitable to split
// if the run size is too small.
inline constexpr size_t kMinRepeatingByteRunSize = 16;
static_assert(kMinRepeatingByteRunSize >= kByteRunAlignmentSize &&
              kMinRepeatingByteRunSize % kByteRunAlignmentSize == 0);

// Splits `memory bytes_list` into 8-byte aligned runs of repeating bytes and
// non repeating bytes.
//
// RETURNS A memory bytes list in ascending order of addresses and with the
// same contents as `memory_bytes_list`. If there are any repeating byte runs
// of sizes at least kMinRepeatingByteRunSize, the runs are split into
// individual elements of the returned list.
//
// REQUIRES `memory_bytes_list` is sorted by address and all elements are 8-byte
// aligned.
//
absl::StatusOr<Snapshot::MemoryBytesList> GetRepeatingByteRuns(
    const Snapshot::MemoryBytesList& memory_bytes_list);

// The same as the previous function except that it operates on a single
// MemoryBytes instead of a MemoryBytesList.
absl::StatusOr<Snapshot::MemoryBytesList> GetRepeatingByteRuns(
    const Snapshot::MemoryBytes& memory_bytes);

// Returns true iff `byte_data` should be encoded as a byte run.
bool inline IsRepeatingByteRun(const Snapshot::ByteData& byte_data) {
  return byte_data.size() >= kMinRepeatingByteRunSize &&
         byte_data.size() % kByteRunAlignmentSize == 0 &&
         MemAllEqualTo(byte_data.data(), byte_data[0], byte_data.size());
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_GEN_REPEATING_BYTE_RUNS_H_
