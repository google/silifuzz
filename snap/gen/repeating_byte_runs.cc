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

#include "./snap/gen/repeating_byte_runs.h"

#include <cstddef>
#include <optional>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "./common/snapshot.h"
#include "./util/checks.h"

namespace silifuzz {

namespace {

using ByteData = Snapshot::ByteData;
using MemoryBytes = Snapshot::MemoryBytes;
using MemoryBytesList = Snapshot::MemoryBytesList;

// Information about a byte run.
struct ByteRunInfo {
  size_t offset = 0;       // offset from beginning of original memory bytes
  size_t size = 0;         // number of bytes in run.
  bool repeating = false;  // whether all bytes are the same.
};

}  // namespace

// Split repeating byte runs in `memory_bytes` of size kMinRepeatingByteRunSize
// or above into their own MemoryBytes objects.
// Returns a list of memory bytes.
absl::StatusOr<MemoryBytesList> GetRepeatingByteRuns(
    const MemoryBytes& memory_bytes) {
  // Determine parts of `memory_bytes` that should be broken out.
  size_t offset = 0;
  std::vector<ByteRunInfo> byte_run_infos;
  const ByteData& byte_data = memory_bytes.byte_values();
  while (offset < memory_bytes.num_bytes()) {
    // Find the size of repeating byte run from the current offset.
    const auto first_byte = byte_data[offset];
    const size_t max_run_size = memory_bytes.num_bytes() - offset;
    size_t run_size = 1;
    while (run_size < max_run_size &&
           byte_data[offset + run_size] == first_byte) {
      ++run_size;
    }

    if (run_size >= kMinRepeatingByteRunSize) {
      // We can compress this run.
      // Round run size down to a multiple of alignment.
      run_size -= run_size % kByteRunAlignmentSize;
      byte_run_infos.push_back({offset, run_size, true});
    } else {
      // This run is not compressible. Round run size up to the next multiple of
      // kByteRunAlignmentSize as the remaining bytes up to the alignment
      // boundary are also not compressible.
      run_size += (-run_size) & (kByteRunAlignmentSize - 1);

      if (!byte_run_infos.empty() && !byte_run_infos.back().repeating) {
        // merge this run into the previous uncompressed run.
        byte_run_infos.back().size += run_size;
      } else {
        // Start a new uncompressed run.
        byte_run_infos.push_back({offset, run_size, false});
      }
    }
    offset += run_size;
  }
  CHECK_EQ(offset, memory_bytes.num_bytes());

  // Use information gathered above to split input memory bytes.
  MemoryBytesList runs;
  runs.reserve(byte_run_infos.size());
  for (const auto& info : byte_run_infos) {
    const Snapshot::Address run_start_address =
        memory_bytes.start_address() + info.offset;
    ByteData run_byte_data(byte_data.data() + info.offset, info.size);
    RETURN_IF_NOT_OK(
        MemoryBytes::CanConstruct(run_start_address, run_byte_data));
    runs.push_back(MemoryBytes(run_start_address, std::move(run_byte_data)));
  }

  return runs;
}

absl::StatusOr<MemoryBytesList> GetRepeatingByteRuns(
    const MemoryBytesList& memory_bytes_list) {
  std::optional<Snapshot::Address> previous_limit;
  MemoryBytesList result;
  for (const auto& memory_bytes : memory_bytes_list) {
    if (previous_limit.has_value() &&
        previous_limit > memory_bytes.start_address()) {
      return absl::FailedPreconditionError(
          "GetRepeatingByteRuns: MemoryBytesList not sorted by address");
    }
    if (memory_bytes.start_address() % kByteRunAlignmentSize != 0) {
      return absl::FailedPreconditionError(
          absl::StrFormat("GetRepeatingByteRuns: unaligned start address %x",
                          memory_bytes.start_address()));
    }
    if (memory_bytes.limit_address() % kByteRunAlignmentSize != 0) {
      return absl::FailedPreconditionError(
          absl::StrFormat("GetRepeatingByteRuns: unaligned limit address %x",
                          memory_bytes.limit_address()));
    }
    ASSIGN_OR_RETURN_IF_NOT_OK(MemoryBytesList runs,
                               GetRepeatingByteRuns(memory_bytes));
    result.reserve(result.size() + runs.size());
    for (auto& run : runs) {
      result.push_back(std::move(run));
    }
    previous_limit = memory_bytes.limit_address();
  }
  return result;
}

}  // namespace silifuzz
