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

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_RAW_INSNS_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_RAW_INSNS_UTIL_H_

#include <cstdint>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "./common/snapshot.h"

namespace silifuzz {

// A single code page mapped by snapshots produced by InstructionsToSnapshot.
constexpr inline uint64_t kFuzzCodePageAddr = 0x10000000;

// A single data page mapped by snapshots produced by InstructionsToSnapshot.
// Same as used in testing/silifuzz/ifuzz/ifuzzcc.go
constexpr inline uint64_t kFuzzDataPageAddr = 0x20000000;

// Converts the code snippet into a properly formatted Snapshot.
// The code is placed at `code_start_addr` and RIP is set to the same value.
// Optional `id` parameter allows to specify snapshot id.
//
// The returned Snapshot will contain a single undefined (i.e. no registers)
// end-state at the address immediately following the final `code` byte.
absl::StatusOr<Snapshot> InstructionsToSnapshot(
    absl::string_view code, const Snapshot::Id& id = Snapshot::UnsetId(),
    uint64_t code_start_addr = kFuzzCodePageAddr);

// Similar to the above except the location of the code page is determined
// based on the hash of `code`. The result is guaranteed to be stable.
absl::StatusOr<Snapshot> InstructionsToSnapshotRandomizedCodePage(
    absl::string_view code, const Snapshot::Id& id = Snapshot::UnsetId());

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_RAW_INSNS_UTIL_H_
