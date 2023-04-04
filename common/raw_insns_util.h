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
#include "./common/proxy_config.h"
#include "./common/snapshot.h"

namespace silifuzz {

// Returns a Snapshot ID that is a function of bytes in `code`.
std::string InstructionsToSnapshotId(absl::string_view code);

// Converts the code snippet into a Snapshot as described in
// https://github.com/google/silifuzz/blob/main/doc/proxy_architecture.md.
// [code_range_start; code_range_start+code_range_size) defines an address range
// where the code page containing bytes from `code`  will be placed.
// code_range_size must be a power of 2. The exact address is determined based
// on the hash of `code`.
//
// The returned Snapshot will contain a single undefined (i.e. no registers)
// expected end-state at the address immediately following the final `code`
// byte. The result is guaranteed to be stable.
absl::StatusOr<Snapshot> InstructionsToSnapshot_X86_64(
    absl::string_view code,
    const FuzzingConfig<X86_64>& config = DEFAULT_X86_64_FUZZING_CONFIG);

absl::StatusOr<Snapshot> InstructionsToSnapshot_AArch64(
    absl::string_view code,
    const FuzzingConfig<AArch64>& config = DEFAULT_AARCH64_FUZZING_CONFIG);

// Entry point for arch-generic tools.
template <typename Arch>
absl::StatusOr<Snapshot> InstructionsToSnapshot(absl::string_view code);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_RAW_INSNS_UTIL_H_
