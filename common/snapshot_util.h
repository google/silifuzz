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

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_UTIL_H_

#include "absl/status/status.h"
#include "./common/snapshot.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

// Register data conversion helper.
// Returned RegisterState will be for Snapshot::CurrentArchitecture().
template <typename Arch>
Snapshot::RegisterState ConvertRegsToSnapshot(const GRegSet<Arch>& gregs,
                                              const FPRegSet<Arch>& fpregs);

// Register data conversion helper.
// REQUIRES: register_state is in Snapshot::CurrentArchitecture().
template <typename Arch>
absl::Status ConvertRegsFromSnapshot(
    const Snapshot::RegisterState& register_state, GRegSet<Arch>* gregs);
template <typename Arch>
absl::Status ConvertRegsFromSnapshot(
    const Snapshot::RegisterState& register_state, GRegSet<Arch>* gregs,
    FPRegSet<Arch>* fpregs);

using BorrowedMemoryBytesList = std::vector<const Snapshot::MemoryBytes*>;
using BorrowedMappingBytesList = std::vector<BorrowedMemoryBytesList>;

// Split `memory_bytes_list` into separate lists, one per memory mapping in
// `memory_mapping_list`. `memory_byte_list` should be normalized and have no
// elements that span multiple mappings.
// This function does not return a MemoryBytesList because that would require
// copying the contents and this can increase the memory footprint of corpus
// creation significantly. Instead, it returns a list of pointers that are
// borrowed references to the data contained in `memory_byte_list`. It is
// expected that `memory_bytes_list` will not be modified in any way while the
// return value is live. If it is modified, memory unsafety may result.
// This is a sharp edge that the caller may cut themselves on, but the intended
// use for this function is during corpus generation and Shapshots are currently
// not being mutated during this process.
BorrowedMappingBytesList SplitBytesByMapping(
    const Snapshot::MemoryMappingList& memory_mapping_list,
    const Snapshot::MemoryBytesList& memory_byte_list);

// Turn a list of MemoryBytes into a list of pointers to those memory bytes.
// The underlying MemoryBytes memory is still owned by the original list. It is
// expected that `memory_bytes_list` will not be modified in any way while the
// return value is live.
BorrowedMemoryBytesList ToBorrowedMemoryBytesList(
    const Snapshot::MemoryBytesList& memory_byte_list);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_UTIL_H_
