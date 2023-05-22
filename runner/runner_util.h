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

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_UTIL_H_

// Helpers for runner.
#include <cstddef>
#include <optional>

#include "./common/snapshot_enums.h"
#include "./runner/endspot.h"
#include "./snap/snap.h"
#include "./util/proc_maps_parser.h"

namespace silifuzz {

// Reads /proc/self/maps and parses it.  Stores result in array
// 'proc_maps_entries[]' with capacity 'max_proc_maps_entries'.  Returns the
// number of entries. It dies if there is any error.
size_t ReadProcMapsEntries(ProcMapsEntry* proc_maps_entries,
                           size_t max_proc_maps_entries);

// Returns true iff 'snap' conflicts with any of the memory ranges in one of the
// 'num_proc_maps_entries' elements of 'proc_maps_entries[]'.
bool SnapOverlapsWithProcMapsEntries(const Snap<Host>& snap,
                                     const ProcMapsEntry* proc_maps_entries,
                                     size_t num_proc_maps_entries);

// Converts the EndSpot to the corresponding Endpoint.
// Returns std::nullopt and logs an error when no conversion is possible.
std::optional<snapshot_types::Endpoint> EndSpotToEndpoint(
    const EndSpot& actual_endspot);

// Writes a null-terminated string to the standard output.
void LogToStdout(const char* data);

// Closes unused FDs and enters a seccomp sandbox. The sandbox allows only
// exit_group(2), write(2) by default. This sandbox configuration is similar to
// seccomp-strict but still allows rdtsc and send SIGSYS when a blocked
// syscall is invoked.
// When `allow_kill_syscall` is set also allows kill(2).
void EnterSeccompStrictMode(bool allow_kill_syscall = false);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_RUNNER_UTIL_H_
