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

#ifndef THIRD_PARTY_SILIFUZZ_TOOL_LIBS_FIX_TOOL_COMMON_H_
#define THIRD_PARTY_SILIFUZZ_TOOL_LIBS_FIX_TOOL_COMMON_H_

// Fix tool logic that can be shared by different implementations
// of the fix tool.
#include <cstdint>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "./common/snapshot.h"
#include "./player/play_options.h"

namespace silifuzz {
namespace fix_tool_internal {

// An abstract interface for fix tool statistics.
// We use this interface so that fixer logic can be used in different
// environments with different counter implementation.
class FixToolCounters {
 public:
  // Increment `counter` by `delta`. This is not thread-safe.
  virtual void IncrementBy(absl::string_view counter, int64_t delta) = 0;

  // Increment `counter` by 1. This is not thread-safe.
  inline void Increment(absl::string_view counter) { IncrementBy(counter, 1); }

 protected:
  // ctor and dtor are only accessible by derived classes.
  FixToolCounters() = default;
  virtual ~FixToolCounters() = default;

  // Not copyable but movable.
  FixToolCounters(const FixToolCounters&) = delete;
  FixToolCounters(FixToolCounters&&) = default;
  FixToolCounters& operator=(const FixToolCounters&) = delete;
  FixToolCounters& operator=(FixToolCounters&&) = default;
};

// Wrapper class for FixToolCounters, used by FixupSnapshot().
class PlatformFixToolCounters {
 public:
  PlatformFixToolCounters(absl::string_view platform, FixToolCounters* counters)
      : platform_(platform), counters_(counters) {}
  ~PlatformFixToolCounters() = default;

  // Copyable and movable.
  PlatformFixToolCounters(const PlatformFixToolCounters&) = default;
  PlatformFixToolCounters(PlatformFixToolCounters&&) = default;
  PlatformFixToolCounters& operator=(PlatformFixToolCounters&&) = default;
  PlatformFixToolCounters& operator=(const PlatformFixToolCounters&) = default;

  // Increments a counter whose name is silifuzz-<platform>-`args` where the
  // args have been concatenated.
  template <typename... Args>
  void IncCounter(Args&&... args) {
    counters_->Increment(absl::StrCat("silifuzz-", platform_, "-", args...));
  }

  // Increments two counters.
  // An origin-specific counter:
  // silifuzz-<platform>-`origin`-`args`
  // And a counter aggregated across origins.
  // silifuzz-<platform>-ALL-`args`
  template <typename... Args>
  void IncOriginCounter(absl::string_view origin, Args&&... args) {
    IncCounter(origin, "-", args...);
    IncCounter("ALL", "-", args...);
  }

 private:
  std::string platform_;       // platform name to be inserted in counter names.
  FixToolCounters* counters_;  // underlying counters.
};

// Applies platform-independent transformations to `snapshot` E.g. normalizes
// memory mappings and creates a fake expected end state if needed. Updates fix
// tool statistics in `*counters`.  Returns true iff normalization is
// successful. Contents of `snapshot` are undefined if it returns false.
bool NormalizeSnapshot(Snapshot& snapshot, FixToolCounters* counters);

// Rewrites the initial register state of `snapshot`. Updates fix tool
// statistics in `*counters`.  Returns true iff `snapshot` is changed.
//
// Currently, overrides the value of XMM[0] iff all XMM registers are 0 thus
// inhibiting init state optimization causing erratum #1386 in
// https://www.amd.com/system/files/TechDocs/56683-PUB-1.07.pdf
bool RewriteInitialState(Snapshot& snapshot, FixToolCounters* counters);

// Options for FixupSnapshot() below.
struct FixupSnapshotOptions {
  // If true, snapshots containing instructions that access memory across cache
  // line boundaries are filtered by FixupSnapshot. This option is
  // x86-only and has no effect on other platforms.
  bool x86_filter_split_lock = false;

  // If true, snapshots containing instructions that access vsyscall memory
  // region are filtered by FixupSnapshot. This option is x86-only and has no
  // effect on other platforms.
  bool x86_filter_vsyscall_region_access = false;

  // If true, snapshots containing instructions that access memory are filtered
  // by FixupSnapshot. Note that the snap exit instruction is exempted. This
  // option is x86-only currently and has no effect on other platforms.
  bool filter_memory_access = false;

  // If true, enforce fuzzing config. Snapshot with non-conforming memory
  // mappings are filtered.
  bool enforce_fuzzing_config = true;

  // If true, snapshots containing EVEX instructions that read from stack
  // pointer, write to AVX registers, and are non-canonical (i.e. x_bar bit is
  // clear).
  bool x86_filter_non_canonical_evex_sp = false;

  // Amount of CPU that snapshot's execution is allowed to spend before
  // we consider it a runaway.
  absl::Duration cpu_time_budget = PlayOptions::Default().run_time_budget;
};

// Fixes up `input` and updates fix tool statistics in `*counters`.
// If `x86_filter_split_lock` is true, snapshots containing instructions that
// access memory across cache line boundaries are filtered. This option is
// x86-only and has no effect on other platforms.
// Returns the fixed-up snapshot or an error status.
absl::StatusOr<Snapshot> FixupSnapshot(const Snapshot& input,
                                       const FixupSnapshotOptions& options,
                                       PlatformFixToolCounters* counters);

}  // namespace fix_tool_internal
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TOOL_LIBS_FIX_TOOL_COMMON_H_
