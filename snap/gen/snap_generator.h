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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_GEN_SNAP_GENERATOR_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_GEN_SNAP_GENERATOR_H_

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/mapped_memory_map.h"
#include "./common/snapshot.h"
#include "./common/snapshot_util.h"
#include "./util/arch.h"
#include "./util/platform.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

// Per-snap generation options.
struct SnapifyOptions {
  // If true, allows the only expected endstate of the _input_ snapshot(s) to
  // be Snapshot::State::kUndefinedEndState.
  bool allow_undefined_end_state = false;

  // Use the end state for this platform.
  PlatformId platform_id = PlatformId::kAny;

  // Use run-length compression for memory byte data.
  bool compress_repeating_bytes = true;

  // Keep executable pages uncompressed so they can be mmaped.
  bool support_direct_mmap = false;

  // Returns Options for running snapshots produced by V2-style Maker.
  // `arch_id` specified the architecture of the snapshot. The default values
  // for SnapifyOptions may depend on the architecture being targeted.
  static constexpr SnapifyOptions V2InputRunOpts(ArchitectureId arch_id) {
    return MakeOpts(arch_id, false);
  }

  // Returns Options for making V2-style snapshots.
  static constexpr SnapifyOptions V2InputMakeOpts(ArchitectureId arch_id) {
    return MakeOpts(arch_id, true);
  }

 private:
  static constexpr SnapifyOptions MakeOpts(ArchitectureId arch_id,
                                           bool allow_undefined_end_state) {
    // On aarch64 we want to avoid compressing executable pages so that they can
    // be mmaped. This works around a performance bottlekneck, but makes the
    // corpus ~2.6x larger. For now, don't try to mmap executable pages on
    // x86_64.
    bool support_direct_mmap = arch_id == ArchitectureId::kAArch64;
    return SnapifyOptions{
        .allow_undefined_end_state = allow_undefined_end_state,
        .support_direct_mmap = support_direct_mmap};
  }
};

// Tests if snapshot can be converted to Snap.
// Returns NOT_FOUND if there's no suitable expected end state for the
// selected platform.
absl::Status CanSnapify(const Snapshot &snapshot, const SnapifyOptions &opts);

// Convert 'snapshot' into a form that GenerateSnap() can convert into a
// Snap that produces the same result as the 'snapshot'. The conversion
// includes adding an exit sequence at the end state instruction
// address and including all writable mapping memory bytes in the end
// state.
absl::StatusOr<Snapshot> Snapify(const Snapshot &snapshot,
                                 const SnapifyOptions &opts);


}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_GEN_SNAP_GENERATOR_H_
