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

#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_SNAP_MAKER_H_
#define THIRD_PARTY_SILIFUZZ_RUNNER_SNAP_MAKER_H_

#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "./common/snapshot.h"
#include "./common/snapshot_enums.h"

namespace silifuzz {

// SnapMaker is a helper class for making, recording and verifying Snapshot-s.
// The generic pipeline to transform a sequence of instructions into a Snapshot
// is something like:
//
//   <bytes>   ->   SnapMaker::Make()  ->   SnapMaper::RecordEndState()
//             ->   SnapMaker::Verify()
//
// Refer to Make(), RecordEndState() and Verify() for details.
//
// This class is thread-compatible.
class SnapMaker {
 public:
  struct Options {
    // Location of the runner binary.
    std::string runner_path = "";

    // How many rw memory pages Make() can add to repair any occurring
    // page faults
    int max_pages_to_add = 5;

    // How many times Verify() will play each snapshot. Higher values provide
    // more confidence that the snapshot is indeed deterministic. The default
    // value is somewhat arbitrary but it should normally be > 1.
    int num_verify_attempts = 5;

    // If true, reject any snapshot with a locking instruction that accesses
    // memory across cache line boundary. This option is x86-only and has no
    // effect on other platforms. See https://lwn.net/Articles/790464/ for
    // details.
    bool x86_filter_split_lock = false;

    absl::Status Validate() const {
      if (runner_path.empty()) {
        return absl::InvalidArgumentError("runner_path must be non-empty");
      }
      if (max_pages_to_add < 0) {
        return absl::InvalidArgumentError("max_pages_to_add < 0");
      }
      if (num_verify_attempts <= 0) {
        return absl::InvalidArgumentError("num_verify_attempts <= 0");
      }

      return absl::OkStatus();
    }
  };

  explicit SnapMaker(const Options& opts);

  // Not movable or copyable (not needed).
  SnapMaker(const SnapMaker&) = delete;
  SnapMaker(SnapMaker&&) = delete;
  SnapMaker& operator=(const SnapMaker&) = delete;
  SnapMaker& operator=(SnapMaker&&) = delete;

  ~SnapMaker() {}

  // Make is a function that converts a Snapshot into _potentially_
  // Snap-compatible Snapshot.
  //
  // Its main use is to repair and grow the given Snapshot by adding necessary
  // data mappings.
  //
  // Make() always creates exactly one undefined (i.e. endpoint-only) end state
  // or returns an error.
  //
  // One might want to apply both of these to the snapshot (re)made by Make():
  // RecordEndState() and Snapshot::NormalizeAll().
  absl::StatusOr<Snapshot> Make(const Snapshot& snapshot);

  // Records an expected end state for the input snapshot.
  // RETURNS: A snapshot with exactly one expected end state that satisfies
  // EndState::IsComplete() or an error.
  absl::StatusOr<Snapshot> RecordEndState(const Snapshot& snapshot);

  // Verifies the input snapshot to ensure the snapshot is deterministic and
  // executes no more than X instructions.
  // RETURNS: OkStatus() if the snapshot was successfully verified.
  absl::Status Verify(const Snapshot& snapshot);

 private:
  // Makes snapshot in a loop until hitting some stopping condition.
  // The reason for stopping is reported in `stop_reason`.
  //
  // RETURNS: The endpoint that the snapshot reached or error if the snapshot
  // cannot be made (e.g. makes a syscall)
  // The returned Endpoint can be used to construct an undefined EndState and
  // then passed to RecordEndState() to capture the full expected end state.
  absl::StatusOr<snapshot_types::Endpoint> MakeLoop(
      Snapshot* snapshot, snapshot_types::MakerStopReason* stop_reason);

  // Adds a new writable memory page containing `addr` to the snapshot.
  absl::Status AddWritableMemoryForAddress(Snapshot* snapshot,
                                           snapshot_types::Address addr);

  // C-tor args.
  Options opts_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_SNAP_MAKER_H_
