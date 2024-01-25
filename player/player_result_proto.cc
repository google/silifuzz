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

#include "./player/player_result_proto.h"

#include <cstdint>
#include <optional>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "./common/snapshot_enums.h"
#include "./common/snapshot_proto.h"
#include "./proto/player_result.pb.h"
#include "./proto/snapshot.pb.h"
#include "./util/checks.h"
#include "./util/cpu_id.h"
#include "./util/misc_util.h"
#include "./util/proto_util.h"
#include "./util/time_proto_util.h"

namespace silifuzz {

using snapshot_types::PlaybackOutcome;

// Make sure that PlaybackOutcome values match.
static_assert(ToInt(PlaybackOutcome::kAsExpected) ==
              ToInt(proto::PlayerResult::AS_EXPECTED));
static_assert(ToInt(PlaybackOutcome::kPlatformMismatch) ==
              ToInt(proto::PlayerResult::PLATFORM_MISMATCH));
static_assert(ToInt(PlaybackOutcome::kMemoryMismatch) ==
              ToInt(proto::PlayerResult::MEMORY_MISMATCH));
static_assert(ToInt(PlaybackOutcome::kRegisterStateMismatch) ==
              ToInt(proto::PlayerResult::REGISTER_STATE_MISMATCH));
static_assert(ToInt(PlaybackOutcome::kEndpointMismatch) ==
              ToInt(proto::PlayerResult::ENDPOINT_MISMATCH));
static_assert(ToInt(PlaybackOutcome ::kExecutionRunaway) ==
              ToInt(proto::PlayerResult::EXECUTION_RUNAWAY));
static_assert(ToInt(PlaybackOutcome::kExecutionMisbehave) ==
              ToInt(proto::PlayerResult::EXECUTION_MISBEHAVE));

// ========================================================================= //

// static
absl::StatusOr<PlayerResultProto::PlayerResult> PlayerResultProto::FromProto(
    const proto::PlayerResult& proto) {
  PlayerResult result;

  PROTO_MUST_HAVE_FIELD(proto, outcome);
  result.outcome = static_cast<PlaybackOutcome>(proto.outcome());

  // Missing only for kEndpointMismatch, kExecutionRunaway,
  // or kExecutionMisbehave.
  if (result.outcome == PlaybackOutcome::kEndpointMismatch ||
      result.outcome == PlaybackOutcome::kExecutionRunaway ||
      result.outcome == PlaybackOutcome::kExecutionMisbehave) {
    PROTO_MUST_NOT_HAVE_FIELD(proto, end_state_index);
  } else {
    if (proto.has_end_state_index()) {
      result.end_state_index = proto.end_state_index();
    }
  }

  if (proto.has_actual_end_state()) {
    auto endstate_or = SnapshotProto::FromProto(proto.actual_end_state());
    RETURN_IF_NOT_OK_PLUS(endstate_or.status(), "Bad EndState: ");
    result.actual_end_state = endstate_or.value();
  }

  // This can fail due to a narrower range of google.protobuf.Duration than
  // that of absl::Duration. In particular +/-absl::InfiniteDuration() cannot
  // be represented by a proto. This is fine as we do not use those values in
  // normal usage.
  if (proto.has_cpu_usage()) {
    absl::StatusOr<absl::Duration> cpu_usage_or =
        DecodeGoogleApiProto(proto.cpu_usage());
    RETURN_IF_NOT_OK_PLUS(cpu_usage_or.status(), "Bad CPU usage: ");
    result.cpu_usage = cpu_usage_or.value();
  } else {
    result.cpu_usage = absl::ZeroDuration();
  }

  if (proto.has_cpu_id()) {
    result.cpu_id = proto.cpu_id();
  } else {
    result.cpu_id = kUnknownCPUId;
  }
  return result;
}

// static
absl::Status PlayerResultProto::ToProto(
    const PlayerResultProto::PlayerResult& result, proto::PlayerResult& proto) {
  proto.Clear();
  proto.set_outcome(static_cast<proto::PlayerResult::Outcome>(result.outcome));
  if (result.end_state_index.has_value()) {
    proto.set_end_state_index(result.end_state_index.value());
  }
  if (result.actual_end_state.has_value()) {
    SnapshotProto::ToProto(result.actual_end_state.value(),
                           proto.mutable_actual_end_state());
  }

  // EncodeGoogleApiProto fails if duration is +/- InfiniteDuration().  This
  // should not happen in our use.
  absl::Status s =
      EncodeGoogleApiProto(result.cpu_usage, proto.mutable_cpu_usage());
  RETURN_IF_NOT_OK_PLUS(s, "Bad CPU usage: ");
  proto.set_cpu_id(result.cpu_id);
  return absl::OkStatus();
}

}  // namespace silifuzz
