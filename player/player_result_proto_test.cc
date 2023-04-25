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

#include <array>
#include <optional>
#include <string>

#include "google/protobuf/duration.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "google/protobuf/util/message_differencer.h"
#include "./common/snapshot.h"
#include "./common/snapshot_enums.h"
#include "./proto/player_result.pb.h"
#include "./proto/snapshot.pb.h"
#include "./util/checks.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"
#include "./util/time_proto_util.h"

namespace silifuzz {
namespace {

using ::google::protobuf::util::MessageDifferencer;
using snapshot_types::PlaybackOutcome;
using ::testing::_;
using Result = snapshot_types::PlaybackResult<Snapshot::EndState>;

struct BuildOptions {
  // The end state has a signal.
  bool ends_at_signal = false;

  // Add an end state regardless of outcome.
  bool always_have_end_state = false;
};

// Build a proto of a given outcome suitable for testing.
absl::StatusOr<proto::PlayerResult> BuildTestProto(
    PlaybackOutcome outcome, const BuildOptions& options) {
  proto::PlayerResult result;
  result.set_outcome(static_cast<proto::PlayerResult::Outcome>(outcome));

  // Index of the (partially) matched element of
  // Snapshot::expected_end_states().
  // Missing only for kEndpointMismatch, kExecutionRunaway,
  // or kExecutionMisbehave.
  if (outcome != PlaybackOutcome::kEndpointMismatch &&
      outcome != PlaybackOutcome::kExecutionRunaway &&
      outcome != PlaybackOutcome::kExecutionMisbehave) {
    result.set_end_state_index(1);
  }

  // Actual end-state reached.
  // Missing only for kAsExpected or kPlatformMismatch (and only for
  // Snapshot::kNormal snapshots)
  // -- because Snapshot::expected_end_states()[end_state_index] can be used
  // in that case.
  // Might be missing for kExecutionMisbehave.
  // For kExecutionRunaway this is just the arbitrary moment where we've
  // stopped the runaway execution.
  if (options.always_have_end_state ||
      (outcome != PlaybackOutcome::kAsExpected &&
       outcome != PlaybackOutcome::kPlatformMismatch)) {
    proto::EndState* end_state = result.mutable_actual_end_state();
    proto::Endpoint* end_point = end_state->mutable_endpoint();
    end_point->set_instruction_address(0x12345678);
    if (options.ends_at_signal) {
      auto sig = end_point->mutable_signal();
      sig->set_sig_num(proto::Endpoint::SIG_SEGV);
      sig->set_sig_cause(proto::Endpoint::SEGV_CANT_READ);
      sig->set_sig_address(0x80386);
      sig->set_sig_instruction_address(0x12345678);
    }
    proto::RegisterState* regs = end_state->mutable_registers();
    *regs->mutable_gregs() = std::string(128, 'g');
    *regs->mutable_fpregs() = std::string(512, 'f');
  }
  absl::Status s = EncodeGoogleApiProto(absl::Milliseconds(1337),
                                        result.mutable_cpu_usage());
  RETURN_IF_NOT_OK(s);

  result.set_cpu_id(42);
  return result;
}

// Build a Result of a given outcome suitable for testing. This builds
// the exact same result corresponding to each proto built by BuildTestProto
// above.
absl::StatusOr<Result> BuildTestResult(PlaybackOutcome outcome,
                                       const BuildOptions& options) {
  Result result;
  result.outcome = outcome;

  // Index of the (partially) matched element of
  // Snapshot::expected_end_states().
  // Missing only for kEndpointMismatch, kExecutionRunaway,
  // or kExecutionMisbehave.
  if (outcome != PlaybackOutcome::kEndpointMismatch &&
      outcome != PlaybackOutcome::kExecutionRunaway &&
      outcome != PlaybackOutcome::kExecutionMisbehave) {
    result.end_state_index = 1;
  }

  // Actual end-state reached.
  // Missing only for kAsExpected or kPlatformMismatch (and only for
  // Snapshot::kNormal snapshots)
  // -- because Snapshot::expected_end_states()[end_state_index] can be used
  // in that case.
  // Might be missing for kExecutionMisbehave.
  // For kExecutionRunaway this is just the arbitrary moment where we've
  // stopped the runaway execution.
  if (options.always_have_end_state ||
      (outcome != PlaybackOutcome::kAsExpected &&
       outcome != PlaybackOutcome::kPlatformMismatch)) {
    const Snapshot::RegisterState regs(std::string(128, 'g'),
                                       std::string(512, 'f'));
    const Snapshot::Endpoint normal_endpoint(0x12345678);
    const Snapshot::Endpoint signal_endpoint(Snapshot::Endpoint::kSigSegv,
                                             Snapshot::Endpoint::kSegvCantRead,
                                             0x80386, 0x12345678);
    const Snapshot::Endpoint end_point =
        options.ends_at_signal ? signal_endpoint : normal_endpoint;
    result.actual_end_state = Snapshot::EndState(end_point, regs);
  }
  result.cpu_usage = absl::Milliseconds(1337);
  result.cpu_id = 42;
  return result;
}

// Helper to compare 2 Results.
bool ResultEq(const Result& lhs, const Result& rhs) {
  return lhs.outcome == rhs.outcome &&
         lhs.end_state_index == rhs.end_state_index &&
         lhs.actual_end_state == rhs.actual_end_state &&
         lhs.cpu_usage == rhs.cpu_usage && lhs.cpu_id == rhs.cpu_id;
}

// Helper to initialize a PlayerResult proto with garbage.
// This helps testing that unused fields are cleared properly.
proto::PlayerResult ResultProtoWithGarbage() {
  proto::PlayerResult proto;
  proto.set_outcome(proto::PlayerResult::REGISTER_STATE_MISMATCH);
  proto.set_end_state_index(-200);
  proto.mutable_actual_end_state()->mutable_endpoint()->set_instruction_address(
      0xd5aa96ff);
  proto.mutable_cpu_usage()->set_seconds(-98765);
  proto.set_cpu_id(-999);
  return proto;
}

constexpr std::array<PlaybackOutcome, 7> kOutcomes = {
    PlaybackOutcome::kAsExpected,
    PlaybackOutcome::kPlatformMismatch,
    PlaybackOutcome::kMemoryMismatch,
    PlaybackOutcome::kRegisterStateMismatch,
    PlaybackOutcome::kEndpointMismatch,
    PlaybackOutcome::kExecutionRunaway,
    PlaybackOutcome::kExecutionMisbehave,
};

constexpr std::array<PlaybackOutcome, 2> kSignalOutcomes = {
    PlaybackOutcome::kEndpointMismatch,
    PlaybackOutcome::kExecutionMisbehave,
};

TEST(PlayerResultProto, FromProto) {
  for (const auto& outcome : kOutcomes) {
    ASSERT_OK_AND_ASSIGN(proto::PlayerResult result_proto,
                         BuildTestProto(outcome, {}));
    ASSERT_OK_AND_ASSIGN(Result expected, BuildTestResult(outcome, {}));
    ASSERT_OK_AND_ASSIGN(Result result,
                         PlayerResultProto::FromProto(result_proto));
    EXPECT_TRUE(ResultEq(result, expected));
  }
}

TEST(PlayerResultProto, FromProtoWithSignal) {
  BuildOptions options;
  options.ends_at_signal = true;
  for (const auto& outcome : kSignalOutcomes) {
    ASSERT_OK_AND_ASSIGN(proto::PlayerResult result_proto,
                         BuildTestProto(outcome, options));
    ASSERT_OK_AND_ASSIGN(Result expected, BuildTestResult(outcome, options));
    ASSERT_OK_AND_ASSIGN(Result result,
                         PlayerResultProto::FromProto(result_proto));
    EXPECT_TRUE(ResultEq(result, expected));
  }
}

// Force as-expected result to have an end state.
TEST(PlayerResultProto, FromProtoAlwaysHaveEndstate) {
  BuildOptions options;
  options.always_have_end_state = true;
  ASSERT_OK_AND_ASSIGN(proto::PlayerResult result_proto,
                       BuildTestProto(PlaybackOutcome::kAsExpected, options));
  ASSERT_OK_AND_ASSIGN(Result expected,
                       BuildTestResult(PlaybackOutcome::kAsExpected, options));
  ASSERT_OK_AND_ASSIGN(Result result,
                       PlayerResultProto::FromProto(result_proto));
  EXPECT_TRUE(ResultEq(result, expected));
}

TEST(PlayerResultProto, ToProto) {
  for (const auto& outcome : kOutcomes) {
    ASSERT_OK_AND_ASSIGN(Result result, BuildTestResult(outcome, {}));
    ASSERT_OK_AND_ASSIGN(proto::PlayerResult expected,
                         BuildTestProto(outcome, {}));
    proto::PlayerResult result_proto = ResultProtoWithGarbage();
    ASSERT_OK(PlayerResultProto::ToProto(result, result_proto));
    EXPECT_TRUE(MessageDifferencer::Equivalent(result_proto, expected));
  }
}

TEST(PlayerResultProto, ToProtoWithSignal) {
  BuildOptions options;
  options.ends_at_signal = true;
  for (const auto& outcome : kSignalOutcomes) {
    ASSERT_OK_AND_ASSIGN(Result result, BuildTestResult(outcome, options));
    ASSERT_OK_AND_ASSIGN(proto::PlayerResult expected,
                         BuildTestProto(outcome, options));
    proto::PlayerResult result_proto = ResultProtoWithGarbage();
    ASSERT_OK(PlayerResultProto::ToProto(result, result_proto));
    EXPECT_TRUE(MessageDifferencer::Equivalent(result_proto, expected));
  }
}

// Force as-expected result to have an end state.
TEST(PlayerResultProto, ToProtoAlwaysHaveEndstate) {
  BuildOptions options;
  options.always_have_end_state = true;
  ASSERT_OK_AND_ASSIGN(Result result,
                       BuildTestResult(PlaybackOutcome::kAsExpected, options));
  ASSERT_OK_AND_ASSIGN(proto::PlayerResult expected,
                       BuildTestProto(PlaybackOutcome::kAsExpected, options));
  proto::PlayerResult result_proto = ResultProtoWithGarbage();
  ASSERT_OK(PlayerResultProto::ToProto(result, result_proto));
  EXPECT_TRUE(MessageDifferencer::Equivalent(result_proto, expected));
}

// Range of google.protobuf.Duration is narrower than that of absl:Duration.
TEST(PlayerResultProto, InfiniteDurations) {
  ASSERT_OK_AND_ASSIGN(Result result,
                       BuildTestResult(PlaybackOutcome::kAsExpected, {}));
  result.cpu_usage = absl::InfiniteDuration();
  proto::PlayerResult result_proto;
  EXPECT_THAT(PlayerResultProto::ToProto(result, result_proto),
              testing::StatusIs(absl::StatusCode::kInvalidArgument, _));

  result.cpu_usage = -absl::InfiniteDuration();
  EXPECT_THAT(PlayerResultProto::ToProto(result, result_proto),
              testing::StatusIs(absl::StatusCode::kInvalidArgument, _));
}

}  // namespace
}  // namespace silifuzz
