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

#include "./orchestrator/binary_log_channel.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <string>
#include <thread>  // NOLINT

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "./proto/binary_log_entry.pb.h"
#include "./proto/player_result.pb.h"
#include "./proto/snapshot_execution_result.pb.h"
#include "./util/checks.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"
#include "./util/time_proto_util.h"

namespace silifuzz {
namespace {

using silifuzz::testing::StatusIs;
using ::testing::StartsWith;

class BinaryLogChannelTest : public ::testing::Test {
 protected:
  enum {
    READ_FD = 0,
    WRITE_FD = 1,
  };

  void SetUp() override {
    // We do not close the file descriptors in TearDown because
    // normaly their ownership is transferred to other objects.
    ASSERT_EQ(pipe(pipefd_), 0) << "pipe() failed: " << strerror(errno);
  }

  int GetFD(int index) const {
    CHECK(index >= 0 && index < kNumFDs);
    return pipefd_[index];
  }

  // Like GetFD but release ownership.
  int ReleaseFD(int index) {
    CHECK(index >= 0 && index < kNumFDs);
    int fd = pipefd_[index];
    pipefd_[index] = -1;
    return fd;
  }

  void CloseFD(int index) {
    ASSERT_TRUE(index >= 0 && index < kNumFDs);
    if (pipefd_[index] != -1) {
      close(pipefd_[index]);  // ignore any error.
      pipefd_[index] = -1;
    }
  }

  // Sets only the flags specified and leave others unchanged.
  absl::Status SetsDescriptorFlags(int fd, int flags) {
    int old_flags = fcntl(fd, F_GETFL);
    if (old_flags == -1) {
      return absl::ErrnoToStatus(errno, "Cannot get file descriptor flags");
    }
    if (fcntl(fd, F_SETFL, old_flags | flags) == -1) {
      return absl::ErrnoToStatus(errno, "Cannot set file descriptor flags");
    }
    return absl::OkStatus();
  }

 private:
  static constexpr int kNumFDs = 2;
  int pipefd_[kNumFDs];
};

// Like BuildInfo testcase but for SnapshotExecutionResults.
TEST_F(BinaryLogChannelTest, SnapshotExecutionResults) {
  // Creates a dummy SnapshotExecutionResults proto and fill in some
  // details.
  proto::BinaryLogEntry expected;
  auto result = expected.mutable_snapshot_execution_result();
  result->set_snapshot_id("some_snapshot");
  auto player_result = result->mutable_player_result();
  player_result->set_outcome(proto::PlayerResult::AS_EXPECTED);
  player_result->set_end_state_index(1);
  ASSERT_OK(EncodeGoogleApiProto(absl::Milliseconds(12),
                                 player_result->mutable_cpu_usage()));
  player_result->set_cpu_id(12);

  // Some random date.
  const absl::Time t = absl::UniversalEpoch() + absl::Hours(24);
  ASSERT_OK(EncodeGoogleApiProto(t, result->mutable_time()));

  // Sends a SnapshotExecutionProto over a pipe and checks that we got
  // the same proto back at the other end.
  absl::Status producer_status;
  std::thread producer_thread([this, &expected, &producer_status]() {
    BinaryLogProducer producer(ReleaseFD(WRITE_FD));
    producer_status = producer.Send(expected);
  });
  BinaryLogConsumer consumer(ReleaseFD(READ_FD));
  ASSERT_OK_AND_ASSIGN(proto::BinaryLogEntry entry, consumer.Receive());
  ASSERT_TRUE(producer_thread.joinable());
  producer_thread.join();

  ASSERT_OK(producer_status);
  EXPECT_EQ(entry.snapshot_execution_result().snapshot_id(),
            expected.snapshot_execution_result().snapshot_id());
}

// Check that we got expected error at the one end of the channel when
// the other end has been shut down.
TEST_F(BinaryLogChannelTest, ProducerShutdown) {
  BinaryLogConsumer consumer(ReleaseFD(READ_FD));
  CloseFD(WRITE_FD);
  absl::StatusOr<proto::BinaryLogEntry> entry_or = consumer.Receive();
  EXPECT_TRUE(IsEndOfChannelError(entry_or.status()));
}

TEST_F(BinaryLogChannelTest, ConsumerShutdown) {
  BinaryLogProducer producer(GetFD(WRITE_FD));
  CloseFD(READ_FD);
  proto::BinaryLogEntry e;
  e.mutable_snapshot_execution_result()->set_snapshot_id("some_snapshot");
  EXPECT_TRUE(IsEndOfChannelError(producer.Send(e)));
}

// Check that we got expected error status when the channel is created with
// back descriptor.
TEST_F(BinaryLogChannelTest, BadDescriptor) {
  absl::Status producer_status;
  std::thread producer_thread([&producer_status]() {
    BinaryLogProducer producer(-2, /*take_ownership=*/false);
    proto::BinaryLogEntry e;
    e.mutable_snapshot_execution_result()->set_snapshot_id("some_snapshot");
    producer_status = producer.Send(e);
  });
  BinaryLogConsumer consumer(-3, /*take_ownership=*/false);
  absl::StatusOr<proto::BinaryLogEntry> entry_or = consumer.Receive();
  ASSERT_TRUE(producer_thread.joinable());
  producer_thread.join();

  EXPECT_THAT(producer_status, StatusIs(absl::StatusCode::kInternal,
                                        StartsWith("Constructor failed")));
  EXPECT_THAT(entry_or, StatusIs(absl::StatusCode::kInternal,
                                 StartsWith("Constructor failed")));
}

TEST_F(BinaryLogChannelTest, IgnoreSIGPIPE) {
  // Close the read end. Child should get a EPIPE on write.
  CloseFD(READ_FD);

  EXPECT_EXIT(
      {
        // Revert SIGPIPE to default to verify BinaryLogProducer sets up
        // SIGPIPE handling correctly.
        signal(SIGPIPE, SIG_DFL);

        BinaryLogProducer producer(ReleaseFD(WRITE_FD));
        proto::BinaryLogEntry empty;
        absl::Status status = producer.Send(empty);
        if (status.ok()) {
          LOG_ERROR("Send succeeded unexpectedly");
          exit(1);
        }
        if (!IsEndOfChannelError(status)) {
          LOG_ERROR("unexpected error ", status.message());
          exit(2);
        }
        LOG_INFO("Success");
        exit(0);
      },
      ::testing::ExitedWithCode(0), "Success");
}

}  // namespace
}  // namespace silifuzz
