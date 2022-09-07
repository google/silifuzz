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

#include "./util/time_proto_util.h"

#include <string>
#include <vector>

#include "google/protobuf/duration.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/time/time.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {

using silifuzz::testing::IsOk;
using silifuzz::testing::IsOkAndHolds;
using silifuzz::testing::StatusIs;

TEST(TimeProtoUtil, EncodeDurationProto) {
  auto test_encodable_duration = [](int64_t seconds, int64_t nanos) {
    google::protobuf::Duration proto;
    const absl::Duration duration =
        absl::Seconds(seconds) + absl::Nanoseconds(nanos);
    EXPECT_THAT(EncodeGoogleApiProto(duration, &proto), IsOk());
    EXPECT_EQ(proto.seconds(), seconds);
    EXPECT_EQ(proto.nanos(), nanos);
  };

  // Test zero.
  test_encodable_duration(0, 0);

  // Test some encodable values.
  test_encodable_duration(123, 456);
  test_encodable_duration(-789, -9876);

  // Test limits.
  test_encodable_duration(kDurationProtoMaxSeconds, kDurationProtoMaxNanos);
  test_encodable_duration(-kDurationProtoMaxSeconds, -kDurationProtoMaxNanos);

  auto test_unencodable_duration = [](absl::Duration duration) {
    google::protobuf::Duration proto;
    EXPECT_THAT(EncodeGoogleApiProto(duration, &proto),
                StatusIs(absl::StatusCode::kInvalidArgument));
  };

  // Test +/- infinite durations.
  test_unencodable_duration(absl::InfiniteDuration());
  test_unencodable_duration(-absl::InfiniteDuration());

  const absl::Duration just_above_limit =
      absl::Seconds(kDurationProtoMaxSeconds + 1);
  test_unencodable_duration(just_above_limit);
  test_unencodable_duration(-just_above_limit);
}

TEST(TimeProtoUtil, DecodeDurationProto) {
  // Test empty proto.
  EXPECT_THAT(DecodeGoogleApiProto(google::protobuf::Duration()),
              IsOkAndHolds(absl::ZeroDuration()));

  auto test_decodable_proto = [](int64_t seconds, int64_t nanos) {
    google::protobuf::Duration proto;
    proto.set_seconds(seconds);
    proto.set_nanos(nanos);
    const absl::Duration duration =
        absl::Seconds(seconds) + absl::Nanoseconds(nanos);
    EXPECT_THAT(DecodeGoogleApiProto(proto), IsOkAndHolds(duration));
  };

  // Test some decodable values.
  test_decodable_proto(123, 456);
  test_decodable_proto(-789, -9876);

  // Test limits.
  test_decodable_proto(kDurationProtoMaxSeconds, kDurationProtoMaxNanos);
  test_decodable_proto(-kDurationProtoMaxSeconds, -kDurationProtoMaxNanos);

  auto test_undecodable_proto = [](int64_t seconds, int64_t nanos) {
    google::protobuf::Duration proto;
    proto.set_seconds(seconds);
    proto.set_nanos(nanos);
    EXPECT_THAT(DecodeGoogleApiProto(proto),
                StatusIs(absl::StatusCode::kInvalidArgument));
  };

  // Test values just exceeding limits.
  test_undecodable_proto(kDurationProtoMaxSeconds + 1, 0);
  test_undecodable_proto(-kDurationProtoMaxSeconds - 1, 0);
  test_undecodable_proto(0, kDurationProtoMaxNanos + 1);
  test_undecodable_proto(0, -kDurationProtoMaxNanos - 1);
}

TEST(TimeProtoUtil, EncodeTimestampProto) {
  // Test zero.
  google::protobuf::Timestamp proto;
  EXPECT_THAT(EncodeGoogleApiProto(absl::UnixEpoch(), &proto), IsOk());
  EXPECT_EQ(proto.seconds(), 0);
  EXPECT_EQ(proto.nanos(), 0);

  // Test limits.
  absl::Time min_time;
  ASSERT_TRUE(AbslParseFlag("0001-01-01T00:00:00Z", &min_time, nullptr));
  EXPECT_THAT(EncodeGoogleApiProto(min_time, &proto), IsOk());
  EXPECT_EQ(proto.seconds(), kTimeStampProtoMinSeconds);
  EXPECT_EQ(proto.nanos(), kTimeStampProtoMinNanos);
  EXPECT_THAT(EncodeGoogleApiProto(min_time - absl::Nanoseconds(1), &proto),
              StatusIs(absl::StatusCode::kInvalidArgument));

  absl::Time max_time;
  ASSERT_TRUE(
      AbslParseFlag("9999-12-31T23:59:59.999999999Z", &max_time, nullptr));
  EXPECT_THAT(EncodeGoogleApiProto(max_time, &proto), IsOk());
  EXPECT_EQ(proto.seconds(), kTimeStampProtoMaxSeconds);
  EXPECT_EQ(proto.nanos(), kTimeStampProtoMaxNanos);
  EXPECT_THAT(EncodeGoogleApiProto(max_time + absl::Nanoseconds(1), &proto),
              StatusIs(absl::StatusCode::kInvalidArgument));

  auto test_encodable_timestamp = [](int64_t seconds, int64_t nanos) {
    absl::Time t = absl::FromUnixSeconds(seconds) + absl::Nanoseconds(nanos);
    google::protobuf::Timestamp proto;
    EXPECT_THAT(EncodeGoogleApiProto(t, &proto), IsOk());
    EXPECT_EQ(proto.seconds(), seconds);
    EXPECT_EQ(proto.nanos(), nanos);
  };

  // Encode some values.
  test_encodable_timestamp(123, 456);
  test_encodable_timestamp(-789, 9876);
}

}  // namespace
}  // namespace silifuzz
