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

#include <cstdlib>  // std::abs()

#include "absl/strings/str_cat.h"
#include "absl/time/time.h"

namespace silifuzz {

namespace {

// Returns true iff duration specified by `seconds` and `nano_seconds` is
// representable as a Duration proto.
bool IsRepresentableDuration(int64_t seconds, int64_t nano_seconds) {
  return std::abs(seconds) <= kDurationProtoMaxSeconds &&
         std::abs(nano_seconds) <= kDurationProtoMaxNanos;
}

// Returns true iff time specified by `seconds` and `nano_seconds` is
// representable as a TimeStamp proto.
bool IsRepresentableTime(int64_t seconds, int64_t nano_seconds) {
  return seconds >= kTimeStampProtoMinSeconds &&
         seconds <= kTimeStampProtoMaxSeconds &&
         nano_seconds >= kTimeStampProtoMinNanos &&
         nano_seconds <= kTimeStampProtoMaxNanos;
}

absl::Status EncodeError(absl::Duration d) {
  return absl::InvalidArgumentError(
      absl::StrCat("Duration ", absl::FormatDuration(d),
                   " cannot be encoded as a Duration proto."));
}

absl::Status EncodeError(absl::Time t) {
  return absl::InvalidArgumentError(
      absl::StrCat("Time ", absl::FormatTime(t),
                   " cannot be encoded as a TimeStamp proto."));
}

}  // namespace

absl::Status EncodeGoogleApiProto(absl::Duration d,
                                  google::protobuf::Duration* proto) {
  if (d == absl::InfiniteDuration() || d == -absl::InfiniteDuration()) {
    return EncodeError(d);
  }

  // Extract seconds and nanoseconds from duration.
  const int64_t seconds = absl::ToInt64Seconds(d);
  const int64_t nanos = absl::ToInt64Nanoseconds(d - absl::Seconds(seconds));
  if (!IsRepresentableDuration(seconds, nanos)) {
    return EncodeError(d);
  }

  proto->Clear();
  proto->set_seconds(seconds);
  proto->set_nanos(nanos);
  return absl::OkStatus();
}

absl::StatusOr<absl::Duration> DecodeGoogleApiProto(
    const google::protobuf::Duration& proto) {
  if (!IsRepresentableDuration(proto.seconds(), proto.nanos())) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Proto ", proto.DebugString(), " cannot be decoded to a Duration."));
  }
  return absl::Seconds(proto.seconds()) + absl::Nanoseconds(proto.nanos());
}

absl::Status EncodeGoogleApiProto(absl::Time t,
                                  google::protobuf::Timestamp* proto) {
  if (t == absl::InfinitePast() || t == absl::InfiniteFuture()) {
    return EncodeError(t);
  }

  // Extract seconds and nanoseconds from time.
  const int64_t seconds = absl::ToUnixSeconds(t);
  const int64_t nano_seconds =
      absl::ToInt64Nanoseconds(t - absl::FromUnixSeconds(seconds));
  if (!IsRepresentableTime(seconds, nano_seconds)) {
    return EncodeError(t);
  }

  proto->Clear();
  proto->set_seconds(seconds);
  proto->set_nanos(nano_seconds);
  return absl::OkStatus();
}

}  // namespace silifuzz
