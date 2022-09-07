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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_TIME_PROTO_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_TIME_PROTO_UTIL_H_

#include <cstdint>

#include "google/protobuf/duration.pb.h"
#include "google/protobuf/timestamp.pb.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"

namespace silifuzz {

// The Duration and TimeStamp protos are documented in:
//
// https://developers.google.com/protocol-buffers/docs/reference/google.protobuf
//

// Limits for seconds and nanos in a Duration proto. The allowed ranges are
// [-max, max].

// Maximum absolute second value representable by a duration proto.
inline constexpr int64_t kDurationProtoMaxSeconds = 315576000000L;

// Maximum absolute nano second value representable by a duration proto.
inline constexpr int32_t kDurationProtoMaxNanos = 999999999L;

// Limits for seconds and nanos in a TimeStamp proto. Unlike Duration, the
// upper and lower limits are not symmetric.

// Accorinding to absl/time/time.h, there are 719162 days from 0001-01-01 to
// 1970-01-01 when using the Gregorian calendar.
inline constexpr int64_t kTimeStampProtoMinSeconds =
    -static_cast<int64_t>(719162) * 24 * 60 * 60;
// Number of seconds from Epoch to 9999-12-31T23:59:59.999999999Z
inline constexpr int64_t kTimeStampProtoMaxSeconds = 253402300799L;
inline constexpr int64_t kTimeStampProtoMinNanos = 0L;
inline constexpr int64_t kTimeStampProtoMaxNanos = 999999999L;

// Encodes duration `d` and writes result in `*proto`. Returns OkStatus() or
// an error if `d` cannot be represented by a Duration proto.
absl::Status EncodeGoogleApiProto(absl::Duration d,
                                  google::protobuf::Duration* proto);

// Decodes `proto` and returns a duration. If `proto` is not valid, returns
// an error instead.
absl::StatusOr<absl::Duration> DecodeGoogleApiProto(
    const google::protobuf::Duration& proto);

// Encodes time `t` and writes result in `*proto`. Returns OkStatus() or
// an error if `t` cannot be represented by a Timestamp proto.
absl::Status EncodeGoogleApiProto(absl::Time t,
                                  google::protobuf::Timestamp* proto);

// TODO(dougkwan): implement DecodeGoogleApiProto() for TimeStamp when needed.

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_TIME_PROTO_UTIL_H_
