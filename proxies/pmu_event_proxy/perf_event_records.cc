// Copyright 2023 The SiliFuzz Authors.
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

#include "./proxies/pmu_event_proxy/perf_event_records.h"

#include <sys/mman.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "./proxies/pmu_event_proxy/ring_buffer_view.h"
#include "./util/checks.h"

namespace silifuzz {

absl::Status PerfEventReadFormat::Parse(uint64_t format, RingBufferView& view) {
  const uint64_t unsupported = format & ~kSupportedFormats;
  if (unsupported != 0) {
    return absl::UnimplementedError(absl::StrCat(
        "Unsupported format bit(s) in PerfEventReadFormat::Parse(): ",
        absl::Hex(unsupported, absl::kZeroPad16)));
  }

#define READ_FORMAT_FIELD(field)                                  \
  do {                                                            \
    if (view.size() < sizeof(field)) {                            \
      return absl::OutOfRangeError(                               \
          "End of data reached in PerfEventReadFormat::Parse()"); \
    }                                                             \
    view.Read(field);                                             \
  } while (false)

#define OPTIONAL_READ_FORMAT_FIELD(fmt, field) \
  do {                                         \
    if (has_format(fmt)) {                     \
      READ_FORMAT_FIELD(field);                \
    }                                          \
  } while (false)

  format_ = format;
  if (has_format(PERF_FORMAT_GROUP)) {
    uint64_t nr;
    READ_FORMAT_FIELD(nr);
    if (nr > kMaxNumValues) {
      return absl::OutOfRangeError(
          absl::StrCat("Number of values ", nr, " larger than limit ",
                       kMaxNumValues, " in PerfEventReadFormat::Parse()"));
    }
    values_.resize(nr);
    OPTIONAL_READ_FORMAT_FIELD(PERF_FORMAT_TOTAL_TIME_ENABLED, time_enabled_);
    OPTIONAL_READ_FORMAT_FIELD(PERF_FORMAT_TOTAL_TIME_RUNNING, time_running_);
    for (uint64_t i = 0; i < nr; ++i) {
      struct Value& v = values_[i];
      READ_FORMAT_FIELD(v.value);
      OPTIONAL_READ_FORMAT_FIELD(PERF_FORMAT_ID, v.id);
    }
  } else {
    values_.resize(1);
    struct Value& v = values_[0];
    READ_FORMAT_FIELD(v.value);
    OPTIONAL_READ_FORMAT_FIELD(PERF_FORMAT_TOTAL_TIME_ENABLED, time_enabled_);
    OPTIONAL_READ_FORMAT_FIELD(PERF_FORMAT_TOTAL_TIME_RUNNING, time_running_);
    OPTIONAL_READ_FORMAT_FIELD(PERF_FORMAT_ID, v.id);
  }

#undef READ_FORMAT_FIELD
#undef OPTIONAL_READ_FORMAT_FIELD

  return absl::OkStatus();
}

absl::Status PerfEventSampleRecord::Parse(uint64_t sample_type,
                                          uint64_t read_format,
                                          RingBufferView& view) {
  const uint64_t unsupported = sample_type & ~kSupportedSamples;
  if (unsupported != 0) {
    return absl::UnimplementedError(
        absl::StrCat("Unsupported samples in PerfEventSampleRecord::Parse(): ",
                     absl::Hex(unsupported, absl::kZeroPad16)));
  }
  sample_type_ = sample_type;

#define SAMPLE_FIELD(field)                                         \
  do {                                                              \
    if (view.size() < sizeof(field)) {                              \
      return absl::OutOfRangeError(                                 \
          "End of data reached in PerfEventSampleRecord::Parse()"); \
    }                                                               \
    view.Read(field);                                               \
  } while (false)

#define OPTIONAL_SAMPLE_FIELD(fmt, field) \
  do {                                    \
    if (has_samples(fmt)) {               \
      SAMPLE_FIELD(field);                \
    }                                     \
  } while (false)

  const size_t original_view_size = view.size();
  SAMPLE_FIELD(header_);
  if (header_.type != PERF_RECORD_SAMPLE) {
    return absl::FailedPreconditionError(
        absl::StrCat("Incorrect event type ", header_.type,
                     " in PerfEventSampleRecord::Parse()"));
  }
  OPTIONAL_SAMPLE_FIELD(PERF_SAMPLE_IDENTIFIER, sample_id_);
  OPTIONAL_SAMPLE_FIELD(PERF_SAMPLE_IP, ip_);
  if (has_samples(PERF_SAMPLE_TID)) {
    SAMPLE_FIELD(pid_);
    SAMPLE_FIELD(tid_);
  }
  OPTIONAL_SAMPLE_FIELD(PERF_SAMPLE_TIME, time_);
  OPTIONAL_SAMPLE_FIELD(PERF_SAMPLE_ADDR, addr_);
  OPTIONAL_SAMPLE_FIELD(PERF_SAMPLE_ID, id_);
  if (has_samples(PERF_SAMPLE_CPU)) {
    SAMPLE_FIELD(cpu_);
    uint32_t unused;
    SAMPLE_FIELD(unused);
  }
  if (has_samples(PERF_SAMPLE_READ)) {
    RETURN_IF_NOT_OK(v_.PerfEventReadFormat::Parse(read_format, view));
  }
  size_t record_size = original_view_size - view.size();
  if (record_size != header_.size) {
    return absl::FailedPreconditionError(
        absl::StrCat("Sample record size in header ", header_.size,
                     " different from actual size ", record_size));
  }
  return absl::OkStatus();
#undef SAMPLE_FIELD
#undef OPTIONAL_SAMPLE_FIELD
}

}  // namespace silifuzz
