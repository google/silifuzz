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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_PERF_EVENT_RECORDS_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_PERF_EVENT_RECORDS_H_
#include <linux/perf_event.h> /* Definition of PERF_* constants */

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "absl/log/check.h"
#include "absl/status/status.h"
#include "./proxies/pmu_event_proxy/ring_buffer_view.h"

namespace silifuzz {

// Containers for various perf event record types as described in the man page
// of perf_event_open(). The records are emitted by kernel and read by user mode
// code in an mmap buffer. The classes here are intended to be used by the
// reader, so these containers are generally read-only except for the Parse()
// method. It is not our intension to support all record types or all fields
// of any record type. We only implement the record types and fields as needed.

// Container for a decoded perf event read format structure. This decodes a
// variable length read format structure to provide a convenient way to access
// information. For details, see man page of perf_event_open().
//
// This class is thread-compatible.
class PerfEventReadFormat {
 public:
  // Fields of read format supported.
  static constexpr uint64_t kSupportedFormats =
      PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING |
      PERF_FORMAT_ID | PERF_FORMAT_GROUP;

  // Perf event header has a 16-bit size field, limiting the max size of
  // any perf event record to be 64kb. Each counter value is 8-byte long,
  // So there cannot be more than 8192 values in read format.
  static constexpr size_t kMaxNumValues = 8192;

  PerfEventReadFormat() = default;
  ~PerfEventReadFormat() = default;

  // Copyable and moveable.
  PerfEventReadFormat(const PerfEventReadFormat&) = default;
  PerfEventReadFormat(PerfEventReadFormat&&) = default;
  PerfEventReadFormat& operator=(const PerfEventReadFormat&) = default;
  PerfEventReadFormat& operator=(PerfEventReadFormat&&) = default;

  // Parses data with 'format in 'view' and stores result in this. Returns
  // a status to tell if parsing succeeded. 'view' is updated to reflect bytes
  // consumed in parsing. If parsing failed, contents of this are undefined
  // and the tail of 'view' points to the point of failure in data.
  absl::Status Parse(uint64_t format, RingBufferView& view);

  // Returns format bits.
  uint64_t format() const { return format_; }

  // Returns true if this has all of 'format'.
  bool has_format(uint64_t format) const {
    return (format_ & format) == format;
  }

  // Field getters. Some fields are optional and callers must check
  // format before call the getters.

  // Number of events in a read format object.
  uint64_t nr() const { return values_.size(); }

  // Accumulated time of the counters enabled since creation.
  uint64_t time_enabled() const {
    CheckFormat(PERF_FORMAT_TOTAL_TIME_ENABLED);
    return time_enabled_;
  }

  // Accumulated time of the counters running since creation.
  // May be different from time_running if counters are multiplexed by
  // kernel.
  uint64_t time_running() const {
    CheckFormat(PERF_FORMAT_TOTAL_TIME_RUNNING);
    return time_running_;
  }

  // Returns the i-th value. i must be between 0 and nr() - 1.
  uint64_t value(size_t i) const {
    CHECK_LT(i, nr());
    return values_[i].value;
  }

  // Returns the i-th value id. i must be between 0 and nr() - 1.
  uint64_t id(size_t i) const {
    CheckFormat(PERF_FORMAT_ID);
    CHECK_LT(i, nr());
    return values_[i].id;
  }

 private:
  // Value of an event.  Not all fields are implemented.
  struct Value {
    uint64_t value = 0;  // Event count value read.
    uint64_t id = 0;     // Unique ID of event assigned at perf_event_open().
  };

  void CheckFormat(uint64_t format) const { CHECK(has_format(format)); }

  uint64_t format_ = 0;
  uint64_t time_enabled_ = 0;
  uint64_t time_running_ = 0;
  std::vector<Value> values_;
};

// Container for a decoded perf event sample record. The perf event kernel
// API writes variable-length-records with optional fields. This class
// decodes a raw sample record to provide a convenient way to access
// information represented by a sample record.
//
// This class is thread-safe as it is read-only.
class PerfEventSampleRecord {
 public:
  // Fields of a perf event sample record supported.  We do not implement all
  // fields but only what we need.
  static constexpr uint64_t kSupportedSamples =
      PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_IP | PERF_SAMPLE_TID |
      PERF_SAMPLE_TIME | PERF_SAMPLE_ADDR | PERF_SAMPLE_ID | PERF_SAMPLE_CPU |
      PERF_SAMPLE_READ;

  PerfEventSampleRecord() = default;
  ~PerfEventSampleRecord() = default;

  // Parses data in 'view' with format described by 'sample_type' and
  // 'read_format' and stores result in this. Returns a status to tell if
  // parsing succeeded. 'view' is updated to reflect bytes consumed in
  // parsing. If parsing failed, contents of this are undefined and the tail
  // of 'view' points to the point of failure in data.
  absl::Status Parse(uint64_t sample_type, uint64_t read_format,
                     RingBufferView& view);

  // Copyable and moveable by default.
  PerfEventSampleRecord(const PerfEventSampleRecord&) = default;
  PerfEventSampleRecord& operator=(const PerfEventSampleRecord&) = default;
  PerfEventSampleRecord(PerfEventSampleRecord&&) = default;
  PerfEventSampleRecord& operator=(PerfEventSampleRecord&&) = default;

  // Additional information about the sample.  See perf_event_header.misc in the
  // man page of perf_event_open() for details.
  uint16_t misc() const { return header_.misc; }

  // Bit masks indicating present fields in this sample record. For the bit
  // values, see perf_event_attr.sample_type in man page of perf_event_open().
  uint64_t sample_type() const { return sample_type_; }

  // Returns true if this has all of 'samples'.
  bool has_samples(uint64_t samples) const {
    return (sample_type_ & samples) == samples;
  }

  // Getters for optional fields in a perf event sample record.
  // Clients need to call has_samples() to check that if fields are present
  // or not before calling.

  // Sample ID. This is a duplicate of id().
  uint64_t sample_id() const {
    CheckSample(PERF_SAMPLE_IDENTIFIER);
    return sample_id_;
  }

  // Instruction pointer associated with the sample.
  uint64_t ip() const {
    CheckSample(PERF_SAMPLE_IP);
    return ip_;
  }

  // Process ID associated with the sample.
  uint32_t pid() const {
    CheckSample(PERF_SAMPLE_TID);
    return pid_;
  }

  // Thread ID associated with the sample.
  uint32_t tid() const {
    CheckSample(PERF_SAMPLE_TID);
    return tid_;
  }

  // Time stamp of the sample.
  uint64_t time() const {
    CheckSample(PERF_SAMPLE_TIME);
    return time_;
  }

  // An address associated with the sample. This is usually the address of a
  // tracepoint, breakpoint, or software event;  otherwise the value is 0.
  uint64_t addr() const {
    CheckSample(PERF_SAMPLE_ADDR);
    return addr_;
  }

  // Unique sample ID.
  uint64_t id() const {
    CheckSample(PERF_SAMPLE_ID);
    return id_;
  }

  // CPU associated with the sample.
  uint32_t cpu() const {
    CheckSample(PERF_SAMPLE_CPU);
    return cpu_;
  }

  // A sample can have multiple read values, this returns a PerfEvenReadFormat
  // object to access individual values.
  const PerfEventReadFormat& v() const {
    CheckSample(PERF_SAMPLE_READ);
    return v_;
  }

 private:
  void CheckSample(uint64_t samples) const { CHECK(has_samples(samples)); }

  uint64_t sample_type_;  // Sample format bitmask.

  // Record header.
  perf_event_header header_;

  // Optional fields.
  uint64_t sample_id_;
  uint64_t ip_;
  uint32_t pid_;
  uint32_t tid_;
  uint64_t time_;
  uint64_t addr_;
  uint64_t id_;
  uint32_t cpu_;
  PerfEventReadFormat v_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_PERF_EVENT_RECORDS_H_
