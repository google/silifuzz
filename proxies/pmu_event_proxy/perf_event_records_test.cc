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

#include <linux/perf_event.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "./proxies/pmu_event_proxy/ring_buffer_view.h"
#include "./util/testing/status_macros.h"
#include "./util/testing/status_matchers.h"

namespace silifuzz {
namespace {

using silifuzz::testing::StatusIs;

// Convert a trivially copyable value into a std::string.
template <typename T>
std::string AsString(const T& t) {
  static_assert(std::is_trivially_copyable<T>::value);
  return std::string(
      std::string_view(reinterpret_cast<const char*>(&t), sizeof(T)));
}

// Narrows a size_t type into uint16_t or die if cast dropped any bits.
uint16_t CastToU16OrDie(size_t n) {
  const uint16_t v = static_cast<uint16_t>(n);
  CHECK_EQ(n, v) << "Lossy cast to uint16_t";
  return v;
}

TEST(PerfEventRecords, InvalidReadFormats) {
  constexpr size_t kBufferSize = 32;
  std::string ring_buffer(kBufferSize, 0);
  RingBufferView view(ring_buffer.size(), 0, ring_buffer.data(),
                      ring_buffer.size());
  PerfEventReadFormat read_format;
  EXPECT_THAT(read_format.Parse(~PerfEventReadFormat::kSupportedFormats, view),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(PerfEventRecords, ReadFormatOutOfData) {
  constexpr size_t kBufferSize = 32;
  std::string ring_buffer(kBufferSize, 0);
  RingBufferView view(0, 0, ring_buffer.data(), ring_buffer.size());
  PerfEventReadFormat read_format;
  EXPECT_THAT(read_format.Parse(PerfEventReadFormat::kSupportedFormats, view),
              StatusIs(absl::StatusCode::kOutOfRange));
}

TEST(PerfEventRecords, EmptyFormat) {
  constexpr size_t kBufferSize = 32;
  std::string ring_buffer(kBufferSize, 0);
  // A read format without any format bits set has only a single value.
  constexpr uint64_t kValue = 1;
  const std::string read_format_bytes = AsString(kValue);
  memcpy(ring_buffer.data(), read_format_bytes.data(),
         read_format_bytes.size());
  RingBufferView view(read_format_bytes.size(), 0, ring_buffer.data(),
                      ring_buffer.size());

  constexpr uint64_t kFormat = 0;
  PerfEventReadFormat read_format;
  EXPECT_OK(read_format.Parse(kFormat, view));
  EXPECT_EQ(read_format.format(), kFormat);
  EXPECT_FALSE(read_format.has_format(PERF_FORMAT_TOTAL_TIME_ENABLED));
  EXPECT_FALSE(read_format.has_format(PERF_FORMAT_TOTAL_TIME_RUNNING));
  EXPECT_FALSE(read_format.has_format(PERF_FORMAT_ID));
  EXPECT_FALSE(read_format.has_format(PERF_FORMAT_GROUP));
  EXPECT_TRUE(read_format.nr() == 1 && read_format.value(0) == kValue);
}

TEST(PerfEventRecords, AllSupportedFormatsExceptGroup) {
  constexpr size_t kBufferSize = 64;
  std::string ring_buffer(kBufferSize, 0);
  PerfEventReadFormat read_format;
  constexpr uint64_t kFormat = PERF_FORMAT_TOTAL_TIME_ENABLED |
                               PERF_FORMAT_TOTAL_TIME_RUNNING | PERF_FORMAT_ID;
  static_assert(kFormat ==
                (PerfEventReadFormat::kSupportedFormats & ~PERF_FORMAT_GROUP));

  // Create a read format struct all supported format bits except group
  // format.  It should contain only 1 single value.
  constexpr uint64_t kValue = 1;
  constexpr uint64_t kTimeEnabled = 2;
  constexpr uint64_t kTimeRunning = 3;
  constexpr uint64_t kId = 4;
  const std::string read_format_bytes = AsString(kValue) +
                                        AsString(kTimeEnabled) +
                                        AsString(kTimeRunning) + AsString(kId);

  CHECK_LE(read_format_bytes.size(), ring_buffer.size());
  memcpy(ring_buffer.data(), read_format_bytes.data(),
         read_format_bytes.size());
  RingBufferView view(read_format_bytes.size(), 0, ring_buffer.data(),
                      ring_buffer.size());

  EXPECT_OK(read_format.Parse(kFormat, view));
  EXPECT_EQ(read_format.format(), kFormat);
  EXPECT_TRUE(read_format.nr() == 1 && read_format.value(0) == kValue);
  EXPECT_TRUE(read_format.has_format(PERF_FORMAT_TOTAL_TIME_ENABLED) &&
              read_format.time_enabled() == kTimeEnabled);
  EXPECT_TRUE(read_format.has_format(PERF_FORMAT_TOTAL_TIME_RUNNING) &&
              read_format.time_running() == kTimeRunning);
  EXPECT_TRUE(read_format.has_format(PERF_FORMAT_ID) &&
              read_format.id(0) == kId);
}

TEST(PerfEventRecords, AllSupportedFormats) {
  constexpr size_t kBufferSize = 64;
  std::string ring_buffer(kBufferSize, 0);
  PerfEventReadFormat read_format;
  constexpr uint64_t kFormat = PERF_FORMAT_TOTAL_TIME_ENABLED |
                               PERF_FORMAT_TOTAL_TIME_RUNNING | PERF_FORMAT_ID |
                               PERF_FORMAT_GROUP;
  static_assert(kFormat == PerfEventReadFormat::kSupportedFormats);

  // Create a read format struct with all supported format bits and 2 values.
  constexpr uint64_t kNr = 2;
  constexpr uint64_t kTimeEnabled = 3;
  constexpr uint64_t kTimeRunning = 4;
  constexpr uint64_t kValue0 = 5;
  constexpr uint64_t kId0 = 6;
  constexpr uint64_t kValue1 = 7;
  constexpr uint64_t kId1 = 8;
  const std::string read_format_bytes =
      AsString(kNr) + AsString(kTimeEnabled) + AsString(kTimeRunning) +
      AsString(kValue0) + AsString(kId0) + AsString(kValue1) + AsString(kId1);

  CHECK_LE(read_format_bytes.size(), ring_buffer.size());
  memcpy(ring_buffer.data(), read_format_bytes.data(),
         read_format_bytes.size());
  RingBufferView view(read_format_bytes.size(), 0, ring_buffer.data(),
                      ring_buffer.size());

  EXPECT_OK(read_format.Parse(kFormat, view));
  EXPECT_EQ(read_format.format(), kFormat);
  EXPECT_EQ(read_format.nr(), kNr);
  EXPECT_TRUE(read_format.has_format(PERF_FORMAT_TOTAL_TIME_ENABLED) &&
              read_format.time_enabled() == kTimeEnabled);
  EXPECT_TRUE(read_format.has_format(PERF_FORMAT_TOTAL_TIME_RUNNING) &&
              read_format.time_running() == kTimeRunning);
  EXPECT_TRUE(read_format.has_format(PERF_FORMAT_ID));
  EXPECT_TRUE(read_format.has_format(PERF_FORMAT_GROUP));

  ASSERT_EQ(read_format.nr(), kNr /* 2 */);
  EXPECT_EQ(read_format.value(0), kValue0);
  EXPECT_EQ(read_format.id(0), kId0);
  EXPECT_EQ(read_format.value(1), kValue1);
  EXPECT_EQ(read_format.id(1), kId1);
}

TEST(PerfEventRecords, InvalidSamples) {
  constexpr size_t kBufferSize = 32;
  std::vector<char> ring_buffer(kBufferSize, 0);
  RingBufferView view(ring_buffer.size(), 0, ring_buffer.data(),
                      ring_buffer.size());
  PerfEventSampleRecord sample_record;
  constexpr uint64_t kReadFormat = 0;  // just a single 64-bit value.
  EXPECT_THAT(sample_record.Parse(~PerfEventSampleRecord::kSupportedSamples,
                                  kReadFormat, view),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(PerfEventRecords, SampleRecordOutOfData) {
  constexpr size_t kBufferSize = 32;
  std::vector<char> ring_buffer(kBufferSize, 0);
  RingBufferView view(0, 0, ring_buffer.data(), ring_buffer.size());
  PerfEventSampleRecord sample_record;
  constexpr uint64_t kReadFormat = 0;  // just a single 64-bit value.
  EXPECT_THAT(sample_record.Parse(PerfEventSampleRecord::kSupportedSamples,
                                  kReadFormat, view),
              StatusIs(absl::StatusCode::kOutOfRange));
}

TEST(PerfEventRecords, EmptySampleType) {
  constexpr size_t kBufferSize = 64;
  std::vector<char> ring_buffer(kBufferSize, 0);
  const std::string sample_record_body;  // empty.
  constexpr uint16_t kMisc = PERF_RECORD_MISC_USER;
  perf_event_header header{.type = PERF_RECORD_SAMPLE,
                           .misc = kMisc,
                           .size = CastToU16OrDie(sizeof(perf_event_header) +
                                                  sample_record_body.size())};
  const std::string sample_record_bytes = AsString(header) + sample_record_body;
  CHECK_LE(sample_record_bytes.size(), ring_buffer.size());
  memcpy(ring_buffer.data(), sample_record_bytes.data(),
         sample_record_bytes.size());
  RingBufferView view(sample_record_bytes.size(), 0, ring_buffer.data(),
                      ring_buffer.size());

  PerfEventSampleRecord sample_record;
  constexpr uint64_t kSampleType = 0;
  constexpr uint64_t kReadFormat = 0;  // just a single 64-bit value.
  EXPECT_OK(sample_record.Parse(kSampleType, kReadFormat, view));
  EXPECT_EQ(sample_record.sample_type(), kSampleType);
  EXPECT_EQ(sample_record.misc(), kMisc);
  EXPECT_FALSE(sample_record.has_samples(PERF_SAMPLE_IDENTIFIER));
  EXPECT_FALSE(sample_record.has_samples(PERF_SAMPLE_IP));
  EXPECT_FALSE(sample_record.has_samples(PERF_SAMPLE_TID));
  EXPECT_FALSE(sample_record.has_samples(PERF_SAMPLE_TIME));
  EXPECT_FALSE(sample_record.has_samples(PERF_SAMPLE_ADDR));
  EXPECT_FALSE(sample_record.has_samples(PERF_SAMPLE_ID));
  EXPECT_FALSE(sample_record.has_samples(PERF_SAMPLE_CPU));
  EXPECT_FALSE(sample_record.has_samples(PERF_SAMPLE_READ));
}

TEST(PerfEventRecords, FullSampleType) {
  constexpr size_t kBufferSize = 128;
  std::vector<char> ring_buffer(kBufferSize, 0);
  constexpr uint64_t kSampleId = 1;
  constexpr uint64_t kIp = 2;
  constexpr uint32_t kPid = 3;
  constexpr uint32_t kTid = 4;
  constexpr uint64_t kTime = 5;
  constexpr uint64_t kAddr = 6;
  constexpr uint64_t kId = 7;
  constexpr uint32_t kCpu = 8;
  constexpr uint32_t kRes = 0;
  constexpr uint64_t kValue = 9;
  const std::string sample_record_body =
      AsString(kSampleId) + AsString(kIp) + AsString(kPid) + AsString(kTid) +
      AsString(kTime) + AsString(kAddr) + AsString(kId) + AsString(kCpu) +
      AsString(kRes) + AsString(kValue);
  constexpr uint16_t kMisc = PERF_RECORD_MISC_USER;
  perf_event_header header{.type = PERF_RECORD_SAMPLE,
                           .misc = kMisc,
                           .size = CastToU16OrDie(sizeof(perf_event_header) +
                                                  sample_record_body.size())};
  const std::string sample_record_bytes = AsString(header) + sample_record_body;
  CHECK_LE(sample_record_bytes.size(), ring_buffer.size());
  memcpy(ring_buffer.data(), sample_record_bytes.data(),
         sample_record_bytes.size());
  RingBufferView view(sample_record_bytes.size(), 0, ring_buffer.data(),
                      ring_buffer.size());

  PerfEventSampleRecord sample_record;
  constexpr uint64_t kSampleType = PERF_SAMPLE_IDENTIFIER | PERF_SAMPLE_IP |
                                   PERF_SAMPLE_TID | PERF_SAMPLE_TIME |
                                   PERF_SAMPLE_ADDR | PERF_SAMPLE_ID |
                                   PERF_SAMPLE_CPU | PERF_SAMPLE_READ;
  static_assert(kSampleType == PerfEventSampleRecord::kSupportedSamples);
  constexpr uint64_t kReadFormat = 0;  // just a single 64-bit value.
  EXPECT_OK(sample_record.Parse(kSampleType, kReadFormat, view));
  EXPECT_EQ(sample_record.sample_type(), kSampleType);
  EXPECT_EQ(sample_record.misc(), kMisc);
  EXPECT_TRUE(sample_record.has_samples(PERF_SAMPLE_IDENTIFIER) &&
              sample_record.sample_id() == kSampleId);
  EXPECT_TRUE(sample_record.has_samples(PERF_SAMPLE_IP) &&
              sample_record.ip() == kIp);
  EXPECT_TRUE(sample_record.has_samples(PERF_SAMPLE_TID) &&
              sample_record.pid() == kPid);
  EXPECT_TRUE(sample_record.has_samples(PERF_SAMPLE_TID) &&
              sample_record.tid() == kTid);
  EXPECT_TRUE(sample_record.has_samples(PERF_SAMPLE_TIME) &&
              sample_record.time() == kTime);
  EXPECT_TRUE(sample_record.has_samples(PERF_SAMPLE_ADDR) &&
              sample_record.addr() == kAddr);
  EXPECT_TRUE(sample_record.has_samples(PERF_SAMPLE_ID) &&
              sample_record.id() == kId);
  EXPECT_TRUE(sample_record.has_samples(PERF_SAMPLE_CPU) &&
              sample_record.cpu() == kCpu);
  EXPECT_TRUE(sample_record.has_samples(PERF_SAMPLE_READ) &&
              sample_record.v().nr() == 1 &&
              sample_record.v().value(0) == kValue);
}

}  // namespace
}  // namespace silifuzz
