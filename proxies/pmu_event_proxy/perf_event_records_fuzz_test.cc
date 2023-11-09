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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "fuzztest/fuzztest.h"
#include "absl/log/check.h"
#include "./proxies/pmu_event_proxy/perf_event_records.h"
#include "./proxies/pmu_event_proxy/ring_buffer_view.h"

namespace silifuzz {
namespace {
using ::fuzztest::Arbitrary;

// Must be powers of 2 as these are used to size ring buffers.
constexpr size_t kMaxReadFormatSize = 64;
constexpr size_t kMaxSampleRecordSize = 128;

// Returns a ring buffer of the given size and stores bytes there at
// offset.
std::vector<char> GetRingBuffer(const std::string& bytes, size_t buffer_size,
                                uint64_t offset) {
  CHECK_GE(buffer_size, bytes.size());
  std::vector<char> ring_buffer(buffer_size, 0);
  offset %= ring_buffer.size();
  if (offset + bytes.size() <= ring_buffer.size()) {
    memcpy(ring_buffer.data() + offset, bytes.data(), bytes.size());
  } else {
    const size_t first_part_size = ring_buffer.size() - offset;
    const size_t second_part_size = bytes.size() - first_part_size;
    memcpy(ring_buffer.data() + offset, bytes.data(), first_part_size);
    memcpy(ring_buffer.data(), bytes.data() + first_part_size,
           second_part_size);
  }
  return ring_buffer;
}

void ParsePerfEventReadFormatShouldNotCrash(uint64_t format,
                                            const std::string& bytes,
                                            uint64_t offset) {
  std::vector<char> ring_buffer(
      GetRingBuffer(bytes, kMaxReadFormatSize, offset));
  RingBufferView view(offset + bytes.size(), offset, ring_buffer.data(),
                      ring_buffer.size());
  PerfEventReadFormat read_format;
  read_format.Parse(format, view).IgnoreError();
}

FUZZ_TEST(FuzzPerfEventRecords, ParsePerfEventReadFormatShouldNotCrash)
    .WithDomains(Arbitrary<uint64_t>(),
                 Arbitrary<std::string>().WithMaxSize(kMaxReadFormatSize),
                 Arbitrary<uint64_t>());

void ParsePerfEventSampleRecordShouldNotCrash(uint64_t sample_type,
                                              uint64_t read_format,
                                              const std::string& bytes,
                                              uint64_t offset) {
  std::vector<char> ring_buffer(
      GetRingBuffer(bytes, kMaxSampleRecordSize, offset));
  offset %= ring_buffer.size();
  RingBufferView view(offset + bytes.size(), offset, ring_buffer.data(),
                      ring_buffer.size());
  PerfEventSampleRecord sample_record;
  sample_record.Parse(sample_type, read_format, view).IgnoreError();
}

FUZZ_TEST(FuzzPerfEventRecords, ParsePerfEventSampleRecordShouldNotCrash)
    .WithDomains(Arbitrary<uint64_t>(), Arbitrary<uint64_t>(),
                 Arbitrary<std::string>().WithMaxSize(kMaxSampleRecordSize),
                 Arbitrary<uint64_t>());

}  // namespace
}  // namespace silifuzz
