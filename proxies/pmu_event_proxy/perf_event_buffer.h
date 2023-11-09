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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_PERF_EVENT_BUFFER_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_PERF_EVENT_BUFFER_H_

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "./proxies/pmu_event_proxy/perf_event_records.h"
#include "./proxies/pmu_event_proxy/ring_buffer_view.h"

namespace silifuzz {

// This class manages memory allocated for perf events buffer associated with
// a perf event file descriptor. It also provides methods of reading events
// in the buffer.
//
// This class is thread-compatible.
class PerfEventBuffer {
 public:
  // Destruct this object and release resources used by this. The destructor is
  // public but clients should use Destroy() to dispose of PerfEventBuffers
  // since the destructor does not report errors.
  ~PerfEventBuffer();

  // Not copyable but movable.
  PerfEventBuffer(const PerfEventBuffer&) = delete;
  PerfEventBuffer& operator=(const PerfEventBuffer&) = delete;
  PerfEventBuffer(PerfEventBuffer&&) = default;
  PerfEventBuffer& operator=(PerfEventBuffer&&) = default;

  // Creates a PerfEventBuffer from a file descriptor 'fd' obtained from
  // perf_event_open(). The buffer has a capacity of 'byte_size' rounded up
  // to the next closest power of 2 number of pages. 'sample_type' and
  // 'read_format' must match for corresponding values in perf_event_attr used
  // to open the descriptor. Returns a unique pointer to buffer or a status if
  // an error happened.
  static absl::StatusOr<std::unique_ptr<PerfEventBuffer>> Create(
      int fd, size_t buffer_byte_size, uint64_t sample_type,
      uint64_t read_format);

  // Destroys 'perf_event_buffer' and releases resources used by it.
  // Returns a status indicating if an error happened.
  static absl::Status Destroy(
      std::unique_ptr<PerfEventBuffer> perf_event_buffer);

  // Returns type of the next event in the buffer or a status. If there
  // is not enough or no data in the buffer, return an out-of-range
  // error. This may return other errors in addition.
  absl::StatusOr<perf_event_type> NextEventType() const;

  // Method(s) for reading individual perf events in buffer.
  // Caller must first use NextEventType() to determine the
  // which method to use.
  //
  // ASSIGN_OR_RETURN_IF_NOT_OK(perf_event_type event_type,
  //                            event_buffer->NextEventType());
  // switch (event_type) {
  // case PERF_RECORD_SAMPLE:
  //    ASSIGN_OR_RETURN_IF_NOT_OK(sample,
  //                               event_buffer->ReadSampleRecord());
  //    ....
  // default:
  //    return absl::UnimplementedError("unhandled");
  // }

  // Currently Only PERF_RECORD_SAMPLE is handled. We will add other
  // pert event types as needed.

  // Reads a perf sample record or a status.
  absl::StatusOr<PerfEventSampleRecord> ReadSampleRecord();

 private:
  // Constructor is private. Clients must use factory method Create() instead.
  PerfEventBuffer(perf_event_mmap_page* mmap_page, size_t mmap_size,
                  uint64_t sample, uint64_t read_format)
      : mmap_page_(mmap_page),
        mmap_size_(mmap_size),
        sample_(sample),
        read_format_(read_format) {}

  // Gets a view of the current ring buffer contents. It also ensures
  // subsequent reads via the returned view are ordered after the creation
  // of the view as seen by all CPUs. See comments in perf_event_buffer.cc
  // for more details about memory ordering in GetCurrentView() and
  // CommitReads().
  RingBufferView GetCurrentView() const;

  // Commits reads from 'view' to the ring buffer. This advances data_tail of
  // mmap_page_ to tail of the 'view'. It also ensures all previous reads via
  // 'view' are ordered before the update of data_tail as seen by all CPUs.
  void CommitReads(const RingBufferView& view);

  // Read without advancing view tail, the next perf event header in 'view' into
  // 'header' or returns an error status.
  absl::Status PeekNextPerfEventHeader(RingBufferView& view,
                                       perf_event_header& header) const;

  // Unmap memory pointed by mmap_page_ and sets it to nullptr. Returns an error
  // status.
  absl::Status Unmap();

  // Points to the perf_event_mmap_page_ structure.
  perf_event_mmap_page* mmap_page_;

  // Size of mmap region containing the perf_event_mmap_page structure and
  // the ring buffer that follows it.
  size_t mmap_size_;

  // samples and read format passed to constructor.
  uint64_t sample_;
  uint64_t read_format_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_PERF_EVENT_BUFFER_H_
