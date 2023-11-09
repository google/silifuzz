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

#include "./proxies/pmu_event_proxy/perf_event_buffer.h"

#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "./proxies/pmu_event_proxy/perf_event_records.h"
#include "./proxies/pmu_event_proxy/ring_buffer_view.h"
#include "./util/checks.h"

namespace silifuzz {

PerfEventBuffer::~PerfEventBuffer() {
  if (mmap_page_ != nullptr) {
    // We reach here if a client deletes this directly instead of calling
    // Destroy(). The API allows doing that but it is discouraged since any
    // error cannot be returned.
    absl::Status status = Unmap();
    if (!status.ok()) {
      LOG(ERROR) << "~PerfEventBuffer() failed: " << status;
    }
  }
}

// static
absl::StatusOr<std::unique_ptr<PerfEventBuffer>> PerfEventBuffer::Create(
    int fd, size_t buffer_byte_size, uint64_t sample_type,
    uint64_t read_format) {
  static size_t page_size = getpagesize();
  CHECK_EQ(page_size & (page_size - 1), 0)
      << "Page size " << page_size << " is not a power of 2";

  // Round buffer size to the closest power of 2 number of pages.
  // We want buffer size to be a power of 2 so that modulo of size can be
  // computed quickly using a bit mask instead of division. This is required
  // by the kernel. See info about perf_event_mmap_page in man page of
  // perf_event_open() for details.
  size_t rounded_up_buffer_size = page_size;  // at least 1 page.
  while (rounded_up_buffer_size < buffer_byte_size) {
    size_t next_rounded_up_buffer_size;
    if (__builtin_mul_overflow(rounded_up_buffer_size, 2,
                               &next_rounded_up_buffer_size)) {
      return absl::InvalidArgumentError("bytes_size too large");
    }
    rounded_up_buffer_size = next_rounded_up_buffer_size;
  }

  // mmap an extra page for the perf_event_mmap_page structure.
  const size_t mmap_size = rounded_up_buffer_size + page_size;
  void* mmap_result =
      mmap(nullptr, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  if (mmap_result == MAP_FAILED) {
    return absl::ErrnoToStatus(errno,
                               "Failed to create perf event mmap buffer");
  }

  return std::unique_ptr<PerfEventBuffer>{new PerfEventBuffer(
      reinterpret_cast<struct perf_event_mmap_page*>(mmap_result), mmap_size,
      sample_type, read_format)};
}

// static
absl::Status PerfEventBuffer::Destroy(
    std::unique_ptr<PerfEventBuffer> event_buffer) {
  return event_buffer->Unmap();
}

// GetCurrentView() and CommitReads() below access data_head and data_tail of
// a perf_event_mmap_page structure. We need to use proper memory barriers to
// synchronize accesses to these pointers and data in the buffer with the
// kernel. For details see:
//
// https://github.com/torvalds/linux/blob/master/tools/include/linux/ring_buffer.h
//
// User mode code accessing data in a the ring buffer need to do the following.
// head = mmap_page_->data_head;
// read_barrier();
//   .. consume data in [data_tail, new_tail) where new_tail <= head ..
// memory_barrier();
// mmap_page_->data_tail = new_tail;
//
RingBufferView PerfEventBuffer::GetCurrentView() const {
  const size_t current_head = mmap_page_->data_head;

  // We need a read barrier after reading data_head. Any loads in the region
  // [data_tail, current_head) must be ordered after the data_head read above.
  std::atomic_thread_fence(std::memory_order_acquire);

  return RingBufferView(
      current_head, mmap_page_->data_tail,
      reinterpret_cast<char*>(mmap_page_) + mmap_page_->data_offset,
      mmap_page_->data_size);
}

void PerfEventBuffer::CommitReads(const RingBufferView& view) {
  // Sanity check: We should not commit past data_head.
  // The read of data_head is not followed by a read barrier as we are not
  // loading data from the ring buffer here.
  CHECK_LE(mmap_page_->data_head - view.tail(), mmap_page_->data_size);

  // Updating data_tail needs to be preceded by a full memory barrier. The
  // update must be ordered after all previous loads via the view.
  std::atomic_thread_fence(std::memory_order_seq_cst);

  mmap_page_->data_tail = view.tail();
}

absl::Status PerfEventBuffer::Unmap() {
  CHECK_NE(mmap_page_, nullptr);
  if (munmap(mmap_page_, mmap_size_) < 0) {
    return absl::ErrnoToStatus(errno, "Failed to munmap perf event buffer");
  }
  mmap_page_ = nullptr;

  return absl::OkStatus();
}

absl::Status PerfEventBuffer::PeekNextPerfEventHeader(
    RingBufferView& view, perf_event_header& header) const {
  if (view.size() < sizeof(perf_event_header)) {
    return absl::OutOfRangeError("Cannot read perf event header");
  }
  view.Peek<perf_event_header>(header);

  // Valid event types are in range (0, PREF_RECORD_MAX)
  if (header.type <= 0 && header.type >= PERF_RECORD_MAX) {
    return absl::FailedPreconditionError(
        absl::StrCat("Invalid event type ", header.type));
  }
  return absl::OkStatus();
}

absl::StatusOr<perf_event_type> PerfEventBuffer::NextEventType() const {
  // Try to read a perf event header.
  RingBufferView view = GetCurrentView();
  perf_event_header header;
  RETURN_IF_NOT_OK(PeekNextPerfEventHeader(view, header));
  return static_cast<perf_event_type>(header.type);
}

absl::StatusOr<PerfEventSampleRecord> PerfEventBuffer::ReadSampleRecord() {
  PerfEventSampleRecord sample_record;
  RingBufferView view = GetCurrentView();
  RETURN_IF_NOT_OK(sample_record.Parse(sample_, read_format_, view));
  CommitReads(view);
  return sample_record;
}

}  // namespace silifuzz
