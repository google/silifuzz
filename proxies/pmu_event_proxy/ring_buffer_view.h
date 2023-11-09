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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_RING_BUFFER_VIEW_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_RING_BUFFER_VIEW_H_

#include <cstddef>
#include <cstring>
#include <type_traits>

#include "absl/base/optimization.h"
#include "absl/log/check.h"

namespace silifuzz {
// This is a helper class for reading data from a ring buffer. A ring buffer
// is a FIFO with a pair of offsets 'head' and 'tail', which mark data held by
// the buffer in the region [tail, head). These offsets advance as data enter
// and leave the buffer. The offsets are virtual and can be converted into
// actual offsets by computing modulus of the offsets with the buffer size.
//
// A ring buffer view object represents a sub-region within [tail, head) of
// the right buffer. Once constructed, a view cannot get more data, i.e. the
// head of a view is fixed. It only shrinks in size as the view's tail advances
// while data are consumed.
//
// There are two reasons why this class is needed. First, it handles address
// wrapping at the end of the underlying buffer so that the buffer appears to
// circular. Second, it accesses data using its own copy of head and tail
// instead of using the ring buffer's. This improves efficiency if the ring
// buffer's head or tail requires memory synchronization.
//
// For example (see man page of perf_event_open() for details):
//
// perf_event_mmap_page* ring_buffer;
//
// head = ring_buffer->head;
// read_barrier();
// RingBufferView view(head, ring_buffer->tail, ...)
//
// .. accessing data in [tail, head)..
//
// ring_buffer->tail = view.tail();
//
// ring_buffer->head is updated by the kernel and read in user space. The man
// page of perf_event_open() says that user space must use a read barrier after
// reading head. If we used ring_buffer->head directly for bound check, we would
// need to use read barriers very frequently when parsing many small scalar
// fields of perf events in the ring buffer. Copying the whole record before
// parsing would eliminate the read barriers but would incur cost of copying.
// Using a view can avoid both memory barriers and copying.
//
// This class is itself thread-compatible. It does not guarantee thread-safety
// of the ring buffer contents covered in a view.

class RingBufferView {
 public:
  // Construct a ring buffer view object covering virtual offsets [tail,
  // head) of a ring buffer implemented by 'buffer' of 'buffer_size'.
  // [tail, head) must be within the valid data region of the ring buffer,
  // marked by the ring buffer's own head and tail.
  // For efficiency, buffer_size must be a power of 2.
  //
  // Operations of view are undefined if the tail of the ring buffer moves
  // past that of the view. The ring buffer's tail should advance only after
  // all previous view constructed with the tail value are destructed.
  RingBufferView(size_t head, size_t tail, const char* buffer,
                 size_t buffer_size)
      : head_(head), tail_(tail), buffer_(buffer), buffer_size_(buffer_size) {
    CHECK_GT(buffer_size, 0);
    CHECK_EQ(buffer_size & (buffer_size - 1), 0)
        << "buffer_size must be a power of 2";
    CHECK_LE(head - tail, buffer_size);
  }

  ~RingBufferView() = default;

  // Copyable and moveable.
  RingBufferView(const RingBufferView&) = default;
  RingBufferView& operator=(const RingBufferView&) = default;
  RingBufferView(RingBufferView&&) = default;
  RingBufferView& operator=(RingBufferView&&) = default;

  // Byte size of available data in the view.
  size_t size() const { return head_ - tail_; }

  // Head of view.
  size_t head() const { return head_; }

  // Tail of view.
  size_t tail() const { return tail_; }

  // Copy an object of type T from tail of view to 'obj' T must be trivially
  // copy-constructible. There must be enough data in the view.
  template <typename T>
  void Peek(T& obj) const {
    // This only works for trivially copyable types, which can be copied or
    // moved using memcpy() or memmove().
    static_assert(std::is_trivially_copyable<T>::value);
    CHECK_GE(size(), sizeof(T));
    const size_t buffer_size_mask = buffer_size_ - 1;
    const size_t offset = tail_ & buffer_size_mask;
    if (ABSL_PREDICT_TRUE(buffer_size_ >= offset + sizeof(T))) {
      // Object does not wrap around the ring buffer. memcpy() of small fixed
      // sizes are often optimized into series of scalar loads.
      memcpy(&obj, buffer_ + offset, sizeof(T));
    } else {
      // Object wraps around end of ring buffer.
      const size_t first_part_size = buffer_size_ - offset;
      const size_t second_part_size = sizeof(T) - first_part_size;
      memcpy(&obj, &buffer_[offset], first_part_size);
      memcpy(reinterpret_cast<char*>(&obj) + first_part_size, &buffer_[0],
             second_part_size);
    }
  }

  // Reads an object of type T at the tail of the view and advances the tail
  // by object size. This has the same requirements as Peek().
  template <typename T>
  void Read(T& obj) {
    Peek(obj);
    tail_ += sizeof(T);
  }

  // Advances tail by 'n' bytes. There must be at least 'n' available bytes in
  // the view.
  void Skip(size_t n) {
    CHECK_GE(size(), n);
    tail_ += n;
  }

 private:
  // Virtual ring buffer offset after the last byte of data in the view. This is
  // fixed.
  const size_t head_;

  // Virtual ring buffer offset of the next available byte in the view. This
  // advances as data are consumed.
  size_t tail_;

  // Points to the beginning of the ring buffer for which this view is created.
  const char* const buffer_;

  // Size of the ring buffer. It must be a power of 2.
  const size_t buffer_size_;
};

}  // namespace silifuzz
#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_RING_BUFFER_VIEW_H_
