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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_MMAPPED_MEMORY_PTR_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_MMAPPED_MEMORY_PTR_H_

#include <sys/mman.h>
#include <unistd.h>

#include <cstddef>
#include <memory>

#include "./util/checks.h"
#include "./util/page_util.h"

namespace silifuzz {

// Helper class to release a memory block previously obtained from mmap().
// This is intended to be used as a unique_ptr deleter.
template <typename T>
struct Munmapper {
  // munmap() the memory block at `ptr` using the unmapper's size.
  void operator()(T* ptr) const {
    // munmap takes a void* pointer. Cast to fix both type and constness
    // of pointer to an arbitratry type T.
    auto as_const_void_ptr = reinterpret_cast<const void*>(ptr);
    CHECK_EQ(munmap(const_cast<void*>(as_const_void_ptr), size), 0);
  }

  size_t size;  // size of the block.
};

// std::unique_ptr variant with custom deleter for mmapped memory.
template <typename T>
using MmappedMemoryPtr = std::unique_ptr<T, Munmapper<T>>;

// Wraps a mmap(2)-ed memory region that will be automatically released
// according to the std::unique_ptr semantics. `size` is the size of the
// memory region.
template <typename T>
static inline MmappedMemoryPtr<T> MakeMmappedMemoryPtr(T* ptr, size_t size) {
  return {ptr, Munmapper<T>{.size = size}};
}

// Allocates a writable buffer of `byte_size` bytes using mmap() and
// returns an MmappedMemoryPtr<T> pointer for the buffer.
template <typename T>
static inline MmappedMemoryPtr<T> AllocateMmappedBuffer(size_t byte_size) {
  const size_t page_aligned_size = RoundUpToPageAlignment(byte_size);
  void* ptr = mmap(nullptr, page_aligned_size, PROT_READ | PROT_WRITE,
                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  CHECK_NE(ptr, MAP_FAILED);

  // The reported size is the original byte size, not the allocation size.
  return MakeMmappedMemoryPtr<T>(reinterpret_cast<T*>(ptr), byte_size);
}

// Returns size of the mmapped() memory block owned by `ptr`.
template <typename T>
static inline size_t MmappedMemorySize(const MmappedMemoryPtr<T>& ptr) {
  return ptr.get_deleter().size;
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_MMAPPED_MEMORY_PTR_H_
