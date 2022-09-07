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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_GEN_RELOCATABLE_DATA_BLOCK_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_GEN_RELOCATABLE_DATA_BLOCK_H_

#include <cstddef>
#include <cstdint>
#include <limits>

#include "./util/checks.h"
#include "./util/misc_util.h"  // AsPtr

namespace silifuzz {

// RelocatableDataBlock describles a contiguous block of memory that
// is loaded into a runner's address space. This is used for generating a
// relocatable Snap corpus. Conceptually, a relocatable Snap corpus is
// divided into several parts, which are represented by relocatable data
// block. These blocks grow in size during corpus building process.
// This class provides facilities for tracking size and alignment of a
// relocatable data block. In addition, it also support translation between
// load address of data and the address of their working copies inside the
// relocatable Snap corpus generator.
//
// This class is used in relocatable Snap generation. It has two modes. When
// Snaps are being laid out, a relocatable data block does not have load
// address or content buffer assigned. The layout process computes the size
// of a relocated data block. After layout, the relocated data block is assigned
// a load address and a content buffer used by the generator.

// This class is thread-compatible.
class RelocatableDataBlock {
 public:
  using Address = uintptr_t;

  // A reference represents a logical location within a relocatable data block.
  // Operations on a Ref are only valid during the life time of the referenced
  // relocatable data block.
  class Ref {
   public:
    // Construct a Ref that points to the location `byte_offset` from the
    // beginning of `relocatable_data_block`
    Ref(RelocatableDataBlock* relocatable_data_block, size_t byte_offset)
        : relocatable_data_block_(relocatable_data_block),
          byte_offset_(byte_offset) {}

    // Constructor with no argument creates a null Ref value.
    constexpr Ref() : relocatable_data_block_(nullptr), byte_offset_(0) {}

    // Ref is copyable and moveable.
    Ref(const Ref&) = default;
    Ref& operator=(const Ref&) = default;
    Ref(Ref&&) = default;
    Ref& operator=(Ref&&) = default;

    // Referenced relocatable data block.
    RelocatableDataBlock* relocatable_data_block() const {
      return relocatable_data_block_;
    }

    // Byte offset from beginning of the relocatable data block.
    size_t byte_offset() const { return byte_offset_; }

    // Returns the load address of this reference. The actual run time
    // address is this value plus a whole corpus adjustment.
    Address load_address() const {
      CHECK_NE(relocatable_data_block_->load_address(), kInvalidAddress);
      CHECK_LE(byte_offset_, relocatable_data_block_->size());
      return relocatable_data_block_->load_address() + byte_offset_;
    }

    // Returns a char* pointer inside the content buffer for this reference.
    // This is used by a corpus generator to access contents
    // of the relocatable data block during corpus generation.
    char* contents() const {
      CHECK_NE(relocatable_data_block_->contents(), nullptr);
      CHECK_LE(byte_offset_, relocatable_data_block_->max_contents_size_);
      return relocatable_data_block_->contents() + byte_offset_;
    }

    // Returns a content pointer to T.
    template <typename T>
    T* contents_as_pointer_of() const {
      CHECK_EQ(reinterpret_cast<uintptr_t>(contents()) % alignof(T), 0);
      return reinterpret_cast<T*>(contents());
    }

    // Returns load address as a pointer to T.
    template <typename T>
    T* load_address_as_pointer_of() const {
      return reinterpret_cast<T*>(AsPtr(load_address()));
    }

    // Returns a new reference to the same data block but add `rhs` to
    // byte offset.
    Ref operator+(uint64_t rhs) const {
      // Checks that offset does not wrap around.
      const uint64_t max_addend =
          std::numeric_limits<size_t>::max() - byte_offset_;
      CHECK_LE(rhs, max_addend);
      return {relocatable_data_block_, byte_offset_ + rhs};
    }

    Ref& operator+=(uint64_t rhs) {
      *this = *this + rhs;
      return *this;
    }

   private:
    RelocatableDataBlock* relocatable_data_block_;
    size_t byte_offset_;
  };

  // Initial value of load address.
  static constexpr Address kInvalidAddress =
      std::numeric_limits<Address>::max();

  RelocatableDataBlock() = default;
  ~RelocatableDataBlock() = default;

  // Copyable but not moveable as existing Refs would be invalidated.
  RelocatableDataBlock(const RelocatableDataBlock&) = default;
  RelocatableDataBlock& operator=(const RelocatableDataBlock&) = default;
  RelocatableDataBlock(RelocatableDataBlock&&) = delete;
  RelocatableDataBlock& operator=(RelocatableDataBlock&&) = delete;

  // Returns current size of this.
  size_t size() const { return size_; }

  // Returns current alignment requirement of this.
  size_t required_alignment() const { return required_alignment_; }

  // Reset size and required alignment of this. Data block is considered empty
  // after calling this function.
  void ResetSizeAndAlignment() {
    size_ = 0;
    required_alignment_ = 1;
  }

  // If a content buffer has been set up using set_contents(), returns
  // a pointer to the buffer.  Otherwise returns nullptr.
  char* contents() const { return contents_; }

  // Set address and maximum size of contents buffer.
  // The data block does not own the buffer.
  void set_contents(char* address, size_t max_size) {
    contents_ = address;
    max_contents_size_ = max_size;
  }

  // Returns load address of this data block
  Address load_address() const { return load_address_; }

  // Sets load address of this data block.
  void set_load_address(Address address) { load_address_ = address; }

  // Allocate a block of memory in this data block of the given size and
  // alignment.  Returns a Ref to the allocated block.
  // REQUIRES: `alignment` is a power of 2. If contents buffer is set, there is
  // enough space in buffer for this allocation.
  Ref Allocate(size_t size, size_t alignment);

  // Like above for embedding `block` into this data block
  // using the current size and alignment of `block`. If `block` changes its
  // size or alignment after allocation, the allocation may no longer fit.
  Ref Allocate(const RelocatableDataBlock& block) {
    return Allocate(block.size(), block.required_alignment());
  }

  // Like Allocate but for `n` objects of the type `T`
  template <typename T>
  Ref AllocateObjectsOfType(size_t n) {
    return Allocate(sizeof(T) * n, alignof(T));
  }

 private:
  // Byte size of the data block.
  size_t size_ = 0;

  // Alignment requirement of this data block.  This is the least alignment
  // wider than or equal to all allocations contained within the
  // data block. See also reset_size_and_alignment() above.
  size_t required_alignment_ = 1;

  // Load address of this data blocks.
  Address load_address_ = kInvalidAddress;

  // Points to contents of the data block.
  // This does not take ownership of the pointed memory.
  char* contents_ = nullptr;

  // Maximum size of the content buffer.
  size_t max_contents_size_ = 0;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_GEN_RELOCATABLE_DATA_BLOCK_H_
