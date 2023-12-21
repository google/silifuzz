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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_SNAPSHOT_STATE_IMAGE_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_SNAPSHOT_STATE_IMAGE_H_

#include <cstddef>
#include <cstdint>
#include <vector>

#include "absl/status/statusor.h"
#include "./common/memory_mapping.h"
#include "./common/memory_state.h"
#include "./proxies/page_table/page_table_creator.h"

namespace silifuzz::proxies {

// MemoryStateImage takes a MemoryState object representing a virtual address
// space and converts it into a contiguous block of physical memory containing
// both the memory bytes in the virtual address space and an
// architecture-dependent page table that describes the virtual address space.
//
// This class is thread-compatible.
template <typename arch>
class MemoryStateImage {
 public:
  ~MemoryStateImage() = default;

  // Describes a virtual to physical mapping. If size of 'virtual' is
  // larger than a translation granule, 'physical' is assumed of be a contiguous
  // region of the same size.
  struct ExternalMapping {
    MemoryMapping
        virtual_memory_mapping;  // virtual memory region and permission.
    uint64_t physical_start;     // starting physical address.
  };

  // Copyable and moveable
  MemoryStateImage(const MemoryStateImage&) = default;
  MemoryStateImage& operator=(const MemoryStateImage&) = default;
  MemoryStateImage(MemoryStateImage&&) = default;
  MemoryStateImage& operator=(MemoryStateImage&&) = default;

  // Returns the physical load address of the image.
  uint64_t physical_address() const { return physical_address_; }

  // Returns a const reference to image data.
  const std::vector<uint8_t>& image_data() const { return image_data_; }

  // Returns physical address of the page table root of the address space.
  uint64_t page_table_root() const { return page_table_root_; }

  // Factory method to create a new memory state image from 'memory_state'.
  // The new image is to be loaded at 'physical_address' at run-time. Additional
  // memory mappings are passed in 'external_mapping'. These virtual to physical
  // translations will be included in the image but no physical memory
  // is allocated inside the image.  Returns a memory state image object or an
  // error.
  static absl::StatusOr<MemoryStateImage> Build(
      const MemoryState& memory_state, uint64_t physical_address,
      const std::vector<ExternalMapping>& external_mappings = {});

 private:
  // Default constructor is private. Object must be created using Build() since
  // a constructor cannot report errors.
  MemoryStateImage(uint64_t physical_address,
                   const std::vector<uint8_t>& image_data,
                   uint64_t page_table_root)
      : physical_address_(physical_address),
        image_data_(image_data),
        page_table_root_(page_table_root) {}
  MemoryStateImage() = default;

  // Helper for Build() to lay out a page table. If 'copy_data' is true,
  // contents of 'memory_state' is copied to 'memory_image_data', starting
  // at 'data_offset' in 'memory_image_data'.
  static absl::StatusOr<PageTableCreator<arch>> LayoutPageTable(
      const MemoryState& memory_state, uint64_t physical_address,
      const std::vector<ExternalMapping>& external_mappings, bool copy_data,
      size_t data_offset, std::vector<uint8_t>& memory_image_data);

  // Physical address to load the image. This is also the address of the page
  // table root.
  uint64_t physical_address_;

  // Image data.
  std::vector<uint8_t> image_data_;

  // Page table root.
  uint64_t page_table_root_;
};

}  // namespace silifuzz::proxies

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PAGE_TABLE_MEMORY_STATE_IMAGE_H_
