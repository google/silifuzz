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

#include "./proxies/page_table/memory_state_image.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "./common/mapped_memory_map.h"
#include "./common/memory_mapping.h"
#include "./common/memory_perms.h"
#include "./common/memory_state.h"
#include "./proxies/page_table/page_table_creator.h"
#include "./util/arch.h"
#include "./util/checks.h"

namespace silifuzz::proxies {

// static method.
template <typename arch>
absl::StatusOr<PageTableCreator<arch>> MemoryStateImage<arch>::LayoutPageTable(
    const MemoryState& memory_state, uint64_t physical_address,
    const std::vector<ExternalMapping>& external_mappings, bool copy_data,
    size_t data_offset, std::vector<uint8_t>& memory_image_data) {
  PageTableCreator<arch> page_table_creator(physical_address);
  absl::Status status;

  // Build the page table. Assign physical addresses for mapped memory
  // regions and optionally copy contents to memory images.
  memory_state.mapped_memory().Iterate([&](MappedMemoryMap::Address start,
                                           MappedMemoryMap::Address limit,
                                           MemoryPerms perms) {
    // Strip mapped bit or constructor below would fail.
    perms.Clear(MemoryPerms::kMapped);
    const MemoryMapping mapping =
        MemoryMapping::MakeRanged(start, limit, perms);
    status.Update(page_table_creator.AddContiguousMapping(
        mapping, physical_address + data_offset));
    if (copy_data) {
      const std::string byte_data =
          memory_state.memory_bytes(start, mapping.num_bytes());
      CHECK_LE(data_offset + byte_data.size(), memory_image_data.size());
      memcpy(&memory_image_data[data_offset], byte_data.data(),
             byte_data.size());
    }
    data_offset += mapping.num_bytes();
  });

  // Add external mappings, these have no memory contents inside the image.
  for (const ExternalMapping& external_mapping : external_mappings) {
    status.Update(page_table_creator.AddContiguousMapping(
        external_mapping.virtual_memory_mapping,
        external_mapping.physical_start));
  }

  RETURN_IF_NOT_OK(status);

  // If copying data, we should reach the end of memory_image_data.
  if (copy_data) {
    CHECK_EQ(data_offset, memory_image_data.size());
  }
  return page_table_creator;
}

// static method.
template <typename arch>
absl::StatusOr<MemoryStateImage<arch>> MemoryStateImage<arch>::Build(
    const MemoryState& memory_state, uint64_t physical_address,
    const std::vector<ExternalMapping>& external_mappings) {
  // We need to fit both the page data and contents of the virtual address
  // space in one contiguous block. We use the page table creator to create
  // a page table as a single block of memory and put the virtual address
  // space contents after that.  The problem here is that we do not know the
  // size of the page table until we have built it. So we cannot determine the
  // physical address of the virtual address space contents while building
  // the page table. To work around this problem, we build the page table twice.
  // The first time, we just build the page table to find out its size and thus
  // the starting physical address of the virtual address contents. After we
  // have the size, we then build page table again now that we can layout the
  // virtual address space contents.
  //
  // There are alternatives to building the table twice.  We could add API in
  // page table creator to adjust physical addresses after a table is created
  // or we can put the virtual pages before page table. In that case page table
  // root is no longer the beginning of block.  We may need to add a header to
  // the block so that the client can find out physical address of the root.
  std::vector<uint8_t> memory_image_data;
  ASSIGN_OR_RETURN_IF_NOT_OK(
      PageTableCreator<arch> page_table_size_measure,
      LayoutPageTable(memory_state, physical_address, external_mappings,
                      /*copy_data=*/false,
                      /*data_offset=*/0, memory_image_data));

  const uint64_t page_table_byte_size =
      page_table_size_measure.GetBinaryData().size() * sizeof(uint64_t);
  const size_t memory_image_size =
      page_table_byte_size + memory_state.num_written_bytes();
  memory_image_data.resize(memory_image_size);

  // Build the page table again. Assign physical addresses for mapped memory
  // regions and copy contents to memory images.
  ASSIGN_OR_RETURN_IF_NOT_OK(
      PageTableCreator<arch> page_table_creator,
      LayoutPageTable(memory_state, physical_address, external_mappings,
                      /*copy_data=*/true,
                      /*data_offset=*/page_table_byte_size, memory_image_data));

  CHECK_EQ(page_table_size_measure.GetBinaryData().size(),
           page_table_creator.GetBinaryData().size());
  memcpy(memory_image_data.data(), page_table_creator.GetBinaryData().data(),
         page_table_byte_size);

  return MemoryStateImage<arch>(physical_address, memory_image_data,
                                physical_address);
}

template class MemoryStateImage<AArch64>;

template class MemoryStateImage<X86_64>;

}  // namespace silifuzz::proxies
