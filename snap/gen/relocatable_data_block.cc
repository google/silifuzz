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

#include "./snap/gen/relocatable_data_block.h"

#include <algorithm>
#include <cstddef>

#include "./util/checks.h"

namespace silifuzz {

RelocatableDataBlock::Ref RelocatableDataBlock::Allocate(size_t size,
                                                         size_t alignment) {
  CHECK_EQ((alignment & (alignment - 1)), 0);  // a power of 2.

  // Widen this block's alignment as necessary. This keeps the current
  // and all allocations contained in the block properly aligned when the block
  // itself is aligned to this.
  required_alignment_ = std::max(required_alignment_, alignment);

  // Align the allocated offset using requested alignment.
  const size_t alignment_mask = alignment - 1;
  const size_t aligned_offset = ((size_ + alignment_mask) & ~alignment_mask);

  // If contents buffer is set, check that buffer can hold this allocation.
  if (contents_ != nullptr) {
    CHECK_LE(aligned_offset + size, max_contents_size_);
  }

  size_ = aligned_offset + size;
  return {this, aligned_offset};
}

}  // namespace silifuzz
