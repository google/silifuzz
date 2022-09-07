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

#include "./snap/snap_relocator.h"

#include <sys/mman.h>

#include <cstddef>
#include <cstdint>

#include "./snap/snap.h"
#include "./util/checks.h"

namespace silifuzz {

template <typename T>
void SnapRelocator::AdjustPointer(T*& ptr) {
  // A pointer in a relocatable Snap corpus offset is just offset from the
  // start of the corpus. The actual run time address of the pointed object
  // is recovered by simply adding the start address of the corpus.
  uintptr_t adjusted_address =
      reinterpret_cast<uintptr_t>(ptr) + start_address_;

  // Adjusted pointer must be within corpus bounds.
  CHECK_LE(start_address_, adjusted_address);
  CHECK_LT(adjusted_address, limit_address_);

  // Adjusted pointer must be correctly aligned.
  CHECK_EQ(adjusted_address % alignof(T), 0);

  ptr = reinterpret_cast<T*>(adjusted_address);
}

void SnapRelocator::RelocateMemoryBytesArray(
    Snap::Array<Snap::MemoryBytes>& memory_bytes_array) {
  AdjustPointer(memory_bytes_array.elements);
  for (size_t i = 0; i < memory_bytes_array.size; ++i) {
    Snap::MemoryBytes& memory_byte = memory_bytes_array.mutable_elements()[i];
    if (!memory_byte.repeating) {
      AdjustPointer(memory_byte.data.byte_values.elements);
    }
  }
}

void SnapRelocator::RelocateCorpus() {
  // Snap corpus has type Snap::Array<const Snap*>. Here we pretend that
  // it has type Snap::Array<Snap*> for convenience.
  using CorpusType = Snap::Array<Snap*>;
  CHECK_EQ(start_address_ % alignof(CorpusType), 0);
  CorpusType& corpus = *reinterpret_cast<CorpusType*>(start_address_);

  AdjustPointer(corpus.elements);
  for (size_t i = 0; i < corpus.size; ++i) {
    AdjustPointer(corpus.mutable_elements()[i]);

    // Adjust pointers in this Snap.
    Snap& snap = *(corpus.mutable_elements()[i]);
    AdjustPointer(snap.id);
    AdjustPointer(snap.memory_mappings.elements);

    // Adjust memory bytes arrays.
    RelocateMemoryBytesArray(snap.memory_bytes);
    RelocateMemoryBytesArray(snap.end_state_memory_bytes);
  }
}

// static
MmappedMemoryPtr<const Snap::Array<const Snap*>> SnapRelocator::RelocateCorpus(
    MmappedMemoryPtr<char> relocatable) {
  const size_t byte_size = MmappedMemorySize(relocatable);
  uintptr_t start_address = reinterpret_cast<uintptr_t>(relocatable.get());
  uintptr_t limit_address = start_address + byte_size;
  SnapRelocator relocator(start_address, limit_address);
  relocator.RelocateCorpus();

  // mprotect corpus after relocation.
  CHECK_EQ(mprotect(reinterpret_cast<void*>(relocatable.get()), byte_size,
                    PROT_READ),
           0);

  auto corpus =
      reinterpret_cast<const Snap::Array<const Snap*>*>(relocatable.release());

  return MakeMmappedMemoryPtr(corpus, byte_size);
}

}  // namespace silifuzz
