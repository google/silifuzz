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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_SNAP_RELOCATOR_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_SNAP_RELOCATOR_H_

#include <cstdint>

#include "./snap/snap.h"
#include "./util/mmapped_memory_ptr.h"

namespace silifuzz {

// SnapRelocator relocates a relocatable Snap corpus loaded at an address
// different from the nominal load address of 0. Relocation involves adding
// the start address of the Snap corpus to every pointer inside the corpus.
class SnapRelocator {
 public:
  // Relocates a relocatable Snap corpus pointed by `relocatable` and then
  // mprotect the memory to be read-only. Dies if there is any error.
  //
  // RETURNS: A mmapped memory pointer to the relocated corpus.
  static MmappedMemoryPtr<const Snap::Corpus> RelocateCorpus(
      MmappedMemoryPtr<char> relocatable);

 private:
  // Constructs a SnapRelocator object for a relocatable Snap corpus in
  // memory region [start_address, limit_address).
  // Constructor is private as relocation is done using a static function.
  SnapRelocator(uintptr_t start_address, uintptr_t limit_address)
      : start_address_(start_address), limit_address_(limit_address) {}

  // Not copyable or moveable. Once a corpus is relocated. It cannot be
  // relocated again. It is generally not meaningful to copy a relocator.
  SnapRelocator(const SnapRelocator&) = delete;
  SnapRelocator(SnapRelocator&&) = delete;
  SnapRelocator& operator=(const SnapRelocator&) = delete;
  SnapRelocator& operator=(SnapRelocator&&) = delete;

  // Adjusts a relocatable pointer in place. This adds the start address
  // of the relocatable corpus to a pointer, which is a relative
  // offset from the start address to the address of the pointed object.
  // This also checks that the relocated pointer is still within the
  // relocatable corpus and is properly aligned for type T.
  template <typename T>
  void AdjustPointer(T*&);

  // Similar to AdjustPointer() but for Snap::Array<T>.
  // Adjusts array.elements if array.size>0 otherwise sets array.elements to
  // nullptr.
  template <typename T>
  void AdjustArray(Snap::Array<T>& array);

  // Relocates a Snap::Array<MemoryBytes>.
  void RelocateMemoryBytesArray(
      Snap::Array<Snap::MemoryBytes>& memory_bytes_array);

  // Relocates corpus by adjusting all pointers inside the corpus.
  // REQUIRES: Only called once.
  void RelocateCorpus();

  // Address of the beginning of the corpus.
  uintptr_t start_address_;

  // Address after the last byte of the corpus.
  uintptr_t limit_address_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_SNAP_RELOCATOR_H_
