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

// Error codes for corpus relocation operation.
enum class [[nodiscard]] SnapRelocatorError {
  kOk = 0,       // No error.
  kEmptyCorpus,  // Cannot relocate an empty corpus.
  kAlignment,    // A pointer is unaligned.
  kOutOfBound,   // A pointer points outside of the relocatable.
  kMprotect,     // Error in setting up memory protection.
  kBadData,      // This is either not a corpus file or it is out of date.
  kBadChecksum,  // Corpus checksum is incorrect.
};

// SnapRelocator relocates a relocatable Snap corpus loaded at an address
// different from the nominal load address of 0. Relocation involves adding
// the start address of the Snap corpus to every pointer inside the corpus.
template <typename Arch>
class SnapRelocator {
 public:
  // Relocates a relocatable Snap corpus pointed by `relocatable` and then
  // mprotect the memory to be read-only.
  // Performs additional integrity checks if `verify` is set.
  // RETURNS: A mmapped memory pointer to the relocated corpus and an error
  // code indicating if relocation succeeded. If relocation failed, the return
  // contents are undefined.
  static MmappedMemoryPtr<const SnapCorpus<Arch>> RelocateCorpus(
      MmappedMemoryPtr<char> relocatable, bool verify,
      SnapRelocatorError* error);

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

  // Validates relocated `address` for type `T`. The address is valid if
  // 1. the whole object is within memory bound of this and
  // 2. the address is aligned for type `T`.
  // Returns an Error.
  template <typename T>
  SnapRelocatorError ValidateRelocatedAddress(uintptr_t address);

  // Adjusts a relocatable pointer in place. This adds the start address
  // of the relocatable corpus to a pointer, which is a relative
  // offset from the start address to the address of the pointed object.
  // This also checks that the relocated pointer is still within the
  // relocatable corpus and is properly aligned for type T.
  //
  // RETURNS: whether adjustment succeeded. If adjustment failed, `T` has
  // an undefined value.
  template <typename T>
  SnapRelocatorError AdjustPointer(T*&);

  // Similar to AdjustPointer() but for SnapArray<T>.
  // Adjusts array.elements if array.size>0 otherwise sets array.elements to
  // nullptr.
  //
  // RETURNS: whether adjustment succeeded. If adjustment failed, contents of
  // `array` are undefined.
  template <typename T>
  SnapRelocatorError AdjustArray(SnapArray<T>& array);

  // Relocates a SnapArray<SnapMemoryBytes>.
  //
  // RETURNS: whether relocation succeeded. If it failed, contents of
  // `memory_byte_array` are undefined.
  SnapRelocatorError RelocateMemoryBytesArray(
      SnapArray<SnapMemoryBytes>& memory_bytes_array);

  // Relocates a RegisterState.
  //
  // RETURNS: whether relocation succeeded. If it failed, contents of
  // `register_state` are undefined.
  SnapRelocatorError RelocateRegisterState(
      Snap<Arch>::RegisterState& register_state);

  // Relocates corpus by adjusting all pointers inside the corpus.
  // If `verify` is true, calculate and verify the corpus checksum before
  // relocation.
  // REQUIRES: Only called once.
  // RETURNS: whether relocation succeeded. If it failed, contents of
  // corpus are undefined.
  SnapRelocatorError RelocateCorpus(bool verify);

  // Address of the beginning of the corpus.
  uintptr_t start_address_;

  // Address after the last byte of the corpus.
  uintptr_t limit_address_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_SNAP_RELOCATOR_H_
