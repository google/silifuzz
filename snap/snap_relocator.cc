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
#include "./snap/snap_checksum.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/mmapped_memory_ptr.h"

namespace silifuzz {

namespace {

// Convenience function to create a null corpus for errors.
template <typename Arch>
MmappedMemoryPtr<const SnapCorpus<Arch>> make_null_corpus() {
  return MakeMmappedMemoryPtr<const SnapCorpus<Arch>>(nullptr, 0);
}

// Ensure that a read from memory only occurs once.
// If the relocator is fed junk data (by a fuzzer, for example) the pointers
// can be aliased in strange ways and any relocation can mutate any part of the
// corpus. If we wanted to be secure against an attacker-provided corpus, we'd
// need to re-design the format to make aliasing detectable / impossible. If we
// want to fuzz and find non-aliasing-related bugs, the following function
// allows us to write code that behaves more predictably in the presence of
// aliasing. For example, we can read the size of an array before iterating over
// it without worrying that processing the array will mutate the size. Naively,
// we could just store the array size in a local variable, but if the compiler
// does any type-based alias optimizations, the local variable could be silently
// re-loaded from memory every loop iteration because the compiler determines it
// should never change and it needs to free up a register. This function
// prevents silent reloads by making the read volitile.
template <typename T>
T read_once(T& value) {
  return *const_cast<volatile T*>(&value);
}

template <typename T>
class RelocationIterator {
 public:
  explicit RelocationIterator(const SnapArray<T>& array) {
    // If the Corpus is malformed, future relocations could corrupt these values
    // so copy them.
    // This iterator should be created immediately after relocating the array
    // and before relocating anything else.
    // Make the elements non-const since we're going to be mutating them.
    elements_ = const_cast<T*>(read_once(array.elements));
    size_ = read_once(array.size);
  }

  T* begin() const { return elements_; }
  T* end() const { return elements_ + size_; }

 private:
  T* elements_;
  size_t size_;
};

// Satisfy -Wctad-maybe-unsupported
template <typename T>
RelocationIterator(SnapArray<T>&) -> RelocationIterator<T>;

}  // namespace

// Similar to RETURN_IF_NOT_OK() but for SnapRelocator::Error.
#define RETURN_IF_RELOCATION_FAILED(exp)                \
  do {                                                  \
    const SnapRelocatorError error = (exp);             \
    if (error != SnapRelocatorError::kOk) return error; \
  } while (0)

template <typename Arch>
template <typename T>
SnapRelocatorError SnapRelocator<Arch>::ValidateRelocatedAddress(
    uintptr_t address) {
  // The whole object must be within corpus bounds.
  // If address + sizeof(T) is exactly numeric_limits<uintptr_t>::max() + 1,
  // this rejects address even the whole object is within 64-bit address space.
  // This is fine as user mode address space size is much less than 64-bit.
  uintptr_t address_after_last_byte;
  if (address < start_address_ ||
      __builtin_add_overflow(address, sizeof(T), &address_after_last_byte) ||
      address_after_last_byte > limit_address_)
    return SnapRelocatorError::kOutOfBound;

  // Address be correctly aligned.
  if (address % alignof(T) != 0) return SnapRelocatorError::kAlignment;

  return SnapRelocatorError::kOk;
}

template <typename Arch>
template <typename T>
SnapRelocatorError SnapRelocator<Arch>::AdjustPointer(T*& ptr) {
  // A pointer in a relocatable Snap corpus offset is just offset from the
  // start of the corpus. The actual run time address of the pointed object
  // is recovered by simply adding the start address of the corpus.
  uintptr_t adjusted_address;
  if (__builtin_add_overflow(start_address_, reinterpret_cast<uintptr_t>(ptr),
                             &adjusted_address)) {
    return SnapRelocatorError::kOutOfBound;
  }
  RETURN_IF_RELOCATION_FAILED(ValidateRelocatedAddress<T>(adjusted_address));

  ptr = reinterpret_cast<T*>(adjusted_address);
  return SnapRelocatorError::kOk;
}

template <typename Arch>
template <typename T>
SnapRelocatorError SnapRelocator<Arch>::AdjustArray(SnapArray<T>& array) {
  if (array.size > 0) {
    RETURN_IF_RELOCATION_FAILED(AdjustPointer(array.elements));

    // Check array size for pointer overflow.
    uintptr_t elements_byte_size;
    if (__builtin_mul_overflow(array.size, sizeof(T), &elements_byte_size)) {
      return SnapRelocatorError::kOutOfBound;
    }

    // Check that the last element is within bound. The beginning of array
    // is checked already by AdjustPointer() above.
    uintptr_t address_after_last_byte;
    if (__builtin_add_overflow(reinterpret_cast<uintptr_t>(array.elements),
                               elements_byte_size, &address_after_last_byte) ||
        address_after_last_byte > limit_address_) {
      return SnapRelocatorError::kOutOfBound;
    }

    return SnapRelocatorError::kOk;
  } else {
    array.elements = nullptr;
    return SnapRelocatorError::kOk;
  }
}

template <typename Arch>
SnapRelocatorError SnapRelocator<Arch>::RelocateMemoryBytesArray(
    SnapArray<SnapMemoryBytes>& memory_bytes_array) {
  RETURN_IF_RELOCATION_FAILED(AdjustArray(memory_bytes_array));
  for (SnapMemoryBytes& memory_byte : RelocationIterator(memory_bytes_array)) {
    if (!memory_byte.repeating()) {
      RETURN_IF_RELOCATION_FAILED(
          AdjustPointer(memory_byte.data.byte_values.elements));
    }
  }
  return SnapRelocatorError::kOk;
}

template <typename Arch>
SnapRelocatorError SnapRelocator<Arch>::RelocateRegisterState(
    typename Snap<Arch>::RegisterState& register_state) {
  RETURN_IF_RELOCATION_FAILED(AdjustPointer(register_state.fpregs));
  RETURN_IF_RELOCATION_FAILED(AdjustPointer(register_state.gregs));
  return SnapRelocatorError::kOk;
}

template <typename Arch>
SnapRelocatorError SnapRelocator<Arch>::RelocateCorpus(bool verify) {
  // We know the pointer is in bounds, but check that the struct fits in memory
  // and is aligned.
  RETURN_IF_RELOCATION_FAILED(
      ValidateRelocatedAddress<SnapCorpus<Arch>>(start_address_));

  SnapCorpus<Arch>& corpus =
      *reinterpret_cast<SnapCorpus<Arch>*>(start_address_);

  // If this constant isn't at the start of the file, it's likely not a corpus.
  if (corpus.header.magic != kSnapCorpusMagic) {
    return SnapRelocatorError::kBadData;
  }
  // If the header isn't the size we expected, this is likely a version
  // mismatch. We check early since the rest of the checks rely on the header
  // having the layout we expect.
  if (corpus.header.header_size != sizeof(SnapCorpusHeader)) {
    return SnapRelocatorError::kBadData;
  }
  // If the corpus file isn't the same number of bytes it was when it was
  // created, it likely is corrupt.
  if (corpus.header.num_bytes != limit_address_ - start_address_) {
    return SnapRelocatorError::kBadData;
  }
  // Verifying the checksum is relatively expensive.
  if (verify) {
    uint32_t expected = corpus.header.checksum;
    CorpusChecksumCalculator checksum;
    checksum.AddData(&corpus, corpus.header.num_bytes);
    uint32_t actual = checksum.Checksum();
    if (expected != actual) {
      // TODO(ncbray): propagate error information in return value.
      LOG_ERROR("Expected corpus would have checksum ", HexStr(expected),
                " but got ", HexStr(actual));
      return SnapRelocatorError::kBadChecksum;
    }
  }
  // Detect if we're trying to load a corpus for the wrong arch.
  if (!corpus.IsExpectedArch()) {
    return SnapRelocatorError::kBadData;
  }
  // The header embeds size of various structs so that we can detect accidental
  // version mismatches.
  if (corpus.header.corpus_type_size != sizeof(SnapCorpus<Arch>)) {
    return SnapRelocatorError::kBadData;
  }
  if (corpus.header.snap_type_size != sizeof(Snap<Arch>)) {
    return SnapRelocatorError::kBadData;
  }
  if (corpus.header.register_state_type_size !=
      sizeof(typename Snap<Arch>::RegisterState)) {
    return SnapRelocatorError::kBadData;
  }

  RETURN_IF_RELOCATION_FAILED(AdjustArray(corpus.snaps));
  for (const Snap<Arch>*& snap_ptr : RelocationIterator(corpus.snaps)) {
    // Adjust the pointer in the array.
    RETURN_IF_RELOCATION_FAILED(AdjustPointer(snap_ptr));

    // Adjust pointers in this Snap.
    Snap<Arch>& snap = *const_cast<Snap<Arch>*>(read_once(snap_ptr));
    RETURN_IF_RELOCATION_FAILED(AdjustPointer(snap.id));

    RETURN_IF_RELOCATION_FAILED(AdjustArray(snap.memory_mappings));
    for (SnapMemoryMapping& mapping :
         RelocationIterator(snap.memory_mappings)) {
      // Adjust memory bytes for initial mappings.
      RETURN_IF_RELOCATION_FAILED(
          RelocateMemoryBytesArray(mapping.memory_bytes));
    }

    // Adjust register pointers.
    RETURN_IF_RELOCATION_FAILED(RelocateRegisterState(snap.registers));
    RETURN_IF_RELOCATION_FAILED(
        RelocateRegisterState(snap.end_state_registers));

    // Adjust memory bytes for end state.
    RETURN_IF_RELOCATION_FAILED(
        RelocateMemoryBytesArray(snap.end_state_memory_bytes));
  }
  return SnapRelocatorError::kOk;
}

// static
template <typename Arch>
MmappedMemoryPtr<const SnapCorpus<Arch>> SnapRelocator<Arch>::RelocateCorpus(
    MmappedMemoryPtr<char> relocatable, bool verify,
    SnapRelocatorError* error) {
  const size_t byte_size = MmappedMemorySize(relocatable);
  if (byte_size == 0) {
    *error = SnapRelocatorError::kEmptyCorpus;
    return make_null_corpus<Arch>();
  }

  uintptr_t start_address = reinterpret_cast<uintptr_t>(relocatable.get());
  uintptr_t limit_address = start_address + byte_size;
  SnapRelocator relocator(start_address, limit_address);

  // Relocate corpus
  *error = relocator.RelocateCorpus(verify);
  if (*error != SnapRelocatorError::kOk) return make_null_corpus<Arch>();

  // mprotect corpus after relocation.
  if (mprotect(reinterpret_cast<void*>(relocatable.get()), byte_size,
               PROT_READ) != 0) {
    *error = SnapRelocatorError::kMprotect;
    return make_null_corpus<Arch>();
  }

  auto corpus =
      reinterpret_cast<const SnapCorpus<Arch>*>(relocatable.release());

  *error = SnapRelocatorError::kOk;
  return MakeMmappedMemoryPtr(corpus, byte_size);
}

template
    // static
    MmappedMemoryPtr<const SnapCorpus<X86_64>>
    SnapRelocator<X86_64>::RelocateCorpus(MmappedMemoryPtr<char> relocatable,
                                          bool verify,
                                          SnapRelocatorError* error);

template
    // static
    MmappedMemoryPtr<const SnapCorpus<AArch64>>
    SnapRelocator<AArch64>::RelocateCorpus(MmappedMemoryPtr<char> relocatable,
                                           bool verify,
                                           SnapRelocatorError* error);

}  // namespace silifuzz
