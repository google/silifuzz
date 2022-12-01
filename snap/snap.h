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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_SNAP_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_SNAP_H_
// Snap
//
// This is a snapshot representation optimized for executation speed.
// intended for embedding snapshots into C/C++ source code as static data
// structures that are compiled and linked into a snapshot player. This
// representation matches proto::Snapshot closely but not exactly,
// Information not required for snapshot execution is left out and will only be
// added back when needed.
#include <sys/mman.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "./util/checks.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

// A simplified snapshot representation.
struct Snap {
  // Linker-initialized array.
  template <typename T>
  struct Array {
    // number of elements in elements[].
    size_t size;

    // The array itself has a fixed size.  So data are placed elsewhere.
    const T* elements;

    typedef const T* const_iterator;
    const_iterator begin() const { return &elements[0]; }
    const_iterator end() const { return &elements[size]; }

    const T& operator[](size_t idx) const { return elements[idx]; }

    const T& at(size_t idx) const {
      CHECK(idx < size);
      return elements[idx];
    }
  };

  // Describe register state of a Snapshot. This is stored in UContext/
  // and can be used directly as the context for running a Snap without any
  // conversion or copying.
  using RegisterState = UContext<Host>;

  // Describes a single contiguous range of byte values in memory.
  // This is a linker-initialized equivalent of Snapshot::MemoryBytes
  struct MemoryBytes {
    // Flags
    enum {
      kRepeating = 1 << 0,  // If set, memory bytes are repeating. This
                            // determines how data below are interpreted.
    };

    // If memory bytes are all the same value, they are stored as
    // a run of single value.
    struct ByteRun {
      uint8_t value;  // repeated value
      size_t size;    // number of bytes in run.
    };

    // Tells if memory bytes are repeating.
    bool repeating() const { return (flags & kRepeating) != 0; }

    // Returns byte size of the memory bytes.
    size_t size() const {
      return repeating() ? data.byte_run.size : data.byte_values.size;
    }

    // Returns true if memory bytes are writable.
    bool writable() const { return (perms & PROT_WRITE) != 0; }

    // Where `byte_values` start.
    uint64_t start_address;

    // POSIX memory permissions of the memory bytes. The snap generator
    // ensures that each MemoryBytes resides in a memory region with the same
    // permissions throughout. This information can be obtained from
    // memory mappings. However, it is duplicated here for efficiency of the
    // runner.
    //
    // TODO(dougkwan): [design] Remove MemoryMapping and just use perms here
    // instead.
    int32_t perms;  // Only stores READ/WRITE/EXEC permssions.

    // Flags
    uint8_t flags = 0;

    union {
      // The memory byte values to exist at start_address. This is set only when
      // repeating == false.
      Array<uint8_t> byte_values;

      // A repeated run of a single byte value at start_address. This is set
      // only when repeating == true.
      ByteRun byte_run;
    } data;
  };

  // Describes a single contiguous page-aligned memory mapping.
  // Linker-initialized equivalent of Snapshot::MemoryMapping.
  struct MemoryMapping {
    // Returns true if memory mapping is writable.
    bool writable() const { return (perms & PROT_WRITE) != 0; }

    // Start address of region mapped.
    uint64_t start_address;

    // Byte size of region.
    uint64_t num_bytes;

    // Bit mask of memory protections. Same as those used in mprotect().
    // This information is duplicated in MemoryBytes above.
    int32_t perms;
  };

  // Identifier for this snapshot.
  const char* id;

  // We do not store architecture in Snap. To ensure we run snapshots on the
  // correct architecture, this information may be stored in a higher-level
  // container like a Snap group, or a Snap corpus.

  // All the memory mappings that exist at the start of the snapshot.
  // See Snapshot::memory_mappings().
  Array<MemoryMapping> memory_mappings;

  // We do not support negative memory mappings for now.

  // All the memory state that exists at the start of the snapshot.
  // See Snapshot::memory_bytes().
  Array<MemoryBytes> memory_bytes;

  // The state of the registers at the start of the snapshot.
  RegisterState* registers;

  // The only possible expected end-state of executing the snapshot.
  // We do not allow multiple end states.

  // For now, we only support snapshots ending at instructions.
  uint64_t end_state_instruction_address;

  // The expected state of the registers to exist at `endpoint`.
  RegisterState* end_state_registers;

  // The expected memory state to exist at `endpoint`.
  // These must cover all writable memory bytes not just deltas compared to
  // the initial memory state.  This representation is optimized for checking
  // memory writable by a snapshot.
  //
  // TODO(dougkwan): [as-needed] We may support other modes of memory checking
  // like just checking only the memory that a snapshot changes.
  Array<MemoryBytes> end_state_memory_bytes;
};

namespace snap_internal {

template <typename T>
constexpr T MakeMagic(const char (&data)[sizeof(T)]) {
  T magic = 0;
  for (size_t i = 0; i < sizeof(T); i++) {
    magic |= ((T)data[i]) << (i * 8);
  }
  return magic;
}

}  // namespace snap_internal

constexpr uint64_t kSnapCorpusMagic = snap_internal::MakeMagic<uint64_t>(
    {'S', 'n', 'a', 'p', 'C', 'o', 'r', 'p'});

struct SnapCorpus {
  // For checking this is actually a snap corpus.
  uint64_t magic;

  // The expected sizeof(SnapCorpus), for checking the data is in sync with the
  // code. This should always be located just after the magic, and be checked
  // just after the magic.
  uint32_t corpus_type_size;

  // The expected sizeof(Snap), for checking the data is in sync with the code.
  uint32_t snap_type_size;

  // The expected size of the register state.
  uint32_t register_state_type_size;

  // The architechture these snaps run on.
  // The runner should check that this equals Host::architecture_id.
  uint8_t architecture_id;

  // Make the unused space in this struct explicit.
  uint8_t padding[3];

  // The corpus data.
  Snap::Array<const Snap*> snaps;

  template <typename Arch>
  bool IsArch() const {
    return architecture_id == static_cast<int>(Arch::architecture_id);
  }

  // Find a Snap with the specified id.
  // Returns nullptr if not found.
  const Snap* Find(const char* id) const {
    for (const Snap* snap : snaps) {
      if (strcmp(snap->id, id) == 0) {
        return snap;
      }
    }
    return nullptr;
  }
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_SNAP_H_
