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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_GEN_RELOCATABLE_SNAP_GENERATOR_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_GEN_RELOCATABLE_SNAP_GENERATOR_H_

#include <vector>

#include "./common/snapshot.h"
#include "./util/mmapped_memory_ptr.h"

namespace silifuzz {

// Relocatable Snap format:
//
// This is a relocatable format for Snap corpus. A relocatable Snap corpus is
// essentially the same as an in-memory Snap corpus except:
//
// 1. all pointers are replaced by offsets from the beginning of the corups.
//    This is as if the corpus was generated for the nominal load address 0.
// 2. all pointers must be within the relocatable corpus itself. There should
//    not be any external references.
//
// A relocatable Snap corpus can be converted back to the normal in-memory
// format by adding the load address of the corpus to pointers inside it.
//
// Corpus layout:
//
// TODO(dougkwan): [design] We most likely will need a file header to store
// metadata like format version, platforms and etc.
//
// +---------------------------+
// | corpus Snap::Array struct |
// +---------------------------+
// | Snap pointer array        |
// +---------------------------+
// | Snap array                |
// +---------------------------+
// | Snap::MemoryBytes array   |
// +------------------------- -+
// | Snap::MemoryMapping array |
// +---------------------------+
// | byte array                |
// +---------------------------+
// | string array              |
// +---------------------------+
//
// The parts are aligned with respect to their individual requirements and the
// whole corpus is loaded with alignment not smaller than the maximum alignment
// requirements of it parts. Data of the same type are grouped together in order
// to minimize alignment gaps inside the corpus.
//
// 1. Corpus Snap::Array struct.
// This is located at the beginning of the whole relocatable Snap corpus.
// It consist of a single Snap::Array<const Snap*> structure. It contains
// the number of Snaps in the corpus as well as a pointer to the snap pointer
// array after it.
//
// 2. Snap pointer array.
// There is one pointer in this array for each Snap in the Snap array that
// follows.
//
// 3. Snap array
// These are fixed-sized parts of Snaps. Variable-sized parts of Snaps are
// stored in their respective parts inside the corpus.
//
// 4. Snap::MemoryBytes array.
// These are Snap::MemoryBytes structures. Byte data referenced by these are
// stored in another part of the corpus.
//
// 5. Snap::MemoryMapping array.
// Fixed-sized Memory mappings structures.
//
// 6. Byte array.
// Variable-sized part of memory bytes.  These are aligned to 64-bit boundaries
// to speed up access.
//
// 7. String array.
// Snapshot IDs.

// Options passed to relocatable Snap corpus generator.
struct RelocatableSnapGeneratorOptions {
  // If true, apply run-length compression to memory bytes data.
  bool compress_repeating_bytes = true;
};

// Generates a relocatable Snap corpus from `snapshots` with `options`.
//
// RETURNS a MmappedMemoryPtr to a buffer containing the relocatable corpus.
//
// REQUIRES: `snapshots` are snapified.
//
// This function is thread-safe.
MmappedMemoryPtr<char> GenerateRelocatableSnaps(
    const std::vector<Snapshot>& snapshots,
    const RelocatableSnapGeneratorOptions& options = {});

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_GEN_RELOCATABLE_SNAP_GENERATOR_H_
