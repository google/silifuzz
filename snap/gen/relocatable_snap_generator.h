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

#include <cstdint>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "./common/snapshot.h"
#include "./util/arch.h"
#include "./util/mmapped_memory_ptr.h"

namespace silifuzz {

// Relocatable Snap format:
//
// This is a relocatable format for Snap corpus. A relocatable Snap corpus is
// essentially the same as an in-memory Snap corpus except:
//
// 1. all pointers are replaced by offsets from the beginning of the corpus.
//    This is as if the corpus was generated for the nominal load address 0.
// 2. all pointers must be within the relocatable corpus itself. There should
//    not be any external references.
//
// A relocatable Snap corpus can be converted back to the normal in-memory
// format by adding the load address of the corpus to pointers inside it.
//
// Corpus layout:
//
// +---------------------------+
// | header SnapCorpus struct  |
// +---------------------------+
// | corpus SnapArray struct   |
// +---------------------------+
// | Snap pointer array        |
// +---------------------------+
// | Snap array                |
// +---------------------------+
// | SnapMemoryBytes array     |
// +---------------------------+
// | SnapMemoryMapping array   |
// +---------------------------+
// | byte array                |
// +---------------------------+
// | string array              |
// +---------------------------+
// | Snap::RegisterState array |
// +---------------------------+
// | page aligned byte data    |
// +---------------------------+
//
// The parts are aligned with respect to their individual requirements and the
// whole corpus is loaded with alignment not smaller than the maximum alignment
// requirements of it parts. Data of the same type are grouped together in order
// to minimize alignment gaps inside the corpus.
//
// 0. Corpus header.
// Located at the beginning of the file. Contains magic and metadata like target
// architecture, etc.
//
// 1. Corpus SnapArray struct.
// It consist of a single Snap::Corpus structure. It contains the number of
// Snaps in the corpus as well as a pointer to the snap pointer array after it.
//
// 2. Snap pointer array.
// There is one pointer in this array for each Snap in the Snap array that
// follows.
//
// 3. Snap array
// These are fixed-sized parts of Snaps. Variable-sized parts of Snaps are
// stored in their respective parts inside the corpus.
//
// 4. SnapMemoryBytes array.
// These are Snap::MemoryBytes structures. Byte data referenced by these are
// stored in another part of the corpus.
//
// 5. SnapMemoryMapping array.
// Fixed-sized Memory mappings structures.
//
// 6. Byte array.
// Variable-sized part of memory bytes.  These are aligned to 64-bit boundaries
// to speed up access.
//
// 7. String array.
// Snapshot IDs.
//
// 8. Snap::RegisterState array.
// These are the registers that specify the entry and exit state of each Snap.
// This data is stored out-of-line from the Snap structure so that relocating
// the Snap doesn't dirty the pages containing register data.
//
// 9. Page-aligned data.
// Page-aligned memory bytes may be put in this section if we want to mmap them
// directly from the file when the corpus is loaded. Page-aligned data will not
// be RLE compressed, however, so there is a tradeoff between load speed and
// corpus size.

// Options passed to relocatable Snap corpus generator.
struct RelocatableSnapGeneratorOptions {
  // If true, apply run-length compression to memory bytes data.
  bool compress_repeating_bytes = true;

  // When present, this map will be populated with various _debug-only_
  // counters representing sizes of different parts of the generated corpus.
  // The keys are human-readable but are not guaranteed to be stable.
  absl::flat_hash_map<std::string, uint64_t>* counters = nullptr;
};

// Generates a relocatable Snap corpus for `architecture_id` from `snapshots`
// with `options`.
//
// RETURNS a MmappedMemoryPtr to a buffer containing the relocatable corpus.
//
// REQUIRES: `snapshots` are snapified.
// REQUIRES: the architecture of each snapshot matches `architecture_id`.
//
// This function is thread-safe.
MmappedMemoryPtr<char> GenerateRelocatableSnaps(
    ArchitectureId architecture_id, const std::vector<Snapshot>& snapshots,
    const RelocatableSnapGeneratorOptions& options = {});

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_GEN_RELOCATABLE_SNAP_GENERATOR_H_
