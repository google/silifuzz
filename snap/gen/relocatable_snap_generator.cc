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

#include "./snap/gen/relocatable_snap_generator.h"

#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/hash/hash.h"
#include "./common/mapped_memory_map.h"
#include "./common/memory_perms.h"
#include "./common/snapshot.h"
#include "./snap/gen/relocatable_data_block.h"
#include "./snap/gen/repeating_byte_runs.h"
#include "./snap/snap.h"
#include "./util/checks.h"
#include "./util/mmapped_memory_ptr.h"
#include "./util/ucontext/serialize.h"

namespace silifuzz {

namespace {

// Sets register in `*tgt` using `src`.
void SetRegisterState(const Snapshot::RegisterState& src,
                      Snap::RegisterState* tgt,
                      bool allow_empty_register_state) {
  memset(tgt, 0, sizeof(*tgt));

  // Both GPR and FPR states can be missing for an undefined end state.
  // We need to check for zero size.
  if (!src.gregs().empty()) {
    CHECK(DeserializeGRegs(src.gregs(), &tgt->gregs));
  } else {
    CHECK(allow_empty_register_state);
    memset(&tgt->gregs, 0, sizeof(tgt->gregs));
  }

  if (!src.fpregs().empty()) {
    CHECK(DeserializeFPRegs(src.fpregs(), &tgt->fpregs));
  } else {
    CHECK(allow_empty_register_state);
    memset(&tgt->fpregs, 0, sizeof(tgt->fpregs));
  }
}

// This encapsulates logic and data neccessary to build a relocatable
// Snap corpus.
//
// This class is not thread-safe.
class Traversal {
 public:
  explicit Traversal(const RelocatableSnapGeneratorOptions& options)
      : options_(options) {}
  ~Traversal() = default;

  // Not copyable or moveable.
  Traversal(const Traversal&) = delete;
  Traversal& operator=(const Traversal&) = delete;
  Traversal(Traversal&&) = delete;
  Traversal& operator=(Traversal&&) = delete;

  // Relocatable Snap corpus generation is a two-pass-process. First, we
  // go over all Snaps to compute sizes and offsets of different parts
  // of the corpus. A content buffer big enough to hold the whole corpus
  // is then allocated. The second pass goes over the input snapshots again to
  // generate contents of the relocatable corpus.
  enum class PassType {
    kLayout,      // Computing data block sizes
    kGeneration,  // Generating relocatable contents
  };

  // Process `snapshots` for `pass`. In the layout pass, this layouts out all
  // the Snap objects corresponding to `snapshots`. In the generation pass,
  // contents of the Snap objects are generated.
  //
  // REQUIRES: This needs to be call twice for `snapshots`, First for the layout
  // pass and then the generation pass. The generation pass must be preceeded by
  // a call to  PrepareSnapGeneration().
  void Process(PassType pass, const std::vector<Snapshot>& snapshots);

  // Sets up content buffers and load addresses for main data block and its
  // component. This also sets up sub data blocks.
  // REQUIRES: Called after layout pass but before generation pass.
  // Content buffer must be as least the current size of the main data block
  // and has the same or wider alignment required by the main data block.
  // `load_address` must also be suitably aligned.
  void PrepareSnapGeneration(char* content_buffer, size_t content_buffer_size,
                             uintptr_t load_address);

  // Returns a const reference to the main block.
  const RelocatableDataBlock& main_block() const { return main_block_; }

 private:
  // Processes `byte_data` for `pass`. Allocates a ref element bytes of the
  // generated Snap::ByteData. Returns element ref.
  RelocatableDataBlock::Ref Process(PassType pass,
                                    const Snapshot::ByteData& byte_data);

  // Processes `memory_mappings` for `pass`. Allocates a ref for the
  // elements of the Snap::MemoryMapping array and returns it.
  RelocatableDataBlock::Ref Process(
      PassType pass, const Snapshot::MemoryMappingList& memory_mappings);

  // Processes a single Snapshot::MemoryBytes object `memory_bytes` for
  // `pass` using a preallocated ref from caller. This uses `mapped_memory_map`
  // to look up memory permission information, which is not included in the
  // source Snapshot::MemoryBytes object.
  void ProcessAllocated(PassType pass,
                        const Snapshot::MemoryBytes& memory_bytes,
                        const MappedMemoryMap& mapped_memory_map,
                        RelocatableDataBlock::Ref memory_bytes_ref);

  // Processes a Snapshot::MemoryBytesList object `memory_bytes_list` for
  // `pass`. `mapped_memory_map` contains information of all memory mappings
  // in the source Snapshot. This allocates a ref the elements of the
  // Snap::MemoryBytes array and returns it.
  RelocatableDataBlock::Ref Process(
      PassType pass, const Snapshot::MemoryBytesList& memory_bytes_list,
      const MappedMemoryMap& mapped_memory_map);

  void ProcessAllocated(PassType pass, const Snapshot& snapshot,
                        RelocatableDataBlock::Ref ref);

  // MemoryBytes de-duping: MemoryBytes are de-duped to reduce size of
  // of a relocatable corpus. MemoryBytes with the same byte values share
  // a single copy of byte data in the generated Snap corpus.  The byte values
  // can be large, so we use pointers to Snapshot::ByteData as keys in the
  // hash map below.

  struct HashByteData {
    size_t operator()(const Snapshot::ByteData* byte_data) const {
      return absl::HashOf(*byte_data);
    }
  };

  // Returns true iff the byte data pointed by lhs and rhs are the same.
  struct ByteDataEq {
    bool operator()(const Snapshot::ByteData* lhs,
                    const Snapshot::ByteData* rhs) const {
      return *lhs == *rhs;
    }
  };

  using ByteDataRefMap =
      absl::flat_hash_map<const Snapshot::ByteData*, RelocatableDataBlock::Ref,
                          HashByteData, ByteDataEq>;

  // Options.
  RelocatableSnapGeneratorOptions options_;

  // The main data block covering the whole relocatable corpus.
  // Other blocks belows are merged into this.
  RelocatableDataBlock main_block_;

  // Sub data blocks.
  RelocatableDataBlock snap_block_;
  RelocatableDataBlock memory_bytes_block_;
  RelocatableDataBlock memory_mapping_block_;
  RelocatableDataBlock byte_data_block_;
  RelocatableDataBlock string_block_;

  // Hash map for de-duping byte data.
  ByteDataRefMap byte_data_ref_map_;
};

RelocatableDataBlock::Ref Traversal::Process(
    PassType pass, const Snapshot::ByteData& byte_data) {
  // Check to see if we can de-dupe byte data.
  static constexpr RelocatableDataBlock::Ref kNullRef;
  auto [it, success] = byte_data_ref_map_.try_emplace(&byte_data, kNullRef);
  auto&& [unused, ref] = *it;

  // try_emplace() above failed because byte_data is a duplicate. Return early
  // as there is no need to do anything for the generation pass.
  if (!success) {
    // Check that optimization is valid during the generation pass. This is
    // expensive for large blocks of data so is done only for debug build.
    if (pass == PassType::kGeneration) {
      DCHECK_EQ(memcmp(ref.contents(), byte_data.data(), byte_data.size()), 0);
    }
    return ref;
  }

  // Allocate a new Ref as this has not be seen before.
  ref = byte_data_block_.Allocate(byte_data.size(), sizeof(uint64_t));
  if (pass == PassType::kGeneration) {
    memcpy(ref.contents(), byte_data.data(), byte_data.size());
  }
  return ref;
}

RelocatableDataBlock::Ref Traversal::Process(
    PassType pass, const Snapshot::MemoryMappingList& memory_mappings) {
  // Allocate space for elements of SnapArray<MemoryMapping>.
  const RelocatableDataBlock::Ref snap_memory_mappings_array_elements_ref =
      memory_mapping_block_.AllocateObjectsOfType<Snap::MemoryMapping>(
          memory_mappings.size());

  if (pass == PassType::kGeneration) {
    RelocatableDataBlock::Ref snap_memory_mapping_ref =
        snap_memory_mappings_array_elements_ref;
    for (const auto& memory_mapping : memory_mappings) {
      new (
          snap_memory_mapping_ref.contents_as_pointer_of<Snap::MemoryMapping>())
          Snap::MemoryMapping{
              .start_address = memory_mapping.start_address(),
              .num_bytes = memory_mapping.num_bytes(),
              .perms = memory_mapping.perms().ToMProtect(),
          };
      snap_memory_mapping_ref += sizeof(Snap::MemoryMapping);
    }
  }

  return snap_memory_mappings_array_elements_ref;
}

void Traversal::ProcessAllocated(PassType pass,
                                 const Snapshot::MemoryBytes& memory_bytes,
                                 const MappedMemoryMap& mapped_memory_map,
                                 RelocatableDataBlock::Ref memory_bytes_ref) {
  const bool compress_repeating_bytes =
      options_.compress_repeating_bytes &&
      IsRepeatingByteRun(memory_bytes.byte_values());
  RelocatableDataBlock::Ref byte_values_elements_ref;
  if (!compress_repeating_bytes) {
    byte_values_elements_ref = Process(pass, memory_bytes.byte_values());
  }

  if (pass == PassType::kGeneration) {
    const MemoryPerms perms =
        mapped_memory_map.PermsAt(memory_bytes.start_address());

    // Construct MemoryBytes in contents buffer.
    if (compress_repeating_bytes) {
      new (memory_bytes_ref.contents_as_pointer_of<Snap::MemoryBytes>())
          Snap::MemoryBytes{
              .start_address = memory_bytes.start_address(),
              .perms = perms.ToMProtect(),
              .flags = Snap::MemoryBytes::kRepeating,
              .data{.byte_run{
                  .value = memory_bytes.byte_values()[0],
                  .size = memory_bytes.num_bytes(),
              }},
          };
    } else {
      new (memory_bytes_ref.contents_as_pointer_of<Snap::MemoryBytes>())
          Snap::MemoryBytes{
              .start_address = memory_bytes.start_address(),
              .perms = perms.ToMProtect(),
              .flags = 0,
              .data{.byte_values{
                  .size = memory_bytes.num_bytes(),
                  .elements = byte_values_elements_ref
                                  .load_address_as_pointer_of<const uint8_t>(),
              }},
          };
    }
  }
}

RelocatableDataBlock::Ref Traversal::Process(
    PassType pass, const Snapshot::MemoryBytesList& memory_bytes_list,
    const MappedMemoryMap& mapped_memory_map) {
  // Allocate space for elements of SnapArray<MemoryBytes>.
  const RelocatableDataBlock::Ref ref =
      memory_bytes_block_.AllocateObjectsOfType<Snap::MemoryBytes>(
          memory_bytes_list.size());

  RelocatableDataBlock::Ref snap_memory_bytes_ref = ref;
  for (const auto& memory_bytes : memory_bytes_list) {
    ProcessAllocated(pass, memory_bytes, mapped_memory_map,
                     snap_memory_bytes_ref);
    snap_memory_bytes_ref += sizeof(Snap::MemoryBytes);
  }
  return ref;
}

void Traversal::ProcessAllocated(PassType pass, const Snapshot& snapshot,
                                 RelocatableDataBlock::Ref snapshot_ref) {
  size_t id_size = snapshot.id().size() + 1;  // NUL character terminator.
  RelocatableDataBlock::Ref id_ref = string_block_.Allocate(id_size, 1);
  RelocatableDataBlock::Ref memory_mappings_elements_ref =
      Process(pass, snapshot.memory_mappings());
  RelocatableDataBlock::Ref memory_bytes_elements_ref =
      Process(pass, snapshot.memory_bytes(), snapshot.mapped_memory_map());
  const Snapshot::EndState& end_state = snapshot.expected_end_states()[0];
  RelocatableDataBlock::Ref end_state_memory_bytes_elements_ref =
      Process(pass, end_state.memory_bytes(), snapshot.mapped_memory_map());

  if (pass == PassType::kGeneration) {
    memcpy(id_ref.contents(), snapshot.id().c_str(), snapshot.id().size() + 1);

    // Construct Snap in data block content buffer.
    // Fill in register states separately to avoid copying.
    Snap* snap = snapshot_ref.contents_as_pointer_of<Snap>();
    new (snap) Snap{
        .id = reinterpret_cast<const char*>(AsPtr(id_ref.load_address())),
        .memory_mappings{
            .size = snapshot.memory_mappings().size(),
            .elements =
                memory_mappings_elements_ref
                    .load_address_as_pointer_of<const Snap::MemoryMapping>(),
        },
        .memory_bytes{
            .size = snapshot.memory_bytes().size(),
            .elements =
                memory_bytes_elements_ref
                    .load_address_as_pointer_of<const Snap::MemoryBytes>(),
        },
        .end_state_instruction_address =
            end_state.endpoint().instruction_address(),
        .end_state_memory_bytes{
            .size = end_state.memory_bytes().size(),
            .elements =
                end_state_memory_bytes_elements_ref
                    .load_address_as_pointer_of<const Snap::MemoryBytes>(),
        },
    };
    SetRegisterState(snapshot.registers(), &snap->registers,
                     /*allow_empty_register_state=*/false);
    // End state may be undefined initially in the making process.
    SetRegisterState(end_state.registers(), &snap->end_state_registers,
                     /*allow_empty_register_state=*/true);
  }
}

void Traversal::Process(PassType pass, const std::vector<Snapshot>& snapshots) {
  // For compatiblity with an older Silifuzz version, we use corpus type
  // Snap::Array<const Snap*>.  We can get rid of the redirection when we
  // change the runner to take Snap::Array<Snap> later.

  // Allocate Snap::Corpus
  using SnapArrayType = Snap::Corpus;
  RelocatableDataBlock::Ref snap_array_ref =
      snap_block_.AllocateObjectsOfType<Snap::Corpus>(1);

  // Allocate space for element.
  RelocatableDataBlock::Ref snap_array_elements_ref =
      snap_block_.AllocateObjectsOfType<const Snap*>(snapshots.size());

  // Allocate space for Snaps.
  RelocatableDataBlock::Ref snaps_ref =
      snap_block_.AllocateObjectsOfType<Snap>(snapshots.size());
  for (size_t i = 0; i < snapshots.size(); ++i) {
    ProcessAllocated(pass, snapshots[i], snaps_ref + i * sizeof(Snap));
  }

  // Merge component data blocks into a single main data block.
  // Parts with and without pointers are group separately to minimize
  // memory pages that needs to be modified. This is desirable if a
  // corpus is to be mmapped by multiple runners.

  // These have pointers.
  main_block_.Allocate(snap_block_);
  main_block_.Allocate(memory_bytes_block_);

  // These are pointer-free
  main_block_.Allocate(memory_mapping_block_);
  main_block_.Allocate(byte_data_block_);
  main_block_.Allocate(string_block_);

  if (pass == PassType::kGeneration) {
    new (snap_array_ref.contents()) SnapArrayType{
        .size = snapshots.size(),
        .elements =
            snap_array_elements_ref.load_address_as_pointer_of<const Snap*>(),
    };

    // Create const pointer array elements.
    for (size_t i = 0; i < snapshots.size(); ++i) {
      const RelocatableDataBlock::Ref snap_ref = snaps_ref + i * sizeof(Snap);
      const RelocatableDataBlock::Ref element_ref =
          snap_array_elements_ref + i * sizeof(const Snap*);
      *element_ref.contents_as_pointer_of<const Snap*>() =
          snap_ref.load_address_as_pointer_of<const Snap>();
    }
  }
}

void Traversal::PrepareSnapGeneration(char* content_buffer,
                                      size_t content_buffer_size,
                                      uintptr_t load_address) {
  main_block_.set_contents(content_buffer, content_buffer_size);
  main_block_.set_load_address(load_address);

  // Layouts a sub-block within the main block and then
  // resets the sub-block for the generating pass.
  auto prepare_sub_data_block = [&](RelocatableDataBlock& block) {
    const RelocatableDataBlock::Ref ref = main_block_.Allocate(block);
    block.set_load_address(ref.load_address());
    block.set_contents(ref.contents(), block.size());
    block.ResetSizeAndAlignment();
  };

  main_block_.ResetSizeAndAlignment();
  prepare_sub_data_block(snap_block_);
  prepare_sub_data_block(memory_bytes_block_);
  prepare_sub_data_block(memory_mapping_block_);
  prepare_sub_data_block(byte_data_block_);
  prepare_sub_data_block(string_block_);

  // Reset main block again for generation pass.
  main_block_.ResetSizeAndAlignment();

  // Reset byte data de-duping hash map.
  byte_data_ref_map_.clear();
}

}  // namespace

MmappedMemoryPtr<char> GenerateRelocatableSnaps(
    const std::vector<Snapshot>& snapshots,
    const RelocatableSnapGeneratorOptions& options) {
  Traversal traversal(options);
  traversal.Process(Traversal::PassType::kLayout, snapshots);

  // Check that the whole corpus has alignment requirement not exceeding page
  // size of the runner since it will be mmap()'ed by the runner.
  // Cross-platform-generation is not supported. So it is okay to use the
  // generator's page size here.
  CHECK_LE(traversal.main_block().required_alignment(), getpagesize());
  auto buffer = AllocateMmappedBuffer<char>(traversal.main_block().size());

  // Generate contents of the relocatable corpus as if it was to be loaded
  // at address 0. Runtime relocation can simply be done by adding the load
  // address of the corpus to every pointers inside the corpus.
  constexpr uintptr_t kNominalLoadAddress = 0;
  traversal.PrepareSnapGeneration(buffer.get(), MmappedMemorySize(buffer),
                                  kNominalLoadAddress);
  traversal.Process(Traversal::PassType::kGeneration, snapshots);
  return buffer;
}

}  // namespace silifuzz
