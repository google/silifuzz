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

#include <cstdint>
#include <cstring>
#include <memory>
#include <new>
#include <string>
#include <tuple>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/hash/hash.h"
#include "absl/log/check.h"
#include "./common/mapped_memory_map.h"
#include "./common/memory_perms.h"
#include "./common/snapshot.h"
#include "./common/snapshot_util.h"
#include "./snap/gen/relocatable_data_block.h"
#include "./snap/gen/repeating_byte_runs.h"
#include "./snap/snap.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/mmapped_memory_ptr.h"
#include "./util/page_util.h"
#include "./util/reg_checksum.h"
#include "./util/reg_checksum_util.h"
#include "./util/ucontext/serialize.h"

namespace silifuzz {

namespace {

// Sets register in `*tgt` using `src`.
template <typename Arch>
void SetRegisterState(const Snapshot::RegisterState& src,
                      typename Snap<Arch>::RegisterState* tgt,
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
template <typename Arch>
class Traversal {
 public:
  Traversal(const RelocatableSnapGeneratorOptions& options)
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
  // Processes the data contained in `memory_bytes` for `pass`. Allocates a ref
  // element bytes of the generated SnapByteData. Returns element ref.
  RelocatableDataBlock::Ref ProcessMemoryBytes(
      PassType pass, const Snapshot::MemoryBytes& memory_bytes);

  // Processes `memory_mappings` for `pass`. Allocates a ref for the
  // elements of the SnapMemoryMapping array and returns it.
  RelocatableDataBlock::Ref ProcessMemoryMappings(
      PassType pass, const Snapshot::MemoryMappingList& memory_mappings,
      const BorrowedMappingBytesList& bytes_per_mapping);

  // Process a single memory mapping.
  void ProcessMemoryMapping(PassType pass,
                            const Snapshot::MemoryMapping& memory_mapping,
                            const BorrowedMemoryBytesList& memory_bytes_list,
                            RelocatableDataBlock::Ref memory_mapping_ref);

  // Processes a single Snapshot::MemoryBytes object `memory_bytes` for
  // `pass` using a preallocated ref from caller.
  void ProcessAllocated(PassType pass,
                        const Snapshot::MemoryBytes& memory_bytes,
                        RelocatableDataBlock::Ref memory_bytes_ref);

  // Processes a Snapshot::MemoryBytesList object `memory_bytes_list` for
  // `pass`. `mapped_memory_map` contains information of all memory mappings
  // in the source Snapshot. This allocates a ref the elements of the
  // SnapMemoryBytes array and returns it.
  RelocatableDataBlock::Ref ProcessMemoryBytesList(
      PassType pass, const BorrowedMemoryBytesList& memory_bytes_list);

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
  RelocatableDataBlock register_state_block_;
  RelocatableDataBlock page_data_block_;

  // Hash map for de-duping byte data.
  ByteDataRefMap byte_data_ref_map_;
};

template <typename Arch>
RelocatableDataBlock::Ref Traversal<Arch>::ProcessMemoryBytes(
    PassType pass, const Snapshot::MemoryBytes& memory_bytes) {
  const Snapshot::ByteData& byte_data = memory_bytes.byte_values();
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

  // The main reason for treating page aligned data separately is so we can mmap
  // it directly from the corpus file. When we process the bytes, however, we
  // throw all page-aligned page-sized data into same data block without regard
  // to if we actually want to mmap it. This makes the logic simpler (for
  // instance we don't need two byte data caches) and at most increases the
  // corpus size by less than 4kB due to fragmentation from the alignment
  // requirements.
  bool page_aligned_data = IsPageAligned(memory_bytes.start_address()) &&
                           IsPageAligned(memory_bytes.num_bytes());

  // Allocate a new Ref as this has not be seen before.
  if (page_aligned_data) {
    // If the data will be page aligned in memory, we also make it page aligned
    // inside the corpus so it can be directly mmaped if desired.
    // Note that we're using the same cache for both data blocks, and the cache
    // does not take alignment into account. For this to work, it must be
    // impossible for equivilent MemoryBytes to be stored with different
    // alignments.
    ref = page_data_block_.Allocate(byte_data.size(), kPageSize);
  } else {
    ref = byte_data_block_.Allocate(byte_data.size(), sizeof(uint64_t));
  }
  if (pass == PassType::kGeneration) {
    memcpy(ref.contents(), byte_data.data(), byte_data.size());
  }
  return ref;
}

template <typename Arch>
void Traversal<Arch>::ProcessMemoryMapping(
    PassType pass, const Snapshot::MemoryMapping& memory_mapping,
    const BorrowedMemoryBytesList& memory_bytes_list,
    RelocatableDataBlock::Ref memory_mapping_ref) {
  RelocatableDataBlock::Ref memory_bytes_elements_ref =
      ProcessMemoryBytesList(pass, memory_bytes_list);

  if (pass == PassType::kGeneration) {
    new (memory_mapping_ref
             .contents_as_pointer_of<SnapMemoryMapping>()) SnapMemoryMapping{
        .start_address = memory_mapping.start_address(),
        .num_bytes = memory_mapping.num_bytes(),
        .perms = memory_mapping.perms().ToMProtect(),
        .memory_bytes =
            {
                .size = memory_bytes_list.size(),
                .elements =
                    memory_bytes_elements_ref
                        .load_address_as_pointer_of<const SnapMemoryBytes>(),
            },
    };
  }
}

template <typename Arch>
RelocatableDataBlock::Ref Traversal<Arch>::ProcessMemoryMappings(
    PassType pass, const Snapshot::MemoryMappingList& memory_mappings,
    const BorrowedMappingBytesList& bytes_per_mapping) {
  // Allocate space for elements of SnapArray<MemoryMapping>.
  const RelocatableDataBlock::Ref snap_memory_mappings_array_elements_ref =
      memory_mapping_block_.AllocateObjectsOfType<SnapMemoryMapping>(
          memory_mappings.size());

  RelocatableDataBlock::Ref memory_mapping_ref =
      snap_memory_mappings_array_elements_ref;
  for (size_t i = 0; i < memory_mappings.size(); ++i) {
    ProcessMemoryMapping(pass, memory_mappings[i], bytes_per_mapping[i],
                         memory_mapping_ref);
    memory_mapping_ref += sizeof(SnapMemoryMapping);
  }

  return snap_memory_mappings_array_elements_ref;
}

template <typename Arch>
void Traversal<Arch>::ProcessAllocated(
    PassType pass, const Snapshot::MemoryBytes& memory_bytes,
    RelocatableDataBlock::Ref memory_bytes_ref) {
  const bool compress_repeating_bytes =
      options_.compress_repeating_bytes &&
      IsRepeatingByteRun(memory_bytes.byte_values());
  RelocatableDataBlock::Ref byte_values_elements_ref;
  if (!compress_repeating_bytes) {
    byte_values_elements_ref = ProcessMemoryBytes(pass, memory_bytes);
  }

  if (pass == PassType::kGeneration) {
    // Construct MemoryBytes in contents buffer.
    if (compress_repeating_bytes) {
      new (memory_bytes_ref.contents_as_pointer_of<SnapMemoryBytes>())
          SnapMemoryBytes{
              .start_address = memory_bytes.start_address(),
              .flags = SnapMemoryBytes::kRepeating,
              .data{.byte_run{
                  .value = memory_bytes.byte_values()[0],
                  .size = memory_bytes.num_bytes(),
              }},
          };
    } else {
      new (memory_bytes_ref.contents_as_pointer_of<SnapMemoryBytes>())
          SnapMemoryBytes{
              .start_address = memory_bytes.start_address(),
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

template <typename Arch>
RelocatableDataBlock::Ref Traversal<Arch>::ProcessMemoryBytesList(
    PassType pass, const BorrowedMemoryBytesList& memory_bytes_list) {
  // Allocate space for elements of SnapArray<MemoryBytes>.
  const RelocatableDataBlock::Ref ref =
      memory_bytes_block_.AllocateObjectsOfType<SnapMemoryBytes>(
          memory_bytes_list.size());

  RelocatableDataBlock::Ref snap_memory_bytes_ref = ref;
  for (const auto& memory_bytes : memory_bytes_list) {
    ProcessAllocated(pass, *memory_bytes, snap_memory_bytes_ref);
    snap_memory_bytes_ref += sizeof(SnapMemoryBytes);
  }
  return ref;
}

template <typename Arch>
void Traversal<Arch>::ProcessAllocated(PassType pass, const Snapshot& snapshot,
                                       RelocatableDataBlock::Ref snapshot_ref) {
  using RegisterState = typename Snap<Arch>::RegisterState;

  CHECK_EQ(static_cast<int>(snapshot.architecture_id()),
           static_cast<int>(Arch::architecture_id));
  size_t id_size = snapshot.id().size() + 1;  // NUL character terminator.
  RelocatableDataBlock::Ref id_ref = string_block_.Allocate(id_size, 1);

  BorrowedMappingBytesList bytes_per_mapping =
      SplitBytesByMapping(snapshot.memory_mappings(), snapshot.memory_bytes());
  RelocatableDataBlock::Ref memory_mappings_elements_ref =
      ProcessMemoryMappings(pass, snapshot.memory_mappings(),
                            bytes_per_mapping);
  // All input snapshots should be Snapify()-ed before they can be compiled.
  // This means exactly one expected end state.
  DCHECK_EQ(snapshot.expected_end_states().size(), 1);
  const Snapshot::EndState& end_state = snapshot.expected_end_states()[0];
  RelocatableDataBlock::Ref end_state_memory_bytes_elements_ref =
      ProcessMemoryBytesList(
          pass, ToBorrowedMemoryBytesList(end_state.memory_bytes()));

  RelocatableDataBlock::Ref registers_ref =
      register_state_block_.AllocateObjectsOfType<RegisterState>(1);
  RelocatableDataBlock::Ref end_state_registers_ref =
      register_state_block_.AllocateObjectsOfType<RegisterState>(1);

  if (pass == PassType::kGeneration) {
    memcpy(id_ref.contents(), snapshot.id().c_str(), snapshot.id().size() + 1);

    // Construct Snap in data block content buffer.
    // Fill in register states separately to avoid copying.
    Snap<Arch>* snap = snapshot_ref.contents_as_pointer_of<Snap<Arch>>();
    absl::StatusOr<RegisterChecksum<Arch>> register_checksum_or =
        DeserializeRegisterChecksum<Arch>(end_state.register_checksum());
    // TODO(dougkwan): Fail more gracefully.  We could report an absl::Status
    // but that requires changing the whole relocatable snap generator.
    CHECK_OK(register_checksum_or.status());
    new (snap) Snap<Arch>{
        .id = reinterpret_cast<const char*>(AsPtr(id_ref.load_address())),
        .memory_mappings{
            .size = snapshot.memory_mappings().size(),
            .elements =
                memory_mappings_elements_ref
                    .load_address_as_pointer_of<const SnapMemoryMapping>(),
        },
        .registers = registers_ref.load_address_as_pointer_of<RegisterState>(),
        .end_state_instruction_address =
            end_state.endpoint().instruction_address(),
        .end_state_registers =
            end_state_registers_ref.load_address_as_pointer_of<RegisterState>(),
        .end_state_memory_bytes{
            .size = end_state.memory_bytes().size(),
            .elements =
                end_state_memory_bytes_elements_ref
                    .load_address_as_pointer_of<const SnapMemoryBytes>(),
        },
        .end_state_register_checksum = register_checksum_or.value()};
    SetRegisterState<Arch>(
        snapshot.registers(),
        registers_ref.contents_as_pointer_of<RegisterState>(),
        /*allow_empty_register_state=*/false);
    // End state may be undefined initially in the making process.
    SetRegisterState<Arch>(
        end_state.registers(),
        end_state_registers_ref.contents_as_pointer_of<RegisterState>(),
        /*allow_empty_register_state=*/true);
  }
}

template <typename Arch>
void Traversal<Arch>::Process(PassType pass,
                              const std::vector<Snapshot>& snapshots) {
  // For compatiblity with an older Silifuzz version, we use a corpus containing
  // SnapArray<const Snap*>.  We can get rid of the redirection when we
  // change the runner to take SnapArray<Snap> later.

  RelocatableDataBlock::Ref corpus_ref =
      snap_block_.AllocateObjectsOfType<SnapCorpus<Arch>>(1);

  // Allocate space for element.
  RelocatableDataBlock::Ref snap_array_elements_ref =
      snap_block_.AllocateObjectsOfType<const Snap<Arch>*>(snapshots.size());

  // Allocate space for Snaps.
  RelocatableDataBlock::Ref snaps_ref =
      snap_block_.AllocateObjectsOfType<Snap<Arch>>(snapshots.size());
  for (size_t i = 0; i < snapshots.size(); ++i) {
    ProcessAllocated(pass, snapshots[i], snaps_ref + i * sizeof(Snap<Arch>));
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
  main_block_.Allocate(register_state_block_);
  main_block_.Allocate(page_data_block_);

  if (pass == PassType::kGeneration) {
    new (corpus_ref.contents()) SnapCorpus<Arch>{
        .magic = kSnapCorpusMagic,
        .corpus_type_size = sizeof(SnapCorpus<Arch>),
        .snap_type_size = sizeof(Snap<Arch>),
        .register_state_type_size = sizeof(typename Snap<Arch>::RegisterState),
        .architecture_id = static_cast<uint8_t>(Arch::architecture_id),
        .padding = {},
        .snaps =
            {
                .size = snapshots.size(),
                .elements =
                    snap_array_elements_ref
                        .load_address_as_pointer_of<const Snap<Arch>*>(),
            },
    };

    // Create const pointer array elements.
    for (size_t i = 0; i < snapshots.size(); ++i) {
      const RelocatableDataBlock::Ref snap_ref =
          snaps_ref + i * sizeof(Snap<Arch>);
      const RelocatableDataBlock::Ref element_ref =
          snap_array_elements_ref + i * sizeof(const Snap<Arch>*);
      *element_ref.contents_as_pointer_of<const Snap<Arch>*>() =
          snap_ref.load_address_as_pointer_of<const Snap<Arch>>();
    }
  }
}

template <typename Arch>
void Traversal<Arch>::PrepareSnapGeneration(char* content_buffer,
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
  prepare_sub_data_block(register_state_block_);
  prepare_sub_data_block(page_data_block_);

  // Reset main block again for generation pass.
  main_block_.ResetSizeAndAlignment();

  // Reset byte data de-duping hash map.
  byte_data_ref_map_.clear();
}

}  // namespace

template <typename Arch>
MmappedMemoryPtr<char> GenerateRelocatableSnapsImpl(
    const std::vector<Snapshot>& snapshots,
    const RelocatableSnapGeneratorOptions& options) {
  Traversal<Arch> traversal(options);
  traversal.Process(Traversal<Arch>::PassType::kLayout, snapshots);

  // Check that the whole corpus has alignment requirement not exceeding page
  // size of the runner since it will be mmap()'ed by the runner.
  CHECK_LE(traversal.main_block().required_alignment(), kPageSize);
  auto buffer = AllocateMmappedBuffer<char>(traversal.main_block().size());

  // Generate contents of the relocatable corpus as if it was to be loaded
  // at address 0. Runtime relocation can simply be done by adding the load
  // address of the corpus to every pointers inside the corpus.
  constexpr uintptr_t kNominalLoadAddress = 0;
  traversal.PrepareSnapGeneration(buffer.get(), MmappedMemorySize(buffer),
                                  kNominalLoadAddress);
  traversal.Process(Traversal<Arch>::PassType::kGeneration, snapshots);
  return buffer;
}

MmappedMemoryPtr<char> GenerateRelocatableSnaps(
    ArchitectureId architecture_id, const std::vector<Snapshot>& snapshots,
    const RelocatableSnapGeneratorOptions& options) {
  CHECK(architecture_id != ArchitectureId::kUndefined);
  return ARCH_DISPATCH(GenerateRelocatableSnapsImpl, architecture_id, snapshots,
                       options);
}

}  // namespace silifuzz
