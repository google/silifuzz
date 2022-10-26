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

#include "./common/memory_state.h"

#include "./common/snapshot_util.h"
#include "./util/checks.h"

namespace silifuzz {

template <>
ABSL_CONST_INIT const char*
    EnumNameMap<MemoryState::MemoryMappingCmd::Action>[3] = {
        "mmap",
        "mprotect",
        "munmap",
};

std::string MemoryState::MemoryMappingCmd::DebugString() const {
  return absl::StrCat(MemoryMapping::DebugString(), " ", EnumStr(action_));
}

// ----------------------------------------------------------------------- //

// static
MemoryState MemoryState::MakeInitial(const Snapshot& snapshot,
                                     MappedZeroing mapped_zeroing) {
  MemoryState r;
  r.SetInitialState(snapshot, mapped_zeroing);
  return r;
}

// static
MemoryState MemoryState::MakeEnd(const Snapshot& snapshot, int end_state_index,
                                 MappedZeroing mapped_zeroing) {
  DCHECK_GE(end_state_index, 0);
  DCHECK_LT(end_state_index, snapshot.expected_end_states().size());
  MemoryState r;
  r.AddNewMemoryMappings(snapshot.memory_mappings());
  if (mapped_zeroing == kZeroMappedBytes) {
    // No filtering of what is zeroed is needed here: all mappings of
    // `snapshot` are new in `r`. Contrast with SetInitialState() below.
    r.ZeroMappedMemoryBytes(snapshot);
  }
  r.SetMemoryBytes(snapshot);
  r.SetMemoryBytes(snapshot.expected_end_states()[end_state_index]);
  return r;
}

// ----------------------------------------------------------------------- //

MemoryState::MemoryState()
    : mapped_memory_map_(), written_memory_set_(), written_memory_bytes_() {}

MemoryState::~MemoryState() {}

MemoryState MemoryState::Copy() const {
  MemoryState r;
  r.mapped_memory_map_ = mapped_memory_map_.Copy();
  r.written_memory_set_ = written_memory_set_;
  r.written_memory_bytes_ = written_memory_bytes_;
  return r;
}

bool MemoryState::operator==(const MemoryState& y) const {
  return mapped_memory_map_ == y.mapped_memory_map_ &&
         written_memory_bytes_ ==
             y.written_memory_bytes_;  // covers written_memory_set_
}

bool MemoryState::MemoryBytesEq(const MemoryState& y) const {
  return written_memory_bytes_ == y.written_memory_bytes_;
}

bool MemoryState::IsEmpty() const {
  // mapped_memory_map_.IsEmpty() actually implies the rest.
  return mapped_memory_map_.IsEmpty() && written_memory_set_.empty() &&
         written_memory_bytes_.empty();
}

// ----------------------------------------------------------------------- //

void MemoryState::AddNewMemoryMapping(const MemoryMapping& mapping) {
  DCHECK(!mapping.perms().IsEmpty());
  // MemoryMapping provides this:
  DCHECK(!mapping.perms().Has(MemoryPerms::kMapped));
  mapped_memory_map_.AddNew(mapping.start_address(), mapping.limit_address(),
                            mapping.perms().Plus(MemoryPerms::kMapped));
}

void MemoryState::SetMemoryMapping(const MemoryMapping& mapping) {
  DCHECK(!mapping.perms().IsEmpty());
  SetMemoryMappingEmptyPermsOk(mapping);
}

void MemoryState::SetMemoryMappingEmptyPermsOk(const MemoryMapping& mapping) {
  // MemoryMapping provides this:
  DCHECK(!mapping.perms().Has(MemoryPerms::kMapped));
  mapped_memory_map_.Set(mapping.start_address(), mapping.limit_address(),
                         mapping.perms().Plus(MemoryPerms::kMapped));
}

void MemoryState::RemoveMemoryMapping(Address start_address,
                                      Address limit_address) {
  mapped_memory_map_.Remove(start_address, limit_address);
  written_memory_set_.Remove(start_address, limit_address);
  written_memory_bytes_.Remove(start_address, limit_address, ByteData());
}

void MemoryState::RemoveMemoryMappingsNotIn(const Snapshot& snapshot) {
  MappedMemoryMap extra_mappings = mapped_memory_map_.Copy();
  extra_mappings.RemoveRangesOf(snapshot.mapped_memory_map());
  extra_mappings.Iterate(
      [this](Address start, Address limit, MemoryPerms perms) {
        RemoveMemoryMapping(start, limit);
      });
}

void MemoryState::ClearMemoryMappingsPermsNotIn(const Snapshot& snapshot) {
  MappedMemoryMap extra_mappings = mapped_memory_map_.Copy();
  extra_mappings.RemoveRangesOf(snapshot.mapped_memory_map());
  extra_mappings.Iterate(
      [this](Address start, Address limit, MemoryPerms perms) {
        mapped_memory_map_.Remove(start, limit, MemoryPerms::All());
      });
}

void MemoryState::SetMemoryBytes(const MemoryBytes& bytes) {
  DCHECK(mapped_memory_map_.Contains(bytes.start_address(),
                                     bytes.limit_address()));
  written_memory_set_.Add(bytes.start_address(), bytes.limit_address());
  written_memory_bytes_.Add(bytes.start_address(), bytes.limit_address(),
                            bytes.byte_values());
}

void MemoryState::ForgetMemoryBytes(Address start_address,
                                    Address limit_address) {
  written_memory_bytes_.Remove(start_address, limit_address, ByteData());
}

void MemoryState::SetMemoryBytes(const Snapshot& snapshot) {
  SetMemoryBytes(snapshot.memory_bytes());
}

void MemoryState::ZeroMappedMemoryBytes(const MemoryMapping& mapping) {
  DCHECK(!mapping.perms().IsEmpty());
  SetMemoryBytes(MemoryBytes(mapping.start_address(),
                             ByteData(mapping.num_bytes(), '\0')));
}

void MemoryState::SetInitialState(const Snapshot& snapshot,
                                  MappedZeroing mapped_zeroing) {
  MappedMemoryMap new_mappings = snapshot.mapped_memory_map().Copy();
  new_mappings.RemoveRangesOf(mapped_memory_map_);
  for (const auto& m : snapshot.memory_mappings()) {
    SetMemoryMapping(m);
  }
  // Remove permissions in mapped_memory_map_ that are in the negative
  // mappings in `snapshot` -- see DeltaMemoryMappings() for similar logic.
  {
    MappedMemoryMap filtered_negative =
        snapshot.negative_mapped_memory_map().Copy();
    // Exclude parts where positive mappings overlap negative --
    // SetMemoryMappings() above already took care of those address ranges:
    filtered_negative.RemoveRangesOf(snapshot.mapped_memory_map());
    MappedMemoryMap delta;
    delta.AddIntersectionOf(mapped_memory_map_, filtered_negative);
    // `delta` now contains parts of mapped_memory_map_ where `snapshot`
    // cares not to have certain permissions, we next remove those perms:
    delta.Iterate([this](Address start, Address limit, MemoryPerms perms) {
      // This holds because snapshot.negative_mapped_memory_map() did not
      // have these and we intersected with it:
      DCHECK(!perms.Has(MemoryPerms::kMapped));
      // Hence this Remove() may leave an entry in mapped_memory_map_
      // with just MemoryPerms::kMapped set, but never remove it completely:
      mapped_memory_map_.Remove(start, limit, perms);
    });
  }
  if (mapped_zeroing == kZeroMappedBytes) {
    // This is like ZeroMappedMemoryBytes(snapshot), but only for the mappings
    // in `snapshot` that did not exist before this SetInitialState() call:
    new_mappings.Iterate(
        [this](Address start, Address limit, MemoryPerms perms) {
          SetMemoryBytes(MemoryBytes(start, ByteData(limit - start, '\0')));
        });
  }
  SetMemoryBytes(snapshot);
}

// ----------------------------------------------------------------------- //

const MappedMemoryMap& MemoryState::mapped_memory() const {
  return mapped_memory_map_;
}

const MemoryState::MemoryBytesSet& MemoryState::written_memory() const {
  return written_memory_set_;
}

MemoryState::ByteSize MemoryState::num_written_bytes() const {
  return written_memory_set_.byte_size();
}

char MemoryState::memory_byte(Address address) const {
  return memory_bytes(address, 1)[0];
}

MemoryState::ByteData MemoryState::memory_bytes(Address start_address,
                                                ByteSize num_bytes) const {
  const auto limit_address = start_address + num_bytes;
  auto iters = written_memory_bytes_.Find(start_address, limit_address);
  // Precondition: exactly one range covers the request:
  DCHECK(iters.first != written_memory_bytes_.end());
  auto it = iters.first;
  if (DEBUG_MODE) ++iters.first;  // for the next DCHECK
  DCHECK(iters.first == iters.second);
  // Precondition: it covers the request fully:
  DCHECK_LE(it.start(), start_address);
  DCHECK_LE(limit_address, it.limit());
  return ByteData(it.value().data() + start_address - it.start(), num_bytes);
}

MemoryState::MemoryBytesList MemoryState::memory_bytes_list(
    const MemoryBytesSet& bytes) const {
  MemoryBytesList r;
  bytes.Iterate([this, &r](Address start, Address limit) {
    r.emplace_back(start, memory_bytes(start, limit - start));
  });
  return r;
}

// ----------------------------------------------------------------------- //

MemoryState::MemoryMappingCmdList MemoryState::DeltaMemoryMapping(
    const MemoryMapping& mapping, MemoryPerms added_perms) const {
  auto m = mapping;
  m.set_perms(m.perms().Plus(added_perms));
  DCHECK(!m.perms().IsEmpty());
  if (mapped_memory_map_.IsEmpty()) {
    return {MemoryMappingCmd(m, MemoryMappingCmd::kMap)};
  }
  // Compute and produce the difference of mapped_memory_map_ from m,
  // which is `mapping` with added_perms:
  MappedMemoryMap delta;
  // Also setting kMapped allows us to properly handle the mapped_memory_map_
  // entries with just kMapped set in them:
  const auto m_perms = m.perms().Plus(MemoryPerms::kMapped);
  delta.AddDifferenceOf(m.start_address(), m.limit_address(), m_perms,
                        mapped_memory_map_);
  MemoryMappingCmdList result;
  // Parts of `m` that are already in mapped_memory_map_ with exactly
  // m_perms will not be in `delta`.
  delta.Iterate(
      [&m, m_perms, &result](Address start, Address limit, MemoryPerms perms) {
        auto d = MemoryMapping::MakeRanged(start, limit, m.perms());
        if (perms == m_perms) {  // nothing of m was in mapped_memory_map_:
                                 // the latter always has at least kMapped set
          result.emplace_back(d, MemoryMappingCmd::kMap);
        } else {  // mapped_memory_map_ had something of m with perms != m_perms
          result.emplace_back(d, MemoryMappingCmd::kProtect);
        }
      });
  return result;
}

MemoryState::MemoryMappingCmdList MemoryState::DeltaMemoryMappings(
    const Snapshot& snapshot, MemoryPerms added_perms) const {
  MemoryMappingCmdList result;
  for (const auto& m : snapshot.memory_mappings()) {
    for (MemoryMappingCmd& x : DeltaMemoryMapping(m, added_perms)) {
      result.emplace_back(std::move(x));
    }
  }
  if (!snapshot.negative_memory_mappings().empty()) {
    if (mapped_memory_map_.IsEmpty()) {
      // No need to do anything about snapshot.negative_memory_mappings().
      // If they overlap with snapshot.memory_mappings(), Snapshot construction
      // made sure the perms from negative_memory_mappings() are not in
      // memory_mappings().
      // Otherwise, since nothing was mapped at all, we have
      // snapshot.negative_memory_mappings() not mapped,
      // i.e. have no perms at all for them.
    } else {
      // Handle snapshot.negative_memory_mappings(): the ranges not in
      // snapshot.memory_mappings() that are inside mapped_memory_map_ and
      // have perms that they should not have, need those perms removed.

      MappedMemoryMap filtered_negative =
          snapshot.negative_mapped_memory_map().Copy();
      // Exclude parts where positive mappings overlap negative --
      // DeltaMemoryMapping() calls at the top of this function already
      // took care of those address ranges:
      filtered_negative.RemoveRangesOf(snapshot.mapped_memory_map());
      MappedMemoryMap delta;
      delta.AddIntersectionOf(mapped_memory_map_, filtered_negative);
      // `delta` now contains parts of mapped_memory_map_ where `snapshot`
      // cares not to have certain permissions, we next generate commands
      // to remove those perms:
      delta.Iterate(
          [&result, this](Address start, Address limit, MemoryPerms perms) {
            // Keep as much existing perms as possible in hopes of minimizing
            // future changes:
            auto p = mapped_memory_map_.Perms(start, limit, MemoryPerms::kAnd);
            p.Clear(perms);
            p.Clear(MemoryPerms::kMapped);  // to satisfy MemoryMapping c-tor
            auto d = MemoryMapping::MakeRanged(start, limit, p);
            result.emplace_back(d, MemoryMappingCmd::kProtect);
          });
    }
  }
  return result;
}

MemoryState::MemoryMappingCmdList MemoryState::DeltaMemoryMappingsExact(
    const Snapshot& snapshot, MemoryPerms added_perms,
    ExactnessMode mode) const {
  MemoryMappingCmdList result;
  // Same logic as in DeltaMemoryMappings(snapshot, added_perms),
  // up to handling of snapshot.negative_memory_mappings():
  for (const auto& m : snapshot.memory_mappings()) {
    for (MemoryMappingCmd& x : DeltaMemoryMapping(m, added_perms)) {
      result.emplace_back(std::move(x));
    }
  }
  if (!mapped_memory_map_.IsEmpty()) {
    // Unmap or unprotect anything in mapped_memory_map_ that is not in the
    // ranges of snapshot.mapped_memory_map():
    MappedMemoryMap to_remove = mapped_memory_map_.Copy();
    to_remove.RemoveRangesOf(snapshot.mapped_memory_map());
    to_remove.Iterate([&result, mode](Address start, Address limit,
                                      MemoryPerms perms) {
      switch (mode) {
        case kUnmapUnused: {
          constexpr auto irrelevant_perms = MemoryPerms::R();
          auto d = MemoryMapping::MakeRanged(start, limit, irrelevant_perms);
          result.emplace_back(d, MemoryMappingCmd::kUnmap);
          break;
        }
        case kProtectUnused: {
          if (perms.HasSomeOf(MemoryPerms::All())) {
            auto d =
                MemoryMapping::MakeRanged(start, limit, MemoryPerms::None());
            result.emplace_back(d, MemoryMappingCmd::kProtect);
          }
          break;
        }
      }
    });
  }
  return result;
}

// Helper for DeltaMemoryBytes():
// Adds `size` bytes at `addr` in `bytes` to existing `chunk` or
// pushes `chunk` into `result` and makes new `chunk`.
//
// static
inline void MemoryState::GrowResultChunk(const MemoryBytes& bytes, Address addr,
                                         size_t size,
                                         std::optional<MemoryBytes>& chunk,
                                         MemoryBytesList& result) {
  // Minimum number of bytes that match after a mismatching byte which are
  // required to start a new entry in the returned MemoryBytesList.
  // Value of 8*2-1 means that we never split-up sequences of differing
  // int64_t words when for each of which only some bytes differ.
  // A sufficiently large value here is important e.g. so that we don't
  // generate end-states with very finely chopped up descriptions.
  // 1 is smallest valid value: corresponds to "never skip-over".
  static constexpr int kMinSkipOverBytes = 8 * 2 - 1;

  const auto& byte_values = bytes.byte_values();
  auto offset = addr - bytes.start_address();  // offset into byte_values
  if (!chunk.has_value()) {
    chunk = MemoryBytes(addr, ByteData(byte_values.data() + offset, size));
  } else if (chunk.value().limit_address() == addr) {
    chunk.value().mutable_byte_values()->append(byte_values, offset, size);
  } else {
    DCHECK_LT(chunk.value().limit_address(), addr);
    if (addr - chunk.value().limit_address() < kMinSkipOverBytes) {
      // Too few unchanged bytes from the last `chunk` to skip,
      // so we append all the bytes from chunk's end to `addr` and then
      // `size` more bytes:
      chunk.value().mutable_byte_values()->append(
          byte_values, chunk.value().limit_address() - bytes.start_address(),
          addr - chunk.value().limit_address() + size);
    } else {
      result.push_back(std::move(chunk).value());
      chunk = MemoryBytes(addr, ByteData(byte_values.data() + offset, size));
    }
  }
}

MemoryState::MemoryBytesList MemoryState::DeltaMemoryBytes(
    const MemoryBytes& bytes) const {
  // We do not check that `bytes` is in mapped_memory_map_ here, so that our
  // callers can generate both memory mapping and memory-writing commands in
  // one shot and then adjust MemoryState in one shot via SetInitialState().
  if (false) {
    DCHECK(mapped_memory_map_.Contains(bytes.start_address(),
                                       bytes.limit_address()));
  }

  if (written_memory_bytes_.empty()) return {bytes};

  // Let's do the work to pass-through parts of `bytes` that differ or missing
  // from written_memory_bytes_.

  auto iters =
      written_memory_bytes_.Find(bytes.start_address(), bytes.limit_address());
  auto it = iters.first;
  const auto end_it = iters.second;
  if (it == written_memory_bytes_.end()) {
    // `bytes` is comletely not in written_memory_bytes_
    return {bytes};
  }
  const auto& byte_values = bytes.byte_values();

  // TODO(ksteuck): [perf] Should be more efficient to compare `bytes` to
  // written_memory_bytes_ int64_t-at-a-time in this function to begin with.
  // Can probably make all MemoryBytes int64_t-aligned and
  // multiple-of-int64_t-sized for this.

  // TODO(ksteuck): [perf] Even more efficient would be a separate range-based
  // representation for the subset of MemoryBytesList-s where all byte values
  // are 0. For the current corpus 99.98% of equal bytes evaluated by
  // DeltaMemoryBytes() are 0 bytes. With a range-based representation we'll
  // do work proportional to the # of ranges, not to the number of 0 bytes in
  // the snapshots. The abundance of 0 bytes in snapshots comes from the fact
  // that we need to map whole 4K pages and then define byte values for complete
  // page data, while the code or data in a snapshot is a very small portion
  // of a page.
  // This perf optimization is important: silifuzz_checker binary spends about
  // 25% of its CPU in DeltaMemoryBytes() for the current corpus.

  // TODO(ksteuck): [perf] New idea that works even if the compared bytes are
  // not 0: In Snapshot-s to be played and in MemoryState have a checksum
  // map covering power-of-two-boundary memory ranges that cover all
  // MemoryBytes. The largest ranges are page-sized, the smallest ones can be
  // chosen by perf tuning all this. Then in this function we start comparing
  // those checksums starting from the largest ranges and then subdivide
  // recursively when checksums differ. This way, whole equal pages will be
  // skipped in O(1) time and we'll effectively skip subportions of pages
  // when e.g. only a few bytes at the start of a page differ.
  // Checksums for larger ranges can be made by combining checksums for the
  // component halves, thus making all checksum preparation/updating efficient.
  // See also and update b/180951719 if executing these todos.

  MemoryBytesList result;
  std::optional<MemoryBytes> chunk  // next candidate to add to `result`
      = std::nullopt;
  for (Address addr = bytes.start_address(); addr < bytes.limit_address();) {
    // Loop invariant: `it` is the range in written_memory_bytes_ that
    // covers `addr` if any such range exists.
    std::optional<Byte> old_byte =
        (it.start() <= addr && addr < it.limit())
            ? std::optional<Byte>(it.value().data()[addr - it.start()])
            : std::nullopt;
    Byte new_byte = byte_values[addr - bytes.start_address()];
    if (!old_byte.has_value() || old_byte.value() != new_byte) {
      // Pass new_byte through: append to existing chunk or start a new chunk.
      GrowResultChunk(bytes, addr, 1, chunk, result);
    }
    // Advance `addr` and if necessay `it`:
    ++addr;
    if (addr >= it.limit()) {
      DCHECK_EQ(addr, it.limit());
      ++it;
      if (it == end_it) {
        // Nothing else overlaps with written_memory_bytes_, so we pass the
        // remainder of `bytes` through.
        auto tail_size = byte_values.size() - (addr - bytes.start_address());
        if (tail_size != 0) {
          GrowResultChunk(bytes, addr, tail_size, chunk, result);
        }
        break;
      }
    }
  }
  if (chunk.has_value()) {
    result.push_back(std::move(chunk).value());
  }
  return result;
}

MemoryState::MemoryBytesList MemoryState::DeltaMemoryBytes(
    const MemoryBytesList& bytes) const {
  if (DEBUG_MODE) {  // DCHECK disjointness of `bytes`
    MemoryBytesSet bytes_set;
    for (const auto& b : bytes) {
      CHECK(bytes_set.IsDisjoint(b.start_address(), b.limit_address()));
      bytes_set.Add(b.start_address(), b.limit_address());
    }
  }
  MemoryBytesList r;
  for (const auto& b : bytes) {
    for (MemoryBytes& x : DeltaMemoryBytes(b)) {
      r.emplace_back(std::move(x));
    }
  }
  return r;
}

MemoryState::MemoryBytesList MemoryState::DeltaMemoryBytes(
    const Snapshot& snapshot) const {
  MemoryBytesList r;
  for (const auto& b : snapshot.memory_bytes()) {
    for (MemoryBytes& x : DeltaMemoryBytes(b)) {
      r.emplace_back(std::move(x));
    }
  }
  return r;
}

// static
MemoryState::MemoryBytes MemoryState::RestoreUContextStackBytes(
    const Snapshot& snapshot) {
  GRegSet gregs;
  CHECK_STATUS(ConvertRegsFromSnapshot(snapshot.registers(), &gregs));
  static constexpr auto reg_size = sizeof(gregs.rax);
  std::string stack_data;
  stack_data.append(reinterpret_cast<const char*>(&gregs.eflags), reg_size);
  stack_data.append(reinterpret_cast<const char*>(&gregs.rip), reg_size);
  return MemoryBytes(gregs.rsp - stack_data.size(), stack_data);
}

}  // namespace silifuzz
