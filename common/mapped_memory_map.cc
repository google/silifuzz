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

#include "./common/mapped_memory_map.h"

#include "./common/memory_perms.h"
#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

MappedMemoryMap MappedMemoryMap::Copy() const {
  MappedMemoryMap r;
  r.rep_ = rep_;
  return r;
}

void MappedMemoryMap::Add(Address start_address, Address limit_address,
                          MemoryPerms perms) {
  DCHECK(!perms.IsEmpty());
  rep_.Add(start_address, limit_address, perms);
}

void MappedMemoryMap::Add(const MappedMemoryMap& y) {
  rep_.AddRangeMap(y.rep_);
}

void MappedMemoryMap::AddNew(Address start_address, Address limit_address,
                             MemoryPerms perms) {
  DCHECK(!Overlaps(start_address, limit_address));
  Add(start_address, limit_address, perms);
}

void MappedMemoryMap::Set(Address start_address, Address limit_address,
                          MemoryPerms perms) {
  DCHECK(!perms.IsEmpty());
  rep_.Remove(start_address, limit_address, MemoryPerms::AllPlusMapped());
  rep_.Add(start_address, limit_address, perms);
}

void MappedMemoryMap::Remove(Address start_address, Address limit_address,
                             MemoryPerms perms) {
  rep_.Remove(start_address, limit_address, perms);
}

void MappedMemoryMap::RemoveRangesOf(const MappedMemoryMap& y,
                                     MemoryPerms perms) {
  for (auto r = rep_.begin(); r != rep_.end();) {
    auto iter_range = y.rep_.Find(r.start(), r.limit());
    // rep_.Remove() below may invalidate `r` even if we did ++r before that,
    // so we remember the key and re-find it below.
    Address r_limit = r.limit();
    for (auto i = iter_range.first; i != iter_range.second; ++i) {
      rep_.Remove(i.start(), i.limit(), perms);
    }
    r = rep_.LowerBound(r_limit);
  }
}

void MappedMemoryMap::AddIntersectionOf(const MappedMemoryMap& x,
                                        const MappedMemoryMap& y) {
  rep_.AddIntersectionOf(x.rep_, y.rep_);
}

void MappedMemoryMap::AddDifferenceOf(Address start_address,
                                      Address limit_address, MemoryPerms perms,
                                      const MappedMemoryMap& y) {
  rep_.AddDifferenceOf(start_address, limit_address, perms, y.rep_);
}

void MappedMemoryMap::AddDifferenceOf(const MappedMemoryMap& x,
                                      const MappedMemoryMap& y) {
  rep_.AddDifferenceOf(x.rep_, y.rep_);
}

bool MappedMemoryMap::Contains(Address address) const {
  return rep_.FindAt(address) != rep_.end();
}

MemoryPerms MappedMemoryMap::PermsAt(Address address) const {
  auto it = rep_.FindAt(address);
  return it != rep_.end() ? it.value() : MemoryPerms::None();
}

std::optional<MemoryMapping> MappedMemoryMap::MappingAt(Address address) const {
  auto it = rep_.FindAt(address);
  if (it != rep_.end()) {
    MemoryPerms perms = it.value();
    perms.Clear(MemoryPerms::kMapped);
    return MemoryMapping::MakeRanged(it.start(), it.limit(), perms);
  } else {
    return std::nullopt;
  }
}

bool MappedMemoryMap::Contains(Address start_address,
                               Address limit_address) const {
  return rep_.Covers(start_address, limit_address,
                     [](Rep::const_iterator i) { return true; });
}

bool MappedMemoryMap::Overlaps(Address start_address,
                               Address limit_address) const {
  auto range = rep_.Find(start_address, limit_address);
  return range.first != range.second;  // found non-empty overlap
}

MemoryPerms MappedMemoryMap::Perms(Address start_address, Address limit_address,
                                   MemoryPerms::JoinMode mode) const {
  DCHECK_LE(start_address, limit_address);
  if (start_address >= limit_address) return MemoryPerms::None();
  MemoryPerms r = mode == MemoryPerms::kOr ? MemoryPerms::None()
                                           : MemoryPerms::AllPlusMapped();
  if (!rep_.Covers(start_address, limit_address,
                   [&r, mode](Rep::const_iterator i) {
                     r.Join(i.value(), mode);
                     return true;
                   })) {
    // rep_ did not cover all of [start_address, limit_address)
    r.Join(MemoryPerms::None(), mode);
  }
  return r;
}

std::string MappedMemoryMap::DebugString() const {
  std::string result;
  for (auto i = rep_.begin(); i != rep_.end(); ++i) {
    absl::StrAppend(&result, HexStr(i.start()), "..", HexStr(i.limit()), ":",
                    i.value().DebugString(), ", ");
  }
  return result;
}

}  // namespace silifuzz
