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

#include "./common/memory_bytes_set.h"

#include <utility>

namespace silifuzz {

MemoryBytesSet::ByteSize MemoryBytesSet::byte_size() const {
  ByteSize size = 0;
  for (auto i = rep_.begin(); i != rep_.end(); ++i) {
    size += i.limit() - i.start();
  }
  return size;
}

void MemoryBytesSet::Add(Address start_address, Address limit_address) {
  rep_.Add(start_address, limit_address, kDummyMappedValue);
}

void MemoryBytesSet::Add(const MemoryBytesSet& y) { rep_.AddRangeMap(y.rep_); }

void MemoryBytesSet::Remove(Address start_address, Address limit_address) {
  rep_.Remove(start_address, limit_address, false /* value does not matter */);
}

void MemoryBytesSet::Intersect(const MemoryBytesSet& y) {
  Rep intersection;
  intersection.AddIntersectionOf(rep_, y.rep_);
  rep_ = std::move(intersection);
}

bool MemoryBytesSet::IsDisjoint(Address start_address,
                                Address limit_address) const {
  auto range = rep_.Find(start_address, limit_address);
  return range.first == range.second;  // empty overlap
}

}  // namespace silifuzz
