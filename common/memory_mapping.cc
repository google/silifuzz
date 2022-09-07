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

#include "./common/memory_mapping.h"

#include "absl/strings/str_cat.h"
#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

// static
absl::Status MemoryMapping::CanMakeSized(Address start_address,
                                         ByteSize num_bytes) {
  if (num_bytes <= 0) {
    return absl::InvalidArgumentError("Non-positive num_bytes");
  }
  if (snapshot_types::kMaxAddress - num_bytes < start_address) {
    return absl::InvalidArgumentError(
        absl::StrCat("start_address ", HexStr(start_address), " + num_bytes ",
                     HexStr(num_bytes), " is too large"));
  }
  return absl::OkStatus();
}

MemoryMapping::MemoryMapping(Address start_address, ByteSize num_bytes,
                             MemoryPerms perms)
    : start_address_(start_address), num_bytes_(num_bytes), perms_(perms) {
  DCHECK_STATUS(CanMakeSized(start_address_, num_bytes_));
  DCHECK(!perms.Has(MemoryPerms::kMapped));
}

bool MemoryMapping::operator==(const MemoryMapping& y) const {
  return start_address_ == y.start_address_ && num_bytes_ == y.num_bytes_ &&
         perms_ == y.perms_;
}

void MemoryMapping::set_perms(MemoryPerms perms) {
  DCHECK(!perms.Has(MemoryPerms::kMapped));
  perms_ = perms;
}

std::string MemoryMapping::DebugString() const {
  return absl::StrCat(HexStr(start_address()), "..", HexStr(limit_address()),
                      ":", perms().DebugString());
}

}  // namespace silifuzz
