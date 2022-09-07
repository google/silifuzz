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

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_MEMORY_MAPPING_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_MEMORY_MAPPING_H_

#include <string>

#include "absl/status/status.h"
#include "./common/memory_perms.h"
#include "./common/snapshot_enums.h"

namespace silifuzz {

// Describes a single contiguous page-aligned memory mapping.
class MemoryMapping {
 public:
  // Type for a memory address (instructions or data inside a snapshot).
  using Address = snapshot_types::Address;
  static constexpr Address kMaxAddress = snapshot_types::kMaxAddress;

  // Type for a size (a non-negative difference between two `Address`es).
  using ByteSize = snapshot_types::ByteSize;

  // Returns iff making MemoryMapping from these is valid:
  // num_bytes needs to be positive.
  static absl::Status CanMakeSized(Address start_address,
                                   ByteSize num_bytes) ABSL_MUST_USE_RESULT;
  static ABSL_MUST_USE_RESULT absl::Status CanMakeRanged(
      Address start_address, Address limit_address) {
    return CanMakeSized(start_address, limit_address - start_address);
  }

  // Makes MemoryMapping with the given permissions.
  // REQUIRES: CanMakeSized(start_address, num_bytes)
  //           `perms` does not have kMapped
  // Note though that Snapshot::can_add_memory_mapping() and
  // Snapshot::can_add_negative_memory_mapping() do not accept MemoryMapping-s
  // with empty perms.
  //
  // Address and ByteSize are the same type currently, so we introduce different
  // factory names, not c-tor overloads to support both cases and prevent
  // wrong calls.
  static MemoryMapping MakeSized(Address start_address, ByteSize num_bytes,
                                 MemoryPerms perms) {
    return MemoryMapping(start_address, num_bytes, perms);
  }
  static MemoryMapping MakeRanged(Address start_address, Address limit_address,
                                  MemoryPerms perms) {
    return MemoryMapping(start_address, limit_address - start_address, perms);
  }

  // Intentionally movable and copyable.

  bool operator==(const MemoryMapping& y) const;
  bool operator!=(const MemoryMapping& y) const { return !(*this == y); }

  // Start address, limit address and size of this mapping:
  // [start_address, limit_address) address range.
  Address start_address() const { return start_address_; }
  Address limit_address() const { return start_address_ + num_bytes_; }
  ByteSize num_bytes() const { return num_bytes_; }

  // PROVIDES: `perms` does not have kMapped
  const MemoryPerms& perms() const { return perms_; }

  // REQUIRES: `perms` does not have kMapped
  void set_perms(MemoryPerms perms);

  // For logging.
  std::string DebugString() const;

 private:
  // C-tor implementing MakeSized().
  MemoryMapping(Address start_address, ByteSize num_bytes, MemoryPerms perms);

  // See start_address().
  Address start_address_;

  // See num_bytes().
  ByteSize num_bytes_;

  // The permissions.
  MemoryPerms perms_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_MEMORY_MAP_H_
