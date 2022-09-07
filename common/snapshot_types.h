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

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TYPES_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TYPES_H_

#include "./common/snapshot.h"

namespace silifuzz {

// SnapshotTypeNames is a class that defines the type names for various
// public nested types of Snapshot.
//
// We have several classes that deal with Snapshot data and thus its nested
// types, which we don't want to make silifuzz-scoped types.
// Inheriting from this otherwise empty class is a convenient way
// to bring in all the type names, that is cleaner than adding the needed using
// declarations into those classes or prefixing all uses of the types
// with Snapshot::. Unfortunately "using namespace" is forbidden inside classes.
//
// Making the inheritance private ensures that one won't be able to type-convert
// any of those unrelated classes to SnapshotTypeNames. The Snapshot::Foo types
// are still visible in public parts of a derived class even with private
// inheritance. Protected inheritance needs to be used for classes from which
// other clases are derived -- see e.g. SnapshotSource.
class SnapshotTypeNames {
 public:
  using Id = Snapshot::Id;
  using Address = Snapshot::Address;
  using ByteSize = Snapshot::ByteSize;
  using ByteData = Snapshot::ByteData;
  using Byte = Snapshot::Byte;
  using Architecture = Snapshot::Architecture;
  using MemoryMapping = Snapshot::MemoryMapping;
  using MemoryMappingList = Snapshot::MemoryMappingList;
  using MemoryBytes = Snapshot::MemoryBytes;
  using MemoryBytesList = Snapshot::MemoryBytesList;
  using MemoryBytesSet = Snapshot::MemoryBytesSet;
  using RegisterState = Snapshot::RegisterState;
  using Endpoint = Snapshot::Endpoint;
  using EndState = Snapshot::EndState;
  using EndStateList = Snapshot::EndStateList;
  using Metadata = Snapshot::Metadata;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TYPES_H_
