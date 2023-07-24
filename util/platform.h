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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_PLATFORM_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_PLATFORM_H_

#include "./util/arch.h"
#include "./util/enum_flag.h"
#include "./util/misc_util.h"

namespace silifuzz {

// Corresponds to proto::PlatformId including the storage-stable enum values.
// silifuzz/common/snapshot_proto.cc checks this.
enum class PlatformId {
  kUndefined = 0,
  kIntelSkylake = 1,
  kIntelHaswell = 2,
  kIntelBroadwell = 3,
  kIntelIvybridge = 4,
  kIntelCascadelake = 5,
  kAmdRome = 6,
  kIntelIcelake = 7,
  kAmdMilan = 8,
  kIntelSapphireRapids = 9,
  kAmdGenoa = 10,
  kIntelCoffeelake = 11,
  kIntelAlderlake = 12,
  kArmNeoverseN1 = 13,
  kAmpereOne = 14,
  kIntelEmeraldRapids = 15,
  // The values below are meta-values that don't have proto::PlatformId
  // representation. Never persisted and can be renumbered as needed.
  kAny = 16,          // any platform for platform selectors
  kNonExistent = 17,  // for tests only
};

DECLARE_ENUM_FLAG(PlatformId);

// Max valid value of PlatformId, min being kUndefined.
constexpr PlatformId kMaxPlatformId = PlatformId::kNonExistent;

// EnumStr() works for PlatformId.
template <>
extern const char* EnumNameMap<PlatformId>[ToInt(kMaxPlatformId) + 1];

// A short name for PlatformId that is unique and still human-readable.
const char* ShortPlatformName(PlatformId platform);

// Returns the PlatformId of where this code runs on or kUndefined if
// we don't have a needed PlatformId value defined or it can't be determined.
PlatformId CurrentPlatformId();

ArchitectureId PlatformArchitecture(PlatformId platform);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_PLATFORM_H_
