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

#include <cstdint>

#include "./util/arch.h"
#include "./util/itoa.h"
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
  kReserved16 = 16,
  kAmdRyzenV3000 = 17,
  kReserved18 = 18,
  kReserved19 = 19,

  kReserved20 = 20,
  kReserved21 = 21,
  kReserved22 = 22,
  kReserved23 = 23,
  kReserved24 = 24,
  kReserved25 = 25,
  kReserved26 = 26,
  kReserved27 = 27,
  kReserved28 = 28,
  kReserved29 = 29,
  kReserved30 = 30,
  kReserved31 = 31,
  kReserved32 = 32,
  kReserved33 = 33,
  kReserved34 = 34,
  kReserved35 = 35,
  kReserved36 = 36,
  kReserved37 = 37,
  kReserved38 = 38,
  kReserved39 = 39,
  kReserved40 = 40,

  kIntelGraniteRapids = 41,
  kAmdSiena = 42,
  kArmNeoverseV2 = 43,
  kAmdTurin = 44,
  kArmNeoverseN3 = 45,
  kArmNeoverseN2 = 46,
  // The values below are meta-values that don't have proto::PlatformId
  // representation. Never persisted and can be renumbered as needed.
  kAny = 47,          // any platform for platform selectors
  kNonExistent = 48,  // for tests only
};

// Max valid value of PlatformId, min being kUndefined.
inline constexpr PlatformId kMaxPlatformId = PlatformId::kNonExistent;

// EnumStr() works for PlatformId.
template <>
inline constexpr const char* EnumNameMap<PlatformId>[ToInt(kMaxPlatformId) +
                                                     1] = {
    "UNDEFINED-PLATFORM-ID",
    "intel-skylake",
    "intel-haswell",
    "intel-broadwell",
    "intel-ivybridge",
    "intel-cascadelake",
    "amd-rome",
    "intel-icelake",
    "amd-milan",
    "intel-sapphirerapids",
    "amd-genoa",
    "intel-coffeelake",
    "intel-alderlake",
    "arm-neoverse-n1",
    "ampere-one",
    "intel-emeraldrapids",
    "reserved-16",
    "amd-ryzen-v3000",
    "reserved-18", "reserved-19",
    "reserved-20",
    "reserved-21",
    "reserved-22",
    "reserved-23",
    "reserved-24",
    "reserved-25",
    "reserved-26",
    "reserved-27",
    "reserved-28",
    "reserved-29",
    "reserved-30",
    "reserved-31",
    "reserved-32",
    "reserved-33",
    "reserved-34",
    "reserved-35",
    "reserved-36",
    "reserved-37",
    "reserved-38",
    "reserved-39",
    "reserved-40",
    "intel-graniterapids",
    "amd-siena",
    "arm-neoverse-v2",
    "amd-turin",
    "arm-neoverse-n3",
    "arm-neoverse-n2",
    "ANY-PLATFORM",
    "NON-EXISTENT-PLATFORM",
};

// Returns the PlatformId of where this code runs on or kUndefined if
// we don't have a needed PlatformId value defined or it can't be determined.
PlatformId CurrentPlatformId();

// The raw data used to derive CurrentPlatformId.
// Useful for dumping the info we need on platforms we don't support, yet.
// Currently this us a uint32_t on every arch, but we may need to migrate to
// arch-specific structs in the future.
uint32_t PlatformIdRegister();

ArchitectureId PlatformArchitecture(PlatformId platform);

// Same as above, but crashes fatally if the platform is undefined. Prefer to
// use this variant in production code to avoid silent errors.
ArchitectureId PlatformArchitectureOrDie(PlatformId platform);

namespace internal {
// These functions are exposed for testing purposes only.
PlatformId IntelPlatformIdFromCpuId(uint32_t family, uint32_t model,
                                    uint32_t stepping);
PlatformId AmdPlatformIdFromCpuId(uint32_t family, uint32_t model,
                                  uint32_t stepping);
PlatformId ArmPlatformIdFromMainId(uint32_t implementer, uint32_t part_number);
}  // namespace internal

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_PLATFORM_H_
