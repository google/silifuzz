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

#include "./util/platform.h"

#include <cstdint>

#include "absl/container/flat_hash_map.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

ArchitectureId PlatformArchitectureOrDie(PlatformId platform) {
  ArchitectureId arch = PlatformArchitecture(platform);
  if (arch == ArchitectureId::kUndefined) {
    LOG_FATAL("Undefined architecture for platform: ", EnumStr(platform));
  }
  return arch;
}

ArchitectureId PlatformArchitecture(PlatformId platform) {
  switch (platform) {
    case PlatformId::kIntelSkylake:
    case PlatformId::kIntelHaswell:
    case PlatformId::kIntelBroadwell:
    case PlatformId::kIntelIvybridge:
    case PlatformId::kIntelCascadelake:
    case PlatformId::kAmdRome:
    case PlatformId::kIntelIcelake:
    case PlatformId::kAmdMilan:
    case PlatformId::kIntelSapphireRapids:
    case PlatformId::kAmdGenoa:
    case PlatformId::kIntelCoffeelake:
    case PlatformId::kIntelAlderlake:
    case PlatformId::kIntelEmeraldRapids:
    case PlatformId::kAmdRyzenV3000:
    case PlatformId::kIntelGraniteRapids:
    case PlatformId::kAmdSiena:
      return ArchitectureId::kX86_64;
    case PlatformId::kArmNeoverseN1:
    case PlatformId::kArmNeoverseV2:
    case PlatformId::kAmpereOne:
      return ArchitectureId::kAArch64;
    case PlatformId::kUndefined:
    case PlatformId::kAny:
    case PlatformId::kNonExistent:
    default:
      return ArchitectureId::kUndefined;
  }
}

namespace internal {

PlatformId IntelPlatformIdFromCpuId(uint32_t family, uint32_t model,
                                    uint32_t stepping) {
  if (family == 6) {
    // Mostly we can just map a model into a platform.
    // Reference: https://en.wikichip.org/wiki/intel/cpuid#Family_6
    static const absl::flat_hash_map<uint32_t, PlatformId> platform_id_map{
        {60, PlatformId::kIntelHaswell},    // Haswell Client
        {61, PlatformId::kIntelBroadwell},  // Broadwell Client
        {62, PlatformId::kIntelIvybridge},
        {63, PlatformId::kIntelHaswell},    // Haswell Server
        {69, PlatformId::kIntelHaswell},    // Haswell Client
        {70, PlatformId::kIntelHaswell},    // Haswell Client
        {71, PlatformId::kIntelBroadwell},  // Broadwell Client
        // Model 78 and 94 are Skylake client. Unlike the server variants, they
        // don't support AVX512. To support these chips, we'd need to
        // distinguish between Skylake client and server chips.
        {79, PlatformId::kIntelBroadwell},  // Broadwell
        {86, PlatformId::kIntelBroadwell},  // Broadwell DE
        {106, PlatformId::kIntelIcelake},   // Icelake Server
        {108, PlatformId::kIntelIcelake},   // Icelake Server
        {125, PlatformId::kIntelIcelake},   // Icelake Client
        {126, PlatformId::kIntelIcelake},   // Icelake Client
        // Coffeelake and Kabylake share the same CPU model but have
        // different stepping (Kabylake stepping <= 9) similar to
        // Skylake/Cascadelake. It's not clear if there's a difference between
        // the two cores from our standpoint.
        {142, PlatformId::kIntelCoffeelake},  // Also Kabylake
        {143, PlatformId::kIntelSapphireRapids},
        {151, PlatformId::kIntelAlderlake},
        {154, PlatformId::kIntelAlderlake},
        {158, PlatformId::kIntelCoffeelake},  // Also Kabylake
        {173, PlatformId::kIntelGraniteRapids},
        {207, PlatformId::kIntelEmeraldRapids},
    };

    auto it = platform_id_map.find(model);
    if (it != platform_id_map.end()) {
      return it->second;
    }

    // Skylake and Cascadelake Xeon.  These share the same model number.
    if (model == 85) {
      return (stepping < 5) ? PlatformId::kIntelSkylake
                            : PlatformId::kIntelCascadelake;
    }
  }

  LOG_ERROR("Unknown Intel platform: family = ", family, " model = ", model,
            " stepping = ", stepping);
  return PlatformId::kUndefined;
}

PlatformId AmdPlatformIdFromCpuId(uint32_t family, uint32_t model,
                                  uint32_t stepping) {
  if (family == 23 && (model == 48 || model == 49)) return PlatformId::kAmdRome;
  if (family == 25 && model <= 15) return PlatformId::kAmdMilan;
  if (family == 25 && (model >= 16 && model <= 31))
    return PlatformId::kAmdGenoa;
  if (family == 25 && (model >= 64 && model <= 79))
    return PlatformId::kAmdRyzenV3000;
  if (family == 25 && (model >= 160 && model <= 175))
    return PlatformId::kAmdSiena;

  LOG_ERROR("Unknown AMD platform: family = ", family, " model = ", model,
            " stepping = ", stepping);
  return PlatformId::kUndefined;
}
}  // namespace internal

}  // namespace silifuzz
