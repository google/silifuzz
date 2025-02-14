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

}  // namespace silifuzz
