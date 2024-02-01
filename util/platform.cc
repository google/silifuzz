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

#include "absl/base/attributes.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/enum_flag.h"
#include "./util/itoa.h"
#include "./util/misc_util.h"

namespace silifuzz {

template <>
ABSL_CONST_INIT const char* EnumNameMap<PlatformId>[ToInt(kMaxPlatformId) +
                                                    1] = {
    "UNDEFINED-PLATFORM", "intel-skylake", "intel-haswell", "intel-broadwell",
    "intel-ivybridge", "intel-cascadelake", "amd-rome", "intel-icelake",
    "amd-milan", "intel-sapphirerapids", "amd-genoa", "intel-coffeelake",
    "intel-alderlake", "arm-neoverse-n1", "ampere-one", "intel-emeraldrapids",
    "amd-ryzen-v3000",
    "ANY-PLATFORM", "NON-EXISTENT-PLATFORM",
};

// An arbitrary name, only used internally.
ABSL_CONST_INIT const char* kShortPlatformNames[ToInt(kMaxPlatformId) + 1] = {
    "UNDEF",
    "skylk",
    "haswl",
    "broadwl",
    "ivybrdg",
    "cascdlk",
    "rome",
    "icelk",
    "milan",
    "sapprpds",
    "genoa",
    "coffeelk",
    "alderlk",
    "neovn1",
    "ampone",
    "emerrpds",
    "ryzenv3000",
    "ANY",
    "NEXST",
};

const char* ShortPlatformName(PlatformId platform) {
  return kShortPlatformNames[ToInt(platform)];
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
      return ArchitectureId::kX86_64;
    case PlatformId::kArmNeoverseN1:
    case PlatformId::kAmpereOne:
      return ArchitectureId::kAArch64;
    case PlatformId::kUndefined:
    case PlatformId::kAny:
    case PlatformId::kNonExistent:
      LOG_FATAL("Tried to get architecture for meta-platform ID: ",
                EnumStr(platform));
  }

  // Doing this here instead of as a default: case so -Werror,-Wswitch can catch
  // missing platforms at compile time.
  LOG_FATAL("Architecture not listed for platform ID: ", EnumStr(platform));
}

}  // namespace silifuzz
