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

#include <sys/utsname.h>

#include <cerrno>

#include "absl/container/flat_hash_map.h"
#include "./util/checks.h"
#include "./util/enum_flag.h"

#ifdef __x86_64__
#include "./util/x86_cpuid.h"
#endif

namespace silifuzz {

template <>
ABSL_CONST_INIT const char* EnumNameMap<PlatformId>[ToInt(kMaxPlatformId) + 1] =
    {
        "UNDEFINED-PLATFORM",
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
        "ANY-PLATFORM",
        "NON-EXISTENT-PLATFORM",
};

DEFINE_ENUM_FLAG(PlatformId);

ABSL_CONST_INIT const char* kShortPlatformNames[ToInt(kMaxPlatformId) + 1] = {
    "UNDEF",   "skylk",    "haswl",   "broadwl", "ivybrdg",
    "cascdlk", "rome",     "icelk",   "milan",   "sapprpds",
    "genoa",   "coffeelk", "alderlk", "ANY",     "NEXST",
};

const char* ShortPlatformName(PlatformId platform) {
  return kShortPlatformNames[ToInt(platform)];
}

#ifdef __x86_64__

// Helpers to decode family, model and stepping information return by CPUID.
// Some are common for both AMD and Intel but model is decoded differently.

static uint32_t DecodeFamily(uint32_t eax) {
  const uint32_t base_family = (eax >> 8) & 0xf;
  if (base_family != 15) return base_family;

  const uint32_t extended_family = (eax >> 20) & 0xff;
  return base_family + extended_family;
}

static uint32_t DecodeIntelModel(uint32_t eax) {
  const uint32_t base_family = (eax >> 8) & 0xf;
  const uint32_t base_model = (eax >> 4) & 0xf;
  if (base_family != 6 && base_family != 15) return base_model;

  const uint32_t extended_model = (eax >> 16) & 0xf;
  return base_model + (extended_model << 4);
}

static uint32_t DecodeAMDModel(uint32_t eax) {
  const uint32_t base_family = (eax >> 8) & 0xf;
  const uint32_t base_model = (eax >> 4) & 0xf;
  if (base_family != 15) return base_model;

  const uint32_t extended_model = (eax >> 16) & 0xf;
  return base_model + (extended_model << 4);
}

static uint32_t DecodeStepping(uint32_t eax) { return eax & 0xf; }

static PlatformId IntelPlatformId() {
  X86CPUIDResult result;
  X86CPUID(0x1, &result);  // get family, model and stepping.
  const uint32_t family = DecodeFamily(result.eax);
  const uint32_t model = DecodeIntelModel(result.eax);
  const uint32_t stepping = DecodeStepping(result.eax);
  if (family == 6) {
    // Mostly we can just map a model into a platform.
    static const absl::flat_hash_map<uint32_t, PlatformId> platform_id_map{
        {60, PlatformId::kIntelHaswell},  // Haswell Client
        {62, PlatformId::kIntelIvybridge},
        {63, PlatformId::kIntelHaswell},    // Haswell Server
        {79, PlatformId::kIntelBroadwell},  // Broadwell
        {86, PlatformId::kIntelBroadwell},  // Broadwell DE
        {106, PlatformId::kIntelIcelake},
        {125, PlatformId::kIntelIcelake},  // Icelake Client
        {126, PlatformId::kIntelIcelake},  // Icelake Client
        // Coffeelake and Kabylake share the same CPU model but have
        // different stepping (Kabylake stepping <= 9) similar to
        // Skylake/Cascadelake. It's not clear if there's a difference between
        // the two cores from our standpoint.
        {142, PlatformId::kIntelCoffeelake},  // Also Kabylake
        {143, PlatformId::kIntelSapphireRapids},
        {151, PlatformId::kIntelAlderlake},
        {154, PlatformId::kIntelAlderlake},
        {158, PlatformId::kIntelCoffeelake},  // Also Kabylake
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

    // TODO(dougkwan): add support for future Intel platforms as needed.
  }

  LOG_ERROR("Unknown Intel platform: family = ", family, " model = ", model,
            " stepping = ", stepping);
  return PlatformId::kUndefined;
}

static PlatformId AmdPlatformId() {
  X86CPUIDResult result;
  X86CPUID(0x1, &result);  // get family, model and stepping.
  const uint32_t family = DecodeFamily(result.eax);
  const uint32_t model = DecodeAMDModel(result.eax);
  const uint32_t stepping = DecodeStepping(result.eax);

  if (family == 23 && (model == 48 || model == 49)) return PlatformId::kAmdRome;
  if (family == 25 && model <= 15) return PlatformId::kAmdMilan;
  if (family == 25 && (model >= 16 && model <= 31))
    return PlatformId::kAmdGenoa;
  // TODO(dougkwan): add support for future AMD platforms as needed.

  LOG_ERROR("Unknown AMD platform: family = ", family, " model = ", model,
            " stepping = ", stepping);
  return PlatformId::kUndefined;
}

// Returns platform Id of the current x86_64 platform.
static PlatformId X86PlatformId() {
  const X86CPUVendorID vendor_id;
  if (vendor_id.IsIntel()) {
    return IntelPlatformId();
  } else if (vendor_id.IsAMD()) {
    return AmdPlatformId();
  } else {
    LOG_ERROR("Unknown x86_64 vendor: ", vendor_id.get());
    return PlatformId::kUndefined;
  }
}
#else
static PlatformId X86PlatformId() {
  LOG_FATAL("Checking x86_64 platform ID on a non-x86_64 platform.");
  return PlatformId::kUndefined;
}
#endif

static PlatformId DoCurrentPlatformId() {
  struct utsname buf;
  if (uname(&buf) != 0) {
    LOG_ERROR("uname() failed: ", strerror(errno));
    return PlatformId::kUndefined;
  }

  if (strcmp(buf.machine, "x86_64") == 0) {
    return X86PlatformId();
  } else {
    LOG_ERROR("Unknown machine: ", buf.machine);
    return PlatformId::kUndefined;
  }
}

PlatformId CurrentPlatformId() {
  static const PlatformId x = DoCurrentPlatformId();
  return x;
}

}  // namespace silifuzz
