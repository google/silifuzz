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

#include <stdint.h>

#include <utility>

#include "absl/container/flat_hash_map.h"
#include "./util/checks.h"
#include "./util/x86_cpuid.h"

namespace silifuzz {

namespace {

// Helpers to decode family, model and stepping information return by CPUID.
// Some are common for both AMD and Intel but model is decoded differently.

uint32_t DecodeFamily(uint32_t eax) {
  const uint32_t base_family = (eax >> 8) & 0xf;
  if (base_family != 15) return base_family;

  const uint32_t extended_family = (eax >> 20) & 0xff;
  return base_family + extended_family;
}

uint32_t DecodeIntelModel(uint32_t eax) {
  const uint32_t base_family = (eax >> 8) & 0xf;
  const uint32_t base_model = (eax >> 4) & 0xf;
  if (base_family != 6 && base_family != 15) return base_model;

  const uint32_t extended_model = (eax >> 16) & 0xf;
  return base_model + (extended_model << 4);
}

uint32_t DecodeAMDModel(uint32_t eax) {
  const uint32_t base_family = (eax >> 8) & 0xf;
  const uint32_t base_model = (eax >> 4) & 0xf;
  if (base_family != 15) return base_model;

  const uint32_t extended_model = (eax >> 16) & 0xf;
  return base_model + (extended_model << 4);
}

uint32_t DecodeStepping(uint32_t eax) { return eax & 0xf; }

PlatformId IntelPlatformId() {
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

    // TODO(dougkwan): add support for future Intel platforms as needed.
  }

  LOG_ERROR("Unknown Intel platform: family = ", family, " model = ", model,
            " stepping = ", stepping);
  return PlatformId::kUndefined;
}

PlatformId AmdPlatformId() {
  X86CPUIDResult result;
  X86CPUID(0x1, &result);  // get family, model and stepping.
  const uint32_t family = DecodeFamily(result.eax);
  const uint32_t model = DecodeAMDModel(result.eax);
  const uint32_t stepping = DecodeStepping(result.eax);

  if (family == 23 && (model == 48 || model == 49)) return PlatformId::kAmdRome;
  if (family == 25 && model <= 15) return PlatformId::kAmdMilan;
  if (family == 25 && (model >= 16 && model <= 31))
    return PlatformId::kAmdGenoa;
  if (family == 25 && (model >= 64 && model <= 79))
    return PlatformId::kAmdRyzenV3000;
  if (family == 25 && (model >= 160 && model <= 175))
    return PlatformId::kAmdSiena;

  // TODO(dougkwan): add support for future AMD platforms as needed.

  LOG_ERROR("Unknown AMD platform: family = ", family, " model = ", model,
            " stepping = ", stepping);
  return PlatformId::kUndefined;
}

// Returns platform Id of the current x86_64 platform.
PlatformId DoCurrentPlatformId() {
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

}  // namespace

uint32_t PlatformIdRegister() {
  X86CPUIDResult result;
  X86CPUID(0x1, &result);  // get family, model and stepping.
  return result.eax;
}

PlatformId CurrentPlatformId() {
  static const PlatformId x = DoCurrentPlatformId();
  return x;
}

}  // namespace silifuzz
