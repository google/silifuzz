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
  return internal::IntelPlatformIdFromCpuId(family, model, stepping);
}

PlatformId AmdPlatformId() {
  X86CPUIDResult result;
  X86CPUID(0x1, &result);  // get family, model and stepping.
  const uint32_t family = DecodeFamily(result.eax);
  const uint32_t model = DecodeAMDModel(result.eax);
  const uint32_t stepping = DecodeStepping(result.eax);
  return internal::AmdPlatformIdFromCpuId(family, model, stepping);
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
