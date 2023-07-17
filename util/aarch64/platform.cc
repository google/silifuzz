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

#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

namespace {

PlatformId DoCurrentPlatformId() {
  uint64_t midr;
  // The kernel will trap and emulate access to MIDR_EL1.
  // https://www.kernel.org/doc/Documentation/arm64/cpu-feature-registers.txt
  asm("mrs %0, MIDR_EL1" : "=r"(midr));

  uint32_t implementer = (midr >> 24) & 0xff;
  // uint32_t variant = (midr >> 20) & 0xf;
  uint32_t part_number = (midr >> 4) & 0xfff;
  // uint32_t revision = midr & 0xf;

  if (implementer == 0x41) {
    // This means the core is ARM IP. Different SoCs may use the same IP.
    if (part_number == 0xd0c) {
      return PlatformId::kArmNeoverseN1;
    } else {
      LOG_ERROR("Unknown ARM part number: ", HexStr(part_number));
      return PlatformId::kUndefined;
    }
  } else if (implementer == 0xc0) {
    // Ampere Computing
    if (part_number == 0xac3) {
      return PlatformId::kAmpereOne;
    } else {
      LOG_ERROR("Unknown ARM part number: ", HexStr(part_number));
      return PlatformId::kUndefined;
    }
  } else {
    LOG_ERROR("Unknown implementer: ", HexStr(implementer));
    return PlatformId::kUndefined;
  }
}

}  // namespace

PlatformId CurrentPlatformId() {
  static const PlatformId x = DoCurrentPlatformId();
  return x;
}

}  // namespace silifuzz
