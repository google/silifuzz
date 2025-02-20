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

namespace silifuzz {

namespace {

uint64_t GetMidr() {
  uint64_t midr;
  // The kernel will trap and emulate access to MIDR_EL1.
  // https://www.kernel.org/doc/Documentation/arm64/cpu-feature-registers.txt
  asm("mrs %0, MIDR_EL1" : "=r"(midr));
  return midr;
}

PlatformId DoCurrentPlatformId() {
  uint64_t midr = GetMidr();

  uint32_t implementer = (midr >> 24) & 0xff;
  // uint32_t variant = (midr >> 20) & 0xf;
  uint32_t part_number = (midr >> 4) & 0xfff;
  // uint32_t revision = midr & 0xf;
  return internal::ArmPlatformIdFromMainId(implementer, part_number);
}

}  // namespace

uint32_t PlatformIdRegister() { return static_cast<uint32_t>(GetMidr()); }

PlatformId CurrentPlatformId() {
  static const PlatformId x = DoCurrentPlatformId();
  return x;
}

}  // namespace silifuzz
