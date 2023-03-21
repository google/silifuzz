// Copyright 2023 The SiliFuzz Authors.
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

#include "./runner/endspot.h"

#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/logging_util.h"

namespace silifuzz {

void EndSpot::Log() const {
  LOG_INFO("Signal: ", IntStr(signum));
  LOG_INFO("sig_address: ", HexStr(sig_address));
  SignalRegSet base = {};
  LogSignalRegs(sigregs, &base);
  if (VLOG_IS_ON(0)) {
    LOG_INFO("CPU registers (non-0 only):");
    gregs_t base = {};
    LogGRegs(*gregs, &base);
  }
  if (VLOG_IS_ON(1)) {
    LOG_INFO("FP registers (non-0 only):");
    fpregs_t base = {};
    LogFPRegs(*fpregs, true, &base);
  }
}

}  // namespace silifuzz
