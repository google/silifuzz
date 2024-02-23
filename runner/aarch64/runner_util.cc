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

#include <signal.h>

#include "./common/snapshot_enums.h"
#include "./runner/endspot.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/ucontext/aarch64/esr.h"
#include "./util/ucontext/signal.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {

using snapshot_types::Endpoint;
using snapshot_types::SigCause;
using snapshot_types::SigNum;

SigCause SigSegvCause(const SignalRegSet& sigregs) {
  ESR esr = {sigregs.esr};
  if (esr.IsDataAbort()) {
    DataAbortISS iss = esr.GetDataAbortISS();
    if (iss.WriteNotRead()) {
      return Endpoint::kSegvCantWrite;
    } else {
      return Endpoint::kSegvCantRead;
    }
  } else if (esr.IsInstructionAbort()) {
    return Endpoint::kSegvCantExec;
  }
  return SigCause::kGenericSigCause;
}

std::optional<Endpoint> EndSpotToEndpoint(const EndSpot& actual_endspot) {
  auto pc = actual_endspot.gregs->GetInstructionPointer();
  switch (actual_endspot.signum) {
    case 0:  // there was no signal.
      return Endpoint(pc);
    case SIGTRAP: {
      // Unlike x86, the instruction pointer will point to the head of the
      // instruction causing the trap, not the tail. There is no need to adjust
      // the instruction pointer.
      return Endpoint(SigNum::kSigTrap, actual_endspot.sig_address, pc);
    }
    case SIGSEGV: {
      SigCause cause = SigSegvCause(actual_endspot.sigregs);
      return Endpoint(Endpoint::kSigSegv, cause, actual_endspot.sig_address,
                      pc);
    }
    case SIGFPE: {
      return Endpoint(Endpoint::kSigFPE, actual_endspot.sig_address, pc);
    }
    case SIGILL: {
      return Endpoint(Endpoint::kSigIll, actual_endspot.sig_address, pc);
    }
    case SIGBUS: {
      // TODO: decode unaligned instruction and stack faults?
      return Endpoint(Endpoint::kSigBus, actual_endspot.sig_address, pc);
    }
    case SIGXCPU:
    case SIGALRM: {
      // a runaway; endpoint is where it got stopped
      return Endpoint(pc);
    }
    default:
      LOG_ERROR("Unsupported signal-based endpoint: signal=",
                IntStr(actual_endspot.signum));
      return std::nullopt;
  }
}

}  // namespace silifuzz
