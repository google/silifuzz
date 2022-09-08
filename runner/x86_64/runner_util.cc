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
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/ucontext/ucontext.h"
#include "./util/x86_traps.h"

namespace silifuzz {

using snapshot_types::Endpoint;
using snapshot_types::EndSpot;
using snapshot_types::SigCause;
using snapshot_types::SigNum;

std::optional<Endpoint> EndSpotToEndpoint(const EndSpot& actual_endspot) {
  switch (actual_endspot.signum) {
    case 0:  // there was no signal.
      return Endpoint(GetInstructionPointer(actual_endspot.gregs));
    case SIGTRAP: {
      CHECK_EQ(actual_endspot.sigregs.err, 0x0);
      // RIP advances to the following insn on trap. The expected trap insn
      // size is 1 byte (size of int3) so we subtract 1 from the current RIP.
      // If the alternate int3 encoding was used (\xCD\x03), this code will
      // return an incorrect instruction address and the produced snapshot
      // won't replay.
      if (actual_endspot.sigregs.trapno == X86Exception::X86_TRAP_BP) {
        return Endpoint(SigNum::kSigTrap, actual_endspot.sig_address,
                        GetInstructionPointer(actual_endspot.gregs) - 1);
      }
      LOG_ERROR("Unsupported SIGTRAP endpoint: trapno=",
                IntStr(actual_endspot.sigregs.trapno));
      return std::nullopt;
    }
    case SIGSEGV: {
      const uintptr_t trap_no = actual_endspot.sigregs.trapno;
      SigCause cause = SigCause::kGenericSigCause;
      if (trap_no == X86Exception::X86_TRAP_PF) {
        // Decode reg_err bits into the specific set of cases. See X86PFError
        // comments for details.
        constexpr uintptr_t mask = X86PFError::PF_WRITE_BIT |
                                   X86PFError::PF_USER_BIT |
                                   X86PFError::PF_INSTR_BIT;
        const uintptr_t reg_err_bits = actual_endspot.sigregs.err & mask;
        switch (reg_err_bits) {
          case X86PFError::PF_INSTR_BIT | X86PFError::PF_USER_BIT:
            cause = Endpoint::kSegvCantExec;
            break;
          case X86PFError::PF_WRITE_BIT | X86PFError::PF_USER_BIT:
            cause = Endpoint::kSegvCantWrite;
            break;
          case X86PFError::PF_USER_BIT:
            cause = Endpoint::kSegvCantRead;
            break;
          default:
            LOG_ERROR("Unhandled SIGSEGV (#PF); reg_err bits: ",
                      HexStr(actual_endspot.sigregs.err),
                      " actual_endspot.sig_address = ",
                      HexStr(actual_endspot.sig_address));
            return std::nullopt;
        }
      } else if (trap_no == X86Exception::X86_TRAP_GP) {
        cause = Endpoint::kSegvGeneralProtection;
      } else if (trap_no == X86Exception::X86_TRAP_OF) {
        cause = Endpoint::kSegvOverflow;
      } else {
        LOG_ERROR("Unhandled SIGSEGV trap_no = ", HexStr(trap_no),
                  ", reg_err = ", HexStr(actual_endspot.sigregs.err));
        return std::nullopt;
      }
      return Endpoint(Endpoint::kSigSegv, cause, actual_endspot.sig_address,
                      GetInstructionPointer(actual_endspot.gregs));
    }
    case SIGFPE: {
      CHECK_EQ(actual_endspot.sigregs.err, 0);
      return Endpoint(Endpoint::kSigFPE, actual_endspot.sig_address,
                      GetInstructionPointer(actual_endspot.gregs));
    }
    case SIGILL: {
      CHECK_EQ(actual_endspot.sigregs.err, 0);
      return Endpoint(Endpoint::kSigIll, actual_endspot.sig_address,
                      GetInstructionPointer(actual_endspot.gregs));
    }
    case SIGBUS: {
      CHECK_EQ(actual_endspot.sigregs.err, 0);
      return Endpoint(Endpoint::kSigBus, actual_endspot.sig_address,
                      GetInstructionPointer(actual_endspot.gregs));
    }
    case SIGXCPU:
    case SIGALRM: {
      // a runaway; endpoint is the rip where it got stopped
      return Endpoint(GetInstructionPointer(actual_endspot.gregs));
    }
    default:
      LOG_ERROR("Unsupported signal-based endpoint: signal=",
                IntStr(actual_endspot.signum));
      return std::nullopt;
  }
}

}  // namespace silifuzz
