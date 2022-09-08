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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_AARCH64_ESR_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_AARCH64_ESR_H_

#include <cstdint>

#include "./util/checks.h"

namespace silifuzz {

// The exception classes, as described in the manual.
// Note: we're defining them as binary values so it's easier to match them to
// the docs.
// Note: aarch32-specific features, BTI, SVE, and other stuff we don't expect to
// encounter yet have been elided.
// Note: not using a scoped enum to make bit manipulation and comparisons
// easier. If be cast the actual exception class to this enum, this can invoke
// undefined behavior because it doesn't cover all possible values.
// See:
// https://developer.arm.com/documentation/ddi0595/2020-12/AArch64-Registers/ESR-EL1--Exception-Syndrome-Register--EL1-
struct ExceptionClass {
  enum Type : uint8_t {
    kUnknown = 0b000000U,
    kInstructionAbortLowerLevel = 0b100000,
    kInstructionAbortSameLevel = 0b100001,
    kPCAlignmentFault = 0b100010,
    kDataAbortLowerLevel = 0b100100,
    kDataAbortSameLevel = 0b100101,
    kSPAlignmentFault = 0b100110,
  };
};

// Some of the exception classes come in pairs. These pairs are similar and we
// can generally treat them the same way.
// Sometimes the exception class specifies if the exception came from a lower
// level or the same level. In this case kLevelBit will be set if it comes from
// the same level, and cleared if it does not. For userspace / EL0, exceptions
// should always be coming from a lower level (they are caught in the kernel /
// EL1). To make the exception class names pedantically correct we define both
// cases and then ignore kLevelBit at the interface level. This lets the
// interface use names like "DataAbort" rather than "DataAbortLowerLevel" while
// letting the ExceptionClass definition match the manual.
struct ExceptionClassBits {
  enum Type : uint8_t {
    kLevelBit = 0b1,
  };
};

// Cross check that LevelBit appears to be defined correctly.
static_assert(ExceptionClass::kInstructionAbortLowerLevel ==
              (ExceptionClass::kInstructionAbortSameLevel &
               ~ExceptionClassBits::kLevelBit));
static_assert(ExceptionClass::kDataAbortLowerLevel ==
              (ExceptionClass::kDataAbortSameLevel &
               ~ExceptionClassBits::kLevelBit));

// Base class for wrapping Instruction Specific Syndrome values.
// Not intended to be instantiated.
struct ISS {
  uint32_t value;
};

struct DataAbortISS : ISS {
  bool FARNotValid() const { return (value >> 10) & 0x1; }

  bool WriteNotRead() const { return (value >> 6) & 0x1; }
};

struct InstructionAbortISS : ISS {
  bool FARNotValid() const { return (value >> 10) & 0x1; }
};

// A datatype to help decode the Exception Syndrome Register
struct ESR {
  uint64_t value;

  // The exception class of the ESR.
  uint8_t ExceptionClass() const { return (value >> 26) & 0x3f; }

  // Is this a 32-bit instruction?
  // Only valid for synchonous exceptions.
  bool InstructionLength() const { return (value >> 25) & 0x1; }

  // The Instruction Specific Syndrome bits of the ESR. How these are
  // interpreted depends on the particular ESR.
  uint32_t ISS() const { return static_cast<uint32_t>(value & 0x1ffffff); }

  // In this case ISS should be zero.
  bool IsUnknown() const {
    return ExceptionClass() == ExceptionClass::kUnknown;
  }

  bool IsInstructionAbort() const {
    return (ExceptionClass() & ~ExceptionClassBits::kLevelBit) ==
           ExceptionClass::kInstructionAbortLowerLevel;
  }

  InstructionAbortISS GetInstructionAbortISS() const {
    CHECK(IsInstructionAbort());
    return InstructionAbortISS{ISS()};
  }

  bool IsDataAbort() const {
    return (ExceptionClass() & ~ExceptionClassBits::kLevelBit) ==
           ExceptionClass::kDataAbortLowerLevel;
  }

  DataAbortISS GetDataAbortISS() const {
    CHECK(IsDataAbort());
    return DataAbortISS{ISS()};
  }

  // In this case ISS should be zero.
  bool IsPCAlignmentFault() const {
    return ExceptionClass() == ExceptionClass::kPCAlignmentFault;
  }

  // In this case ISS should be zero.
  bool IsSPAlignmentFault() const {
    return ExceptionClass() == ExceptionClass::kSPAlignmentFault;
  }
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_UCONTEXT_AARCH64_ESR_H_
