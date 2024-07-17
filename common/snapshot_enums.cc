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

#include "./common/snapshot_enums.h"

#include "./util/checks.h"

namespace silifuzz {
namespace snapshot_types {

Endpoint::Endpoint(Address instruction_address)
    : type_(kInstruction), instruction_address_(instruction_address) {}

Endpoint::Endpoint(SigNum sig_num, SigCause sig_cause, Address sig_address,
                   Address sig_instruction_address)
    : type_(kSignal),
      sig_num_(sig_num),
      sig_cause_(sig_cause),
      sig_address_(sig_address),
      instruction_address_(sig_instruction_address) {
  DCHECK_EQ(sig_cause != kGenericSigCause, sig_num == kSigSegv);
}

bool Endpoint::operator==(const Endpoint& y) const {
  switch (type_) {
    case kInstruction:
      return type_ == y.type_ && instruction_address_ == y.instruction_address_;
    case kSignal:
      return type_ == y.type_ && sig_num_ == y.sig_num_ &&
             sig_cause_ == y.sig_cause_ && sig_address_ == y.sig_address_ &&
             instruction_address_ == y.instruction_address_;
  }
}

Address Endpoint::instruction_address() const {
  DCHECK(type_ == kInstruction);
  return instruction_address_;
}

SigNum Endpoint::sig_num() const {
  DCHECK(type_ == kSignal);
  return sig_num_;
}

SigCause Endpoint::sig_cause() const {
  DCHECK(type_ == kSignal);
  return sig_cause_;
}

Address Endpoint::sig_address() const {
  DCHECK(type_ == kSignal);
  return sig_address_;
}

Address Endpoint::sig_instruction_address() const {
  DCHECK(type_ == kSignal);
  return instruction_address_;
}

}  // namespace snapshot_types

}  // namespace silifuzz
