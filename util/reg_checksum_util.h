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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_REG_CHECKSUM_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_REG_CHECKSUM_UTIL_H_

#include <unistd.h>

#include <algorithm>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "./util/reg_checksum.h"

namespace silifuzz {

// Deserializes 'data' into a RegisterChecksum<Arch> struct. Returns a struct or
// an error status.  If 'data' is empty, returns a checksum with an empty
// register group set and a checksum value of 0.
template <typename Arch>
absl::StatusOr<RegisterChecksum<Arch>> DeserializeRegisterChecksum(
    const std::string& data) {
  RegisterChecksum<Arch> register_checksum{};
  if (data.empty()) {
    return register_checksum;
  }
  ssize_t bytes_consumed =
      Deserialize(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
                  register_checksum);
  if (bytes_consumed == -1) {
    constexpr size_t kMaxBytes = 32;
    const size_t len = std::min(data.size(), kMaxBytes);
    std::string hex_repl;
    for (size_t i = 0; i < len; ++i) {
      hex_repl += absl::StrFormat("%02x", data[i]);
    }
    if (len < data.size()) hex_repl += "...";
    return absl::InvalidArgumentError(
        absl::StrCat("Cannot deserialize register checksum bytes: ", hex_repl));
  }
  return register_checksum;
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_REG_CHECKSUM_UTIL_H_
