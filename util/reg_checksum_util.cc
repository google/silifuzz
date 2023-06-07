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

#include "./util/reg_checksum_util.h"

#include "./util/arch.h"
#include "./util/reg_checksum.h"

namespace silifuzz {

namespace {

// Returns true iff 'data' is a valid RegisterChecksum of 'Arch'
template <typename Arch>
bool IsValidRegisterChecksumImpl(const std::string& data) {
  absl::StatusOr<RegisterChecksum<Arch>> register_checksum_or =
      DeserializeRegisterChecksum<Arch>(data);
  return register_checksum_or.ok();
}

}  // namespace

bool IsValidRegisterChecksumForArch(ArchitectureId arch,
                                    const std::string& data) {
  return ARCH_DISPATCH(IsValidRegisterChecksumImpl, arch, data);
}

}  // namespace silifuzz
