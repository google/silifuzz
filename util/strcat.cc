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

#include "./util/strcat.h"

#include <initializer_list>

#include "absl/strings/string_view.h"
#include "./util/checks.h"

namespace silifuzz {

namespace strcat_internal {

// Based on absl::strings_internal::CatPieces.
void CatPieces(std::initializer_list<absl::string_view> pieces, char* out,
               int max_string_length) {
  size_t total_size = 0;
  for (const absl::string_view& piece : pieces) total_size += piece.size();
  if (total_size > max_string_length) {
    LOG_FATAL("MaxLength too small");
  }

  for (const absl::string_view& piece : pieces) {
    const size_t this_size = piece.size();
    if (this_size != 0) {
      memcpy(out, piece.data(), this_size);
      out += this_size;
    }
  }
  *out = '\0';
}

}  // namespace strcat_internal
}  // namespace silifuzz
