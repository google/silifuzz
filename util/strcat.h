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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_STRCAT_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_STRCAT_H_

#include <initializer_list>

#include "absl/strings/string_view.h"

namespace silifuzz {

namespace strcat_internal {

// Helper for StrCat::StrCat below.
void CatPieces(std::initializer_list<absl::string_view> pieces, char* output,
               int max_string_length);

template <int MaxLength>
class StrCat {
  static_assert(MaxLength >= 0);

 public:
  StrCat(std::initializer_list<absl::string_view> pieces) {
    CatPieces(pieces, buf_, MaxLength);
  }

  StrCat(const StrCat&) = delete;
  StrCat(StrCat&&) = delete;
  StrCat& operator=(const StrCat&) = delete;
  StrCat& operator=(StrCat&&) = delete;

  const char* c_str() const { return buf_; }

 private:
  char buf_[MaxLength + 1];
};

}  // namespace strcat_internal

// Simple absl::StrCat-like helper that works without libc dependencies and
// does not perform heap allocation.
// Accepts an initializer_list<absl::string_view> as parameter e.g.
//
// StrCat({"foo", "bar"});
//
template <int MaxLength = 128>
inline const char* StrCat(const strcat_internal::StrCat<MaxLength>& x) {
  return x.c_str();
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_STRCAT_H_
