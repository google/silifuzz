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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_FILE_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_FILE_UTIL_H_

#include "absl/base/attributes.h"
#include "absl/strings/string_view.h"

namespace silifuzz {

// Writes the data provided in `contents` to the file descriptor `fd`.
ABSL_MUST_USE_RESULT bool WriteToFileDescriptor(int fd,
                                                absl::string_view contents);

// Writes the data provided in `contents` to the file `file_name`, overwriting
// any existing content. Fails if directory does not exist.
//
// NOTE: Will return true iff all of the data in `content` was written.
// May write some of the data and return an error.
ABSL_MUST_USE_RESULT bool SetContents(absl::string_view file_name,
                                      absl::string_view contents);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_FILE_UTIL_H_
