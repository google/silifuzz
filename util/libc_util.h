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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_LIBC_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_LIBC_UTIL_H_

// This library contains various simple utilities that are small enhancements
// on top of some libc functionality. Move things if they grow beyond that.

#include <fcntl.h>

namespace silifuzz {

// Wrapper around fcntl() to clear the given file status flag bits for `fd`.
int fcntl_clearfl(int fd, int flags) {
  return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~flags);
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_LIBC_UTIL_H_
