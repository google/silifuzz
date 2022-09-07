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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_BYTE_IO_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_BYTE_IO_H_
// Byte I/O utility

#include <sys/types.h>  // ssize_t

namespace silifuzz {

// A simple nolibc-compatible file reading helper. Reads up-to `space` bytes
// from `fd` into '*buffer`. Returns number of bytes read or -1 on any failure.
ssize_t Read(int fd, void* buffer, size_t space);

// A simple nolibc-compatible file writing helper. Writes up-to `space` bytes
// from '*buffer` into `fd`. Returns number of bytes written or -1 on any
// failure.
ssize_t Write(int fd, const void* buffer, size_t space);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_BYTE_IO_H_
