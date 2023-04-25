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

#include "./util/byte_io.h"

#include <stddef.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>

#include "./util/checks.h"
#include "./util/itoa.h"

namespace silifuzz {

ssize_t Read(int fd, void* buffer, size_t space) {
  uint8_t* ptr = reinterpret_cast<uint8_t*>(buffer);
  uint8_t* start_ptr = ptr;
  while (space > 0) {
    ssize_t r = read(fd, ptr, space);
    if (r == 0) break;  // EOF
    if (r < 0) {
      // Instead of restarting, we treat EAGAIN as an error as non-blocking
      // I/O is not expected. This is done to avoid unnecessary busy-wait.
      if (errno == EINTR) continue;
      LOG_ERROR("Error reading from fd ", IntStr(fd), ": ", ErrnoStr(errno));
      return -1;
    }
    CHECK_LE(r, space);  // could only happen if read() is buggy
    ptr += r;
    space -= r;
  }
  return ptr - start_ptr;
}

ssize_t Write(int fd, const void* buffer, size_t space) {
  const uint8_t* ptr = reinterpret_cast<const uint8_t*>(buffer);
  const uint8_t* start_ptr = ptr;
  while (space > 0) {
    ssize_t r = write(fd, ptr, space);
    // Since space > 0, we would expect some kind of error if
    // no bytes are written. In that case r should be -1 instead of 0.
    CHECK_NE(r, 0);
    if (r < 0) {
      // Instead of restarting, we treat EAGAIN as an error as non-blocking
      // I/O is not expected. This is done to avoid unnecessary busy-wait.
      if (errno == EINTR) continue;
      LOG_ERROR("Error writing to fd ", IntStr(fd), ": ", ErrnoStr(errno));
      return -1;
    }
    CHECK_LE(r, space);  // could only happen if write() is buggy
    ptr += r;
    space -= r;
  }
  return ptr - start_ptr;
}

}  // namespace silifuzz
