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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_OWNED_FILE_DESCRIPTOR_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_OWNED_FILE_DESCRIPTOR_H_

#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "./util/checks.h"

namespace silifuzz {

// A wrapper for FDs that will release them on destruction.
// Cannot be copied.
// May be moved.
// May be empty (FD == -1).
class OwnedFileDescriptor {
 public:
  // Empty by default.
  OwnedFileDescriptor() : fd_(-1) {}

  // Takes ownership of the FD.
  explicit OwnedFileDescriptor(int fd) : fd_(fd) {}

  // Copy not allowed.
  OwnedFileDescriptor(const OwnedFileDescriptor&) = delete;
  OwnedFileDescriptor& operator=(const OwnedFileDescriptor&) = delete;

  OwnedFileDescriptor(OwnedFileDescriptor&& other) {
    fd_ = other.fd_;
    other.fd_ = -1;
  }

  OwnedFileDescriptor& operator=(OwnedFileDescriptor&& other) {
    release();
    fd_ = other.fd_;
    other.fd_ = -1;
    return *this;
  }

  int borrow() const { return fd_; }

  ~OwnedFileDescriptor() { release(); }

 private:
  void release() {
    if (fd_ != -1) {
      if (close(fd_) < 0) {
        LOG_ERROR("close() failed: ", strerror(errno));
      }
      fd_ = -1;
    }
  }

  int fd_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_OWNED_FILE_DESCRIPTOR_H_
