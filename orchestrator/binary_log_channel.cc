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

#include "./orchestrator/binary_log_channel.h"

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>  // IWYU pragma: keep
#include <cstring>
#include <string>

#include "absl/numeric/bits.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "./proto/binary_log_entry.pb.h"
#include "./proto/snapshot_execution_result.pb.h"
#include "./util/byte_io.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/signals.h"

namespace silifuzz {

namespace {
void LittleEndianStore64(void* dst, uint64_t value) {
  // Swap bytes if host is big-endian.
  if (absl::endian::native == absl::endian::big) {
    value = absl::byteswap(value);  // NOLINT(clang-diagnostic-unreachable-code)
  }
  memcpy(dst, &value, sizeof(value));
}

uint64_t LittleEndianLoad64(const void* src) {
  uint64_t value;
  memcpy(&value, src, sizeof(uint64_t));
  // Swap bytes if host is big-endian.
  if (absl::endian::native == absl::endian::big) {
    value = absl::byteswap(value);  // NOLINT(clang-diagnostic-unreachable-code)
  }
  return value;
}

// End-of-channel error status
absl::Status EndOfChannelError() { return absl::OutOfRangeError("EOC"); }

// Clears flags of a file descriptor.
absl::Status ClearFlags(int fd, int flags) {
  const int old_flags = fcntl(fd, F_GETFL);
  if (old_flags == -1) {
    return absl::ErrnoToStatus(errno, "cannot get file descriptor flags");
  }

  const int new_flags = old_flags & ~flags;
  if (fcntl(fd, F_SETFL, new_flags) < 0) {
    return absl::ErrnoToStatus(errno, "cannot set file descriptor flags");
  }
  return absl::OkStatus();
}

// If 's' is okay, just returns it.  Otherwise, converts the status into
// an internal error and adds a prefix to the message.
absl::Status WrapConstructorError(absl::Status s) {
  if (s.ok()) {
    return s;
  }
  return absl::InternalError(absl::StrCat("Constructor failed: ", s.message()));
}

}  // namespace

BinaryLogProducer::BinaryLogProducer(int fd, bool take_ownership)
    : fd_(fd), take_ownership_(take_ownership) {
  // Ignore SIGPIPE globally so that we do not get a signal when writing
  // to a pipe with closed reading end. Signal state is global so there is
  // no guarantee that SIGPIPE handling will not be changed after this.
  IgnoreSignal(SIGPIPE);

  // We need a non-blocking file descriptor.
  constructor_status_ = WrapConstructorError(ClearFlags(fd, O_NONBLOCK));
}

BinaryLogProducer::~BinaryLogProducer() {
  if (take_ownership_ && close(fd_) < 0) {
    LOG_ERROR("Cannot close channel descriptor: ", ErrnoStr(errno));
  }
}

// Send a BinaryLogEntry proto over the channel and return a status indicating
// success or failure.
absl::Status BinaryLogProducer::Send(const proto::BinaryLogEntry& entry) {
  RETURN_IF_NOT_OK(constructor_status_);

  const std::string serialized_proto = entry.SerializeAsString();
  const uint64_t proto_size = serialized_proto.size();
  char le_proto_size[sizeof(uint64_t)];
  LittleEndianStore64(le_proto_size, proto_size);

  // The whole message needs to be written into channel atomically.
  absl::MutexLock l(&lock_);

  const ssize_t written_size = Write(fd_, le_proto_size, sizeof(le_proto_size));
  if (written_size == -1) {
    return EndOfChannelError();
  }
  if (written_size != sizeof(le_proto_size)) {
    return absl::ErrnoToStatus(errno, "Cannot write BinaryLogEntry size");
  }
  if (Write(fd_, serialized_proto.data(), proto_size) != proto_size) {
    return absl::ErrnoToStatus(errno, "Cannot write BinaryLogEntry");
  }
  return absl::OkStatus();
}

BinaryLogConsumer::BinaryLogConsumer(int fd, bool take_ownership)
    : fd_(fd), take_ownership_(take_ownership) {
  // We need a blocking file descriptor.
  constructor_status_ = WrapConstructorError(ClearFlags(fd, O_NONBLOCK));
}

BinaryLogConsumer::~BinaryLogConsumer() {
  if (take_ownership_ && close(fd_) < 0) {
    LOG_ERROR("Cannot close channel descriptor: ", ErrnoStr(errno));
  }
}

// Receive a serialized message, return a BinaryLogEntry proto containing
// the message or an error status.
absl::StatusOr<proto::BinaryLogEntry> BinaryLogConsumer::Receive() {
  RETURN_IF_NOT_OK(constructor_status_);

  char le_proto_size[sizeof(uint64_t)];

  // The whole message needs to be read from channel atomically.
  absl::MutexLock l(&lock_);

  const ssize_t bytes_read = Read(fd_, le_proto_size, sizeof(le_proto_size));
  if (bytes_read == 0) {
    return EndOfChannelError();
  }
  if (bytes_read == -1) {
    return absl::ErrnoToStatus(
        errno, absl::StrCat("Cannot read BinaryLogEntry size, fd=", fd_));
  } else if (bytes_read != sizeof(le_proto_size)) {
    return absl::DataLossError(absl::StrCat("Malformed stream: expected ",
                                            sizeof(le_proto_size), " but got ",
                                            bytes_read, " bytes"));
  }
  const size_t proto_size = LittleEndianLoad64(le_proto_size);
  std::string serialized_proto;
  serialized_proto.resize(proto_size);
  if (Read(fd_, serialized_proto.data(), proto_size) != proto_size) {
    return absl::ErrnoToStatus(errno, "Cannot read BinaryLogEntry proto");
  }
  proto::BinaryLogEntry entry;
  if (!entry.ParseFromString(serialized_proto)) {
    return absl::DataLossError("Cannot deserialize BinaryLogEntry");
  }
  return entry;
}

}  // namespace silifuzz
