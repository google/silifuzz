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

#ifndef THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_LOG_CHANNEL_H_
#define THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_LOG_CHANNEL_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/synchronization/mutex.h"
#include "./proto/binary_log_entry.pb.h"
#include "./proto/snapshot_execution_result.pb.h"

namespace silifuzz {

// A binary log channel allows SiliFuzz orchestrator to send out execution
// results as a serialized protos using file descriptors.  The descriptors
// can be a pipe, a socket pair. There are two parts of the channel. A binary
// log producer inside SiliFuzz, and a binary log consumer in the parent process
// of the orchestrator. The parent process is required to create a pipe/socket
// pair and pass it to the orchestrator.

// Binary log stream format:
//
// A binary log stream consists of zero or more consecutive binary log entries.
// Each entry consists of 2 parts with no space in between.
//    a) a 64-bit little endian integer representing the byte size of a
//       serialized BinaryLogEntry protobuf that follows.
//    b) the BinaryLogEntry protobuf serialized as bytes.

// Returns true iff s is the end-of-channel status. For details see
// BinaryLogProducer::Send() and BinaryLogConsumer::Receive().
inline bool IsEndOfChannelError(const absl::Status& s) {
  return (s.code() == absl::StatusCode::kOutOfRange) && (s.message() == "EOC");
}

// This class is thread-safe.
class BinaryLogProducer {
 public:
  // Constructs a BinaryLogProducer object using file descriptor 'fd'.  If
  // 'take_ownership' is true, the object takes ownerships of the descriptor.
  explicit BinaryLogProducer(int fd, bool take_ownership = true);

  // Closes the file descriptor if this owns it. Any error reported by close()
  // is logged but ignored as it is not recoverable.
  ~BinaryLogProducer();

  // This cannot be copied or moved.
  BinaryLogProducer(const BinaryLogProducer&) = delete;
  BinaryLogProducer& operator=(const BinaryLogProducer&) = delete;
  BinaryLogProducer(BinaryLogProducer&&) = delete;
  BinaryLogProducer& operator=(BinaryLogProducer&&) = delete;

  // Sends a binary log entry proto and returns a status to indicate any errors.
  // In particular if the consumer closed its end of channel already before we
  // write to the channel, an OutOfRangeError("EOC") status is reported.
  absl::Status Send(const proto::BinaryLogEntry& entry);

 private:
  // File descriptor of the log channel.
  int fd_;

  // Whether this takes over ownership of fd_.
  bool take_ownership_;

  // The channel is protected by a lock to avoid interleaving messages.
  absl::Mutex lock_;

  // error status set by constructor.
  absl::Status constructor_status_;
};

// This class is thread-safe.
class BinaryLogConsumer {
 public:
  // Constructs a BinaryLogConsumer object using file descriptor 'fd'.
  // If 'take_ownership' is true, the object takes ownerships of the descriptor
  // and will close it when the object is destroyed.
  explicit BinaryLogConsumer(int fd, bool take_ownership = true);

  // Closes the file descriptor if this owns it. Any error reported by close()
  // is logged but ignored as it is not recoverable.
  ~BinaryLogConsumer();

  // This cannot be copied or moved.
  BinaryLogConsumer(const BinaryLogConsumer&) = delete;
  BinaryLogConsumer& operator=(const BinaryLogConsumer&) = delete;
  BinaryLogConsumer(BinaryLogConsumer&&) = delete;
  BinaryLogConsumer& operator=(BinaryLogConsumer&&) = delete;

  // Waits to receives a binary log entry from the channel.  If there is no
  // error, returns a BinaryLogEntry proto. Otherwise an error status is
  // reported. In particular if there is no data and the producer closed its
  // end of channel already, an OutOfRangeError("EOC") status is reported.
  absl::StatusOr<proto::BinaryLogEntry> Receive();

 private:
  // File descriptor of the log channel.
  int fd_;

  // Whether this takes ownership of fd_.
  bool take_ownership_;

  // The channel is protected by a lock to avoid interleaving messages.
  absl::Mutex lock_;

  // error status set by constructor.
  absl::Status constructor_status_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_ORCHESTRATOR_LOG_CHANNEL_H_
