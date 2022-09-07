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

#ifndef THIRD_PARTY_SILIFUZZ_PLAYER_PLAYER_RESULT_PROTO_H_
#define THIRD_PARTY_SILIFUZZ_PLAYER_PLAYER_RESULT_PROTO_H_

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "./common/snapshot_enums.h"
#include "./common/snapshot_types.h"
#include "./proto/player_result.pb.h"

namespace silifuzz {

// A collection of utilities to convert between the Player::Result class
// and its proto representation, proto::PlayerResult.
class PlayerResultProto : private SnapshotTypeNames {
 public:
  using PlayerResult = snapshot_types::PlaybackResult<EndState>;
  // Attempts to build a PlayerResult from proto.
  // Returns an error status if unsuccessful.
  static absl::StatusOr<PlayerResult> FromProto(
      const proto::PlayerResult& proto);

  // Dumps Player::Result into proto representation.
  static absl::Status ToProto(const PlayerResult& result,
                              proto::PlayerResult& proto);
};

}  // namespace silifuzz
#endif  // THIRD_PARTY_SILIFUZZ_PLAYER_PLAYER_RESULT_PROTO_H_
