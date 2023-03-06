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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_SNAP_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_SNAP_UTIL_H_

// Utilities for Snap.
// These are not parts of Snap classes to reduce dependencies of snap.h,
// which is used in the nolibc environment by the runner.

#include "absl/status/statusor.h"
#include "./common/snapshot.h"
#include "./snap/snap.h"
#include "./util/platform.h"

namespace silifuzz {

// Converts Snap into Snapshot with `platform` representing the platform for the
// only expected end state in `snap`.
// TODO(ksteuck): [impl] There should be metadata in the corpus file or the Snap
// to describe the target platform.
absl::StatusOr<Snapshot> SnapToSnapshot(const Snap& snap, PlatformId platform);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_SNAP_UTIL_H_
