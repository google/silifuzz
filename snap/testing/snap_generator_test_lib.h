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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_TESTING_SNAP_GENERATOR_TEST_LIB_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_TESTING_SNAP_GENERATOR_TEST_LIB_H_

#include "./common/snapshot.h"
#include "./snap/gen/snap_generator.h"
#include "./snap/snap.h"

namespace silifuzz {

// Verifies that 'snap' is correctly generated from 'snapshot' using
// 'generator_options'. Die if any error is found.
void VerifyTestSnap(
    const Snapshot& snapshot, const Snap& snap,
    const SnapifyOptions& generator_options = SnapifyOptions::Default());
}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_TESTING_SNAP_GENERATOR_TEST_LIB_H_
