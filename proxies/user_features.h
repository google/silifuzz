// Copyright 2023 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_USER_FEATURES_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_USER_FEATURES_H_

#include <cstddef>
#include <cstdint>

#include "./util/checks.h"

// Centipede scans the content of a specific ELF section for user features.
// To send user features to Centipede, we need to declare an array in that ELF
// section and also mark that array something the compiler should assume is used
// even though it doesn't see any explicit reads from the array. (The compiler
// does not understand that when the Centipede runner consumes the ELF section
// it is implicitly reading this array.)
#define USER_FEATURE_ARRAY \
  __attribute__((used, retain, section("__centipede_extra_features")))

// User features are 64-bit values. The upper 32 bits are the domain, and the
// lower 32 bits are the feature within that domain.
using user_feature_t = uint64_t;

class UserFeatures {
 public:
  UserFeatures() : features_(nullptr), num_features_(0), current_feature_(0) {}

  // Disallow copy and move.
  UserFeatures(const UserFeatures&) = delete;
  UserFeatures(UserFeatures&&) = delete;
  UserFeatures& operator=(const UserFeatures&) = delete;
  UserFeatures& operator=(UserFeatures&&) = delete;

  template <size_t N>
  void Reset(user_feature_t (&features)[N]) {
    features_ = features;
    num_features_ = N;
    current_feature_ = 0;
  }

  void EmitFeature(uint32_t domain, uint32_t feature) {
    // HACK to work around domain = 0 / feature = 0 being ignored by Centipede
    // TODO(ncbray): improve how Centipede detects freshly emitted features.
    if (domain == 0) {
      feature++;
    }

    // Known limits for centipede.
    // These can change, but checking the values are reasonable isn't a bad
    // idea for now.
    CHECK_LT(domain, 16);
    CHECK_LT(feature, 1ULL << 27);

    // TODO(ncbray): remove this once we're convinced overflows do not occur.
    CHECK_LT(current_feature_, num_features_);

    // Emit the feature.
    // Do a modulus for memory safety, but keep track of the actual number of
    // features in case we need to print it out for debugging purposes.
    features_[current_feature_ % num_features_] =
        ((uint64_t)domain) << 32 | feature;
    current_feature_++;
  }

 private:
  user_feature_t* features_;
  size_t num_features_;
  size_t current_feature_;
};

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_USER_FEATURES_H_
