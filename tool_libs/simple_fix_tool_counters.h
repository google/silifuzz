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

#ifndef THIRD_PARTY_SILIFUZZ_TOOL_LIBS_SIMPLE_FIX_TOOL_COUNTERS_H_
#define THIRD_PARTY_SILIFUZZ_TOOL_LIBS_SIMPLE_FIX_TOOL_COUNTERS_H_
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/meta/type_traits.h"
#include "absl/strings/string_view.h"
#include "./tool_libs/fix_tool_common.h"

namespace silifuzz::fix_tool_internal {

// An implementation of the FixToolCounters interface for the simple fix tool.
// This stores counter values in an object. The values are destroyed when
// the object is destroyed.
//
// This class is not thread-safe.
class SimpleFixToolCounters : public FixToolCounters {
 public:
  SimpleFixToolCounters() = default;
  virtual ~SimpleFixToolCounters() = default;

  // Not copyable but movable like parent.
  SimpleFixToolCounters(const SimpleFixToolCounters&) = delete;
  SimpleFixToolCounters(SimpleFixToolCounters&&) = default;
  SimpleFixToolCounters& operator=(const SimpleFixToolCounters&) = delete;
  SimpleFixToolCounters& operator=(SimpleFixToolCounters&&) = default;

  void IncrementBy(absl::string_view counter, int64_t delta) override {
    auto [it, inserted] = counters_.emplace(counter, delta);
    if (!inserted) it->second += delta;
  }

  // Additional API on top of FixToolCounters interface.

  // Merge count values from another SimpleFixToolCounters object.
  void Merge(const SimpleFixToolCounters& other) {
    for (const auto& [counter, count] : other.counters_) {
      IncrementBy(counter, count);
    }
  }

  // Returns value of `counter` or 0 if it does not exist.
  int64_t GetValue(absl::string_view counter) const {
    auto it = counters_.find(counter);
    return it != counters_.end() ? it->second : 0;
  }

  // Returns unordered names of all counters.
  std::vector<std::string> GetCounterNames() const {
    std::vector<std::string> counter_names;
    counter_names.reserve(counters_.size());
    for (const auto& [counter, _] : counters_) {
      counter_names.push_back(counter);
    }
    return counter_names;
  }

 private:
  // Stored counter values.
  absl::flat_hash_map<std::string, int64_t> counters_;
};

}  // namespace silifuzz::fix_tool_internal

#endif  // THIRD_PARTY_SILIFUZZ_TOOL_LIBS_SIMPLE_FIX_TOOL_COUNTERS_H_
