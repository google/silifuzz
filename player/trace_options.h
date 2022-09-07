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

#ifndef THIRD_PARTY_SILIFUZZ_PLAYER_TRACE_OPTIONS_H_
#define THIRD_PARTY_SILIFUZZ_PLAYER_TRACE_OPTIONS_H_

#include "./player/play_options.h"

namespace silifuzz {

// Common options for tracing a snapshot.
//
// Currently consists of just PlayOptions.
//
// This class is a thread-compatible value type.
class TraceOptions {
 public:
  TraceOptions() {}
  ~TraceOptions() = default;

  // Intentionally movable and copyable.

  // Default values.
  static const TraceOptions& Default();

  PlayOptions play_options = PlayOptions::Default();

  // Maximum number of instructions the snapshot is allowed to execute
  // before the tracer stops it. 0 for unlimited.
  int instruction_count_limit = 1000;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_PLAYER_TRACE_OPTIONS_H_
