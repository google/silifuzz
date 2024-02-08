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
//
// A SimpleFixTool is a tool the integrates the fixer pipeline, the corpus
// partitioner and relocatable corpus building. Currently, it takes a corpus
// consisting of raw instruction sequences from Centipede, converts these into
// snapshots with undefined end states, runs the Snap maker to make Snapshots
// complete, partitions snapshots into shards and creates a relocatable corpus.
// As everything is done in memory, there is a limit on of corpus size. The
// limit may change in the future if we implement streaming for intermediate
// results in and out of a file system.

#ifndef THIRD_PARTY_SILIFUZZ_TOOLS_FUZZ_FILTER_TOOL_H_
#define THIRD_PARTY_SILIFUZZ_TOOLS_FUZZ_FILTER_TOOL_H_

#include "absl/status/status.h"
#include "absl/strings/string_view.h"

namespace silifuzz {

absl::Status FilterToolMain(absl::string_view raw_insns_bytes);
}

#endif  // THIRD_PARTY_SILIFUZZ_TOOLS_FUZZ_FILTER_TOOL_H_
