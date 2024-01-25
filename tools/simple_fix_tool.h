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

#ifndef THIRD_PARTY_SILIFUZZ_TOOLS_SIMPLE_FIX_TOOL_H_
#define THIRD_PARTY_SILIFUZZ_TOOLS_SIMPLE_FIX_TOOL_H_

#include <cstddef>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "./common/snapshot.h"
#include "./tool_libs/simple_fix_tool_counters.h"

namespace silifuzz {

// Options for simple fix tool.
struct SimpleFixToolOptions {
  SimpleFixToolOptions() = default;
  ~SimpleFixToolOptions() = default;

  // Number of corpus partitioning iterations.
  int num_partitioning_iterations = 10;

  // Number of parallel worker threads.  If it is 0, the maximum hardware
  // parallelism is used.
  int parallelism = 0;

  // If true, filter Snap containing lock instructions that access memory
  // across cache line boundary. This has no effect on platforms other than x86.
  bool x86_filter_split_lock = true;

  // If true, tracer injects a signal when an instruction accesses memory in
  // vsyscall memory region of Linux. This has no effect on non-x86 platforms.
  bool x86_filter_vsyscall_region_access = true;

  // If true, tracer injects a signal when an instruction accesses memory. This
  // has no effect on non-x86 platforms.
  bool filter_memory_access = false;
};

// Converts raw instructions blobs in `inputs` into snapshots of the
// current architecture. Runs the snapshots through the maker to generate
// end states for them. Partitions successfully made snapshots into
// `num_output_shards` shards and outputs snapified snapshots as a sharded
// relocatable corpus. pdates fix tool statistics in
// `counters`.
void FixupCorpus(const SimpleFixToolOptions& options,
                 const std::vector<std::string>& inputs,
                 absl::string_view output_path_prefix, size_t num_output_shards,
                 fix_tool_internal::SimpleFixToolCounters* counters);

// ----------------------- implementation details ------------------
namespace fix_tool_internal {

// Read unique blobs from files in `inputs`. Returns a vector of blobs. This
// reads as many blobs as possible.  It there is an error while reading a blob
// file, the rest of the file is ignored and reading continues. Updates
// statistics in `counters`.
std::vector<std::string> ReadUniqueCentipedeBlobs(
    const std::vector<std::string>& inputs, SimpleFixToolCounters* counters);

// Makes `blobs` with `parallelism` into complete snapshots with end states
// for the current platform on which this runs. Return a vector of made
// snapshots. The make process is controlled by `options`. Updates fix tool
// statistics in `counters`.
std::vector<Snapshot> MakeSnapshotsFromBlobs(
    const SimpleFixToolOptions& options, const std::vector<std::string>& blobs,
    SimpleFixToolCounters* counters);

// Partitions and moves `snapshots` into `num_groups` groups,
// each of which contains snapshots with no memory mapping conflicts.
// The partition process is controlled by `options`.
// Returns a vector of groups (vector<Snapshot>). Snapshots that
// cannot be grouped and moved will remain in `snapshots`. Also updates fix
// tool statistics in `counters`.
std::vector<std::vector<Snapshot>> PartitionSnapshots(
    const SimpleFixToolOptions& options, int num_groups,
    std::vector<Snapshot>& snapshots);

// Writes snapshots in `shards` into relocatable corpora. Each corpus has
// a path `output_path_prefix` + '.' + <shard index>. Updates fix tool
// statistics in `counters`.
void WriteOutputFiles(const std::vector<std::vector<Snapshot>>& shards,
                      absl::string_view output_path_prefix,
                      SimpleFixToolCounters* counters);

}  // namespace fix_tool_internal

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TOOLS_SIMPLE_FIX_TOOL_H_
