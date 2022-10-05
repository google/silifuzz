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

#include "./tools/simple_fix_tool.h"

#include <algorithm>
#include <cstddef>
#include <fstream>
#include <thread>  // NOLINT(build/c++11)
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "external/centipede/blob_file.h"
#include "./common/proxy_config.h"
#include "./common/raw_insns_util.h"
#include "./common/snapshot.h"
#include "./snap/gen/relocatable_snap_generator.h"
#include "./tool_libs/corpus_partitioner_lib.h"
#include "./tool_libs/fix_tool_common.h"
#include "./tool_libs/simple_fix_tool_counters.h"
#include "./tool_libs/snap_group.h"
#include "./util/checks.h"
#include "./util/span_util.h"

namespace silifuzz {
namespace fix_tool_internal {
namespace {

// Arguments for a make worker thread.
// This is used for both input and output.
struct FixToolWorkerArgs {
  // A worker needs to reference simple fix tool options.
  // The worker does not own the option.
  const SimpleFixToolOptions* options;
  absl::Span<const std::string> blobs;
  std::vector<Snapshot> good_snapshots;
  SimpleFixToolCounters counters;
};

void FixToolWorker(FixToolWorkerArgs& args) {
  auto current_platform = CurrentPlatformId();
  CHECK(current_platform != PlatformId::kUndefined);
  PlatformFixToolCounters platform_counters(ShortPlatformName(current_platform),
                                            &args.counters);

  for (const auto& blob : args.blobs) {
    absl::StatusOr<Snapshot> snapshot = InstructionsToSnapshot_X86_64(
        blob.data(), kCodeAddr, kCodeLimit - kCodeAddr, kMem1Addr);
    if (!snapshot.ok()) {
      args.counters.Increment(
          "silifuzz-ERROR-FixToolWorker:instructions-to-snapshot-failed");
      continue;
    }
    snapshot->set_id(InstructionsToSnapshotId(blob));
    if (!NormalizeSnapshot(snapshot.value(), &args.counters)) {
      continue;
    }
    RewriteInitialState(snapshot.value(), &args.counters);
    auto remade_snapshot_or =
        FixupSnapshot(snapshot.value(), &platform_counters);
    if (!remade_snapshot_or.ok()) {
      continue;
    }
    args.good_snapshots.push_back(std::move(remade_snapshot_or.value()));
    args.counters.Increment("silifuzz-INFO-FixToolWorker:success");
  }
}

}  // namespace

std::vector<std::string> ReadUniqueCentipedeBlobs(
    const std::vector<std::string>& inputs, SimpleFixToolCounters* counters) {
  std::vector<std::string> blobs;

  // Centipede generates fuzzing corpus using multiple workers in parallel.
  // It is common for the generated corpus to have duplicates.
  // Record unique snapshot names seen so far to de-dupe blobs.
  absl::flat_hash_set<Snapshot::Id> id_seen;

  for (const auto& input : inputs) {
    auto reader = centipede::DefaultBlobFileReaderFactory();
    if (!reader->Open(input).ok()) {
      counters->Increment("silifuzz-ERROR-Read:open-blob-reader-failed");
      continue;
    }

    // TODO(dougkwan): Parallelize this to speed up blob reading.
    absl::Status status;
    absl::Span<uint8_t> blob;
    while ((status = reader->Read(blob)).ok()) {
      const std::string id = InstructionsToSnapshotId(
          {reinterpret_cast<const char*>(blob.data()), blob.size()});
      auto [_, inserted] = id_seen.insert(id);
      if (inserted) {
        blobs.push_back(std::string(blob.begin(), blob.end()));
      } else {
        counters->Increment("silifuzz-INFO-Read:duplicate-blobs");
      }
    }

    // Log if loop exited not because of EOF.
    if (!absl::IsOutOfRange(status)) {
      counters->Increment("silifuzz-ERROR-Read:read-blob-failed");
    }

    if (!reader->Close().ok()) {
      counters->Increment("silifuzz-ERROR-Read:close-blob-reader-failed");
    }
  }

  return blobs;
}

std::vector<Snapshot> MakeSnapshotsFromBlobs(
    const SimpleFixToolOptions& options, const std::vector<std::string>& blobs,
    SimpleFixToolCounters* counters) {
  const size_t num_workers = options.parallelism
                                 ? options.parallelism
                                 : std::thread::hardware_concurrency();
  const std::vector<absl::Span<const std::string>> blob_spans =
      PartitionEvenly(blobs, num_workers);

  // Prepare args.
  std::vector<FixToolWorkerArgs> worker_args;
  worker_args.reserve(num_workers);
  for (size_t i = 0; i < num_workers; ++i) {
    FixToolWorkerArgs args;
    args.options = &options;
    args.blobs = blob_spans[i];
    worker_args.push_back(std::move(args));
  }

  // Start workers.
  std::vector<std::thread> workers;
  for (size_t i = 0; i < num_workers; ++i) {
    workers.emplace_back(FixToolWorker, std::ref(worker_args[i]));
  }

  size_t num_good_snapshots = 0;
  // Wait for workers to finish.
  for (int i = 0; i < num_workers; ++i) {
    workers[i].join();

    // It is now safe to access worker args for this worker.
    counters->Merge(worker_args[i].counters);
    num_good_snapshots += worker_args[i].good_snapshots.size();
  }

  // Collect made snapshots and bad snapshot id.
  std::vector<Snapshot> made_snapshots;
  made_snapshots.reserve(num_good_snapshots);
  for (auto& work_arg : worker_args) {
    std::move(work_arg.good_snapshots.begin(), work_arg.good_snapshots.end(),
              std::back_inserter(made_snapshots));
    work_arg.good_snapshots.clear();
  }
  return made_snapshots;
}

std::vector<std::vector<Snapshot>> PartitionSnapshots(
    const SimpleFixToolOptions& options, int num_groups,
    std::vector<Snapshot>& snapshots, SimpleFixToolCounters* counters) {
  // Create snapshot summaries for partitioner.
  SnapshotGroup::SnapshotSummaryList ungrouped;
  ungrouped.reserve(snapshots.size());
  for (auto& snapshot : snapshots) {
    ungrouped.emplace_back(snapshot);
  }

  // Run iterative partitioner.
  auto partitions = PartitionCorpus(
      num_groups, options.num_partitioning_iterations, ungrouped);
  counters->IncrementBy("silifuzz-INFO-Partition:cannot-group",
                        ungrouped.size());

  // Build Snapshot ID -> Group index map.
  absl::flat_hash_map<Snapshot::Id, int> group_map;
  group_map.reserve(snapshots.size());
  for (int i = 0; i < partitions.snapshot_groups().size(); ++i) {
    const std::vector<Snapshot::Id> id_list =
        partitions.snapshot_groups()[i].id_list();
    for (const std::string& id : id_list) {
      group_map[id] = i;
    }
  }

  // Reserve memory in output.
  std::vector<std::vector<Snapshot>> groups(
      partitions.snapshot_groups().size());
  for (int i = 0; i < partitions.snapshot_groups().size(); ++i) {
    groups[i].reserve(partitions.snapshot_groups()[i].size());
  }
  std::vector<Snapshot> ungrouped_snapshots;
  ungrouped_snapshots.reserve(ungrouped.size());

  // Move grouped snapshots to output.
  for (auto& snapshot : snapshots) {
    auto it = group_map.find(snapshot.id());
    if (it != group_map.end()) {
      groups[it->second].push_back(std::move(snapshot));
    } else {
      ungrouped_snapshots.push_back(std::move(snapshot));
    }
  }
  snapshots.swap(ungrouped_snapshots);

  return groups;
}

void WriteOutputFiles(const std::vector<std::vector<Snapshot>>& shards,
                      absl::string_view output_path_prefix,
                      SimpleFixToolCounters* counters) {
  for (int i = 0; i < shards.size(); ++i) {
    auto relocatable = GenerateRelocatableSnaps(shards[i]);
    const std::string file_name =
        absl::StrFormat("%s.%05d", output_path_prefix, i);
    std::ofstream os(file_name);
    if (!os.is_open()) {
      counters->Increment("silifuzz-ERROR-Output:open-failed");
      continue;
    }
    os.write(relocatable.get(), MmappedMemorySize(relocatable));
    if (os.fail()) {
      counters->Increment("silifuzz-ERROR-Output:write-failed.");
    }
    os.close();
  }
}

}  // namespace fix_tool_internal

void FixupCorpus(const SimpleFixToolOptions& options,
                 const std::vector<std::string>& inputs,
                 absl::string_view output_path_prefix, size_t num_output_shards,
                 fix_tool_internal::SimpleFixToolCounters* counters) {
  const std::vector<std::string> blobs =
      ReadUniqueCentipedeBlobs(inputs, counters);
  std::vector<Snapshot> made_snapshots =
      MakeSnapshotsFromBlobs(options, blobs, counters);

  std::vector<std::vector<Snapshot>> shards =
      PartitionSnapshots(options, num_output_shards, made_snapshots, counters);
  made_snapshots.clear();  // discard any left-over snapshots.

  WriteOutputFiles(shards, output_path_prefix, counters);
}

}  // namespace silifuzz
