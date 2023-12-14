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

// PMU Event Proxy
//
// This is a centipede fuzz target that executes arbitrary CPU instruction blobs
// and record PMU event count changes during execution. The event counts are
// converted into coverage features for consumption by centipede.
//
#include <sys/prctl.h>
#include <sys/resource.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "external/com_google_fuzztest/centipede/feature.h"
#include "./proxies/pmu_event_proxy/perf_event_fuzzer.h"
#include "./proxies/pmu_event_proxy/pmu_events.h"
#include "./proxies/user_features.h"
#include "./proxies/util/set_process_dumpable.h"
#include "./util/checks.h"
#include "external/libpfm4/include/perfmon/pfmlib.h"
#include "external/libpfm4/include/perfmon/pfmlib_perf_event.h"

ABSL_FLAG(size_t, num_iterations, 10,
          "Number of iterations to run each input.");

// This array lives in an ELF segment that the Centipede runner will read from.
USER_FEATURE_ARRAY user_feature_t features[100000];

namespace silifuzz {

namespace {

// These are global so that LLVMFuzzerTestOneInput() can see them.
std::vector<std::string> *pmu_events;
PerfEventFuzzer *perf_event_fuzzer;

// Convert a non-zero PMU event 'count' of the 'i-th' event to a user
// feature by its MSB position. This maps 'count' into one of the 8 feature
// bits.
uint32_t Convert8BitCountToUserFeature(size_t i, uint8_t count) {
  CHECK_NE(count, 0);
  // Compute a log2 of counter_value, i.e. a value between 0 and 7.
  // __builtin_clz consumes an unsigned int.
  const unsigned int unsigned_count = static_cast<unsigned int>(count);
  const uint32_t counter_log2 =
      sizeof(unsigned_count) * 8 - 1 - __builtin_clz(unsigned_count);
  return i * 8 + counter_log2;
}

// Executes a payload at 'data' of 'size' bytes.  Returns 0 if we should keep
// the payload for fuzzing or -1 if we should discard it.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  absl::StatusOr<PerfEventFuzzer::PerfEventMeasurementList> event_measurements =
      perf_event_fuzzer->FuzzOneInput(data, size,
                                      absl::GetFlag(FLAGS_num_iterations));
  if (!event_measurements.ok()) {
    LOG(ERROR) << "Failed to test one input: " << event_measurements.status();
    return -1;
  }

  // We generate two kinds of coverage from PMU event counts.
  // 1. Count values: Counter values are clipped to fit in the range
  // [0..255]. Each value in the range is a distinct feature. Due to noise
  // in counter reading, feature generation is non-deterministic.
  // Fuzzing inputs are usually very short with O(100) instructions so we do not
  // expect large event counts. 8 bits seem to be a good estimate. We can scale
  // count values or increase the range if 8 bits are not sufficient.
  // 2. Count value pairs: Non-zero count values are paired to form a
  // single feature. This is quadratic so we compress the count values
  // by taking using the MSB only. The stored feature is thus a pair of
  // MSBs.

  UserFeatures user_features;
  user_features.Reset(features);
  std::vector<uint32_t> compressed_counts;

  constexpr int kPMUCounterDomain = 1;
  constexpr size_t kMaxCount = 255;
  CHECK_EQ(event_measurements->size(), pmu_events->size());
  for (size_t i = 0; i < pmu_events->size(); ++i) {
    PerfEventMeasurements &measurements = event_measurements.value()[i];
    CHECK_EQ(measurements.event(), (*pmu_events)[i]);
    const double count =
        measurements.mean().has_value() ? measurements.mean().value() : 0;
    const double clipped =
        static_cast<uint32_t>(std::min<double>(count, kMaxCount));
    user_features.EmitFeature(kPMUCounterDomain, i * (kMaxCount + 1) + clipped);
    if (clipped > 0) {
      // 256 count features are compressed into 8.
      compressed_counts.push_back(Convert8BitCountToUserFeature(i, clipped));
    }
  }

  constexpr int kPMUCounterPairDomain = 2;
  size_t d = pmu_events->size() * 8;
  for (size_t i = 1; i < compressed_counts.size(); ++i) {
    for (size_t j = 0; j < i; ++j) {
      const uint64_t pair = compressed_counts[i] * d + compressed_counts[j];
      DCHECK_LT(pair, centipede::feature_domains::Domain::kDomainSize);
      user_features.EmitFeature(kPMUCounterPairDomain, pair);
    }
  }

  return 0;
}

absl::Status PMUEventProxyInitialize(int *argc, char ***argv) {
  absl::ParseCommandLine(*argc, *argv);

  pfm_err_t init_err = pfm_initialize();
  if (init_err != PFM_SUCCESS) {
    return absl::InternalError(
        absl::StrCat("Failed to initialize libpfm: ", pfm_strerror(init_err)));
  }

  // Revert dumpable setting for snap maker to work.
  // See comments in set_process_dumpable.h for details.
  RETURN_IF_NOT_OK(proxies::SetProcessDumpable());

  // Get PMU perf events.
  // TODO(dougkwan): Instead of calling GetUniqueCPUCorePMUEvents(), use a
  // file containing events to fuzz.
  ASSIGN_OR_RETURN_IF_NOT_OK(std::vector<std::string> events,
                             GetUniqueCPUCorePMUEvents());
  pmu_events = new std::vector<std::string>();
  pmu_events->swap(events);

  perf_event_fuzzer = new PerfEventFuzzer(*pmu_events);
  return absl::OkStatus();
}

}  // namespace

}  // namespace silifuzz

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  absl::Status status = silifuzz::PMUEventProxyInitialize(argc, argv);
  if (!status.ok()) {
    LOG(ERROR) << "Failed to initialize PMU Event proxy: " << status;
    return -1;
  }
  return 0;
}
