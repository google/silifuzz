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

#include "./proxies/pmu_event_proxy/pmu_events.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/base/call_once.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./util/checks.h"
#include "./util/x86_cpuid.h"
#include "perfmon/pfmlib.h"
#include "perfmon/pfmlib_perf_event.h"

namespace silifuzz {

namespace {

absl::once_flag init_once;
pfm_err_t pfm_initialize_result;

// A subset of information returned by pfm_get_os_event_encoding.
struct EventEncodingInfo {
  // Full name of PMU event, including any modifiers.
  std::string full_name;
  // An opaque unique identifier passed to pfm_get_event_info() to get
  // information about the event.
  int idx;
};

// Initialize libpfm4 if necessary, returns a cached status of calling
// pfm_initialize().
absl::Status InitializeIfNecessary() {
  absl::call_once(init_once,
                  []() { pfm_initialize_result = pfm_initialize(); });
  if (pfm_initialize_result != PFM_SUCCESS) {
    return absl::InternalError(absl::StrCat(
        "pfm_initialize() failed: ", pfm_strerror(pfm_initialize_result)));
  }
  return absl::OkStatus();
}

absl::StatusOr<pfm_pmu_info_t> GetPMUInfo(pfm_pmu_t pmu) {
  auto error_msg = [](pfm_pmu_t pmu, pfm_err_t err) {
    return absl::StrCat("pfm_get_pmu_info(", pmu,
                        ") failed: ", pfm_strerror(err));
  };
  pfm_pmu_info_t pmu_info{};
  const pfm_err_t get_pmu_info_result = pfm_get_pmu_info(pmu, &pmu_info);
  // Treat PFM_ERR_NOTSUPP differently than other errors. We get this error
  // when probing for PMU.
  if (get_pmu_info_result == PFM_ERR_NOTSUPP) {
    return absl::UnavailableError(error_msg(pmu, get_pmu_info_result));
  }
  // Return InternalError status for all other types of errors.
  if (get_pmu_info_result != PFM_SUCCESS) {
    return absl::InternalError(error_msg(pmu, get_pmu_info_result));
  }
  return pmu_info;
}

// Returns the CPU Core PMU of current platform or an error status.
// This is called once by GetCPUCorePMUOrDie(), which caches the result.
absl::StatusOr<pfm_pmu_t> GetCPUCorePMU() {
  // Get PMU information.
  std::vector<pfm_pmu_t> cpu_core_pmus;
  for (size_t i = 0; i < static_cast<size_t>(PFM_PMU_MAX); ++i) {
    pfm_pmu_t pmu = static_cast<pfm_pmu_t>(i);
    // Skip null PMU value PFM_PFM_NONE.
    if (pmu == PFM_PMU_NONE) continue;

    absl::StatusOr<pfm_pmu_info_t> pmu_info = GetPMUInfo(pmu);
    // Skip PMU if unsupported or absent.
    if (absl::IsUnavailable(pmu_info.status())) continue;

    RETURN_IF_NOT_OK(pmu_info.status());

    // We are only interested in CPU Core counter events.  We could include
    // uncore counters but those are more prone to being affected by workloads
    // on other cores thus not usable for our purpose. Also skip the
    // architecture default PMU, which only provides generic events.
    if (pmu_info->is_present && !pmu_info->is_dfl &&
        pmu_info->type == PFM_PMU_TYPE_CORE) {
      cpu_core_pmus.push_back(pmu);
    }
  }

  // There should be one and only one PMU detected.
  if (cpu_core_pmus.size() != 1) {
    return absl::FailedPreconditionError(
        absl::StrCat("Found ", cpu_core_pmus.size(), " PMUs instead of 1"));
  }
  return cpu_core_pmus[0];
}

// Returns the CPU Core PMU of current platform. Crashes if there is an error.
pfm_pmu_t GetCPUCorePMUOrDie() {
  static pfm_pmu_t cached_pmu = []() {
    absl::StatusOr<pfm_pmu_t> pmu = GetCPUCorePMU();
    if (!pmu.ok()) {
      // If we cannot get the PMU, there is not much point continuing.
      LOG(FATAL) << "Cannot determine CPU core PMU: " << pmu.status();
    }
    return pmu.value();
  }();
  return cached_pmu;
}

#ifdef __x86_64__
// Specialized version of GetNumCounters() below for Intel CPU.
// Return the number of performance counters on Intel CPUs supporting
// Architectural Performance Monitoring, or -1 otherwise.
int GetNumCountersIntelAPM() {
  X86CPUVendorID vendor_id_string;
  if (vendor_id_string.IsIntel()) {
    // For details, see Intel 64 and IA-32 Architectures Software Developer’s
    // Manual, Volume 3, 18.2.1.1 Architectural Performance Monitoring Version 1
    // Facilities. This works for reasonably modern Intel CPUs with architecture
    // performance monitoring.
    X86CPUIDResult result;
    X86CPUID(0xa, &result);
    // Architecture performance monitoring version in eax [7:0].
    const uint32_t apm_version = result.eax & 0xff;
    if (apm_version > 0) {
      // Number of counters per logical CPU in eax [15:8].
      const uint32_t num_counters = (result.eax >> 8) & 0xff;
      LOG(INFO) << "CPUID function 0xa reports Intel APM version "
                << apm_version << " and " << num_counters
                << " performance counters";
      return num_counters;
    }
  }
  return -1;
}
#endif

// Returns the number of counters on a logic CPU of the current platform.
// For some Intel microarchitectures, libpfm4 reports the number of programmable
// performance counters when hyperthreading (HT) is turned-off. With HT on, each
// logical CPU only has half of the counters so we have do an adjustment.
int GetNumCounters() {
#ifdef __x86_64__
  const int num_counters = GetNumCountersIntelAPM();
  if (num_counters != -1) return num_counters;
#endif
  pfm_pmu_t pmu = GetCPUCorePMUOrDie();
  absl::StatusOr<pfm_pmu_info_t> pmu_info = GetPMUInfo(pmu);
  CHECK_OK(pmu_info.status());
  return pmu_info->num_cntrs;
}

absl::StatusOr<EventEncodingInfo> GetEventEncodingInfo(
    const std::string& event) {
  // pfm_get_os_event_encoding() returns binary encoding of the PMU event
  // stored in config* fields of perf_event_attr.  Currently there are
  // 3 such fields.  We do not use this returned information.
  constexpr size_t kMaxCodes = 3;
  uint64_t codes[kMaxCodes];

  // Full name of PMU event. pfm_get_os_event_encoding() below stores a
  // pointer to a newly allocated string there. We use this for deduping.
  // The returned string needs to be deallocated by free() after use.
  char* fstr = nullptr;

  pfm_pmu_encode_arg_t arg{
      .codes = codes,
      .fstr = &fstr,
      .size = sizeof(pfm_pmu_encode_arg_t),
      .count = std::size(codes),
  };
  pfm_err_t err =
      pfm_get_os_event_encoding(event.c_str(), PFM_PLM3, PFM_OS_NONE, &arg);
  if (err != PFM_SUCCESS) {
    return absl::InternalError(absl::StrCat("pfm_get_os_event_encoding(", event,
                                            ") failed: ", pfm_strerror(err)));
  }
  std::string full_name = std::string(fstr);
  free(fstr);
  return EventEncodingInfo{.full_name = full_name, .idx = arg.idx};
}

// Adds names of event and any sub-events described by 'event_info' into
// 'events'.  Any sub-events that are aliases are also added.
absl::Status AddEventAndSubEvents(const pfm_event_info_t& event_info,
                                  PMUEventList& events) {
  // Get all umask attributes.
  size_t num_sub_events = 0;
  for (size_t i = 0; i < event_info.nattrs; ++i) {
    pfm_event_attr_info_t event_attr{};
    const int get_event_attr_info_result = pfm_get_event_attr_info(
        event_info.idx, i, PFM_OS_PERF_EVENT, &event_attr);
    if (get_event_attr_info_result != PFM_SUCCESS) {
      return absl::InternalError(
          absl::StrCat("pfm_get_event_attr_info() failed: ",
                       pfm_strerror(get_event_attr_info_result)));
    }
    if (event_attr.type == PFM_ATTR_UMASK) {
      events.push_back(absl::StrCat(event_info.name, ":", event_attr.name));
      ++num_sub_events;
    }
  }

  // If there are no sub-events, add the event itself.
  if (num_sub_events == 0) {
    events.push_back(absl::StrCat(event_info.name));
  }
  return absl::OkStatus();
}

absl::StatusOr<PMUEventList> DeduplicateEvents(const PMUEventList& events) {
  std::vector<std::string> unique_pmu_events;

  // Sort input to ensure a deterministic result.
  PMUEventList sorted_events(events.begin(), events.end());
  absl::c_sort(sorted_events);

  absl::flat_hash_set<std::string> unique_full_names;
  for (const auto& event : sorted_events) {
    ASSIGN_OR_RETURN_IF_NOT_OK(EventEncodingInfo info,
                               GetEventEncodingInfo(event));
    // Check for duplicate full event names.
    const bool inserted = unique_full_names.insert(info.full_name).second;
    if (inserted) {
      unique_pmu_events.push_back(event);
    }
  }
  return unique_pmu_events;
}

// Filters out events that are not supported by the proxy in-place. This is
// best-effort and non-exhaustive.
//
// For example, the proxy opens counters one at a time, so events that need to
// be grouped together are removed.
void FilterEvents(PMUEventList& events) {
  std::erase_if(events, [](absl::string_view event) {
#if defined(__aarch64__)
    // Skip `CHAIN` and `COUNTER_OVERFLOW` events.
    //
    // These events only work when paired with an adjacent counter, and it never
    // makes sense to open one in isolation (which is what the proxy does), as
    // they'll be rotated arbitrarily. This also returns an invalid argument
    // error for certain kernel versions.
    //
    // These are actually the same event, but they have different names under
    // different platforms.`CHAIN` is used in Ampere Siryn / Cavium TX2 and
    // `COUNTER_OVERFLOW` is used in ARM Neoverse platforms.
    if (event == "CHAIN" || event == "COUNTER_OVERFLOW") {
      LOG(INFO) << "Skipping " << event << " event";
      return true;
    }
#elif defined(__x86_64__)
    // Skip `TOPDOWN_M` events.
    //
    // From libpfm4: All TOPDOWN_M events must be in a Linux perf_events
    // group and SLOTS must be the first event for the kernel to program the
    // events onto the PERF_METRICS MSR.
    //
    // The fuzzer opens each event as a single counter, not as part of a group,
    // so we skip `TOPDOWN_M` events that will return an invalid argument error
    // here.
    if (absl::StartsWith(event, "TOPDOWN_M")) {
      LOG(INFO) << "Skipping " << event << " event";
      return true;
    }
#endif
    return false;
  });
}

}  // namespace

absl::StatusOr<PMUEventList> GetUniqueFilteredCPUCorePMUEvents() {
  RETURN_IF_NOT_OK(InitializeIfNecessary());
  const pfm_pmu_t pmu = GetCPUCorePMUOrDie();
  ASSIGN_OR_RETURN_IF_NOT_OK(pfm_pmu_info_t pmu_info, GetPMUInfo(pmu));

  // Adds all events and unique sub-events. Any events that are aliases are also
  // added.
  PMUEventList events;
  for (int id = pmu_info.first_event; id != -1; id = pfm_get_event_next(id)) {
    pfm_event_info_t event_info{};
    const pfm_err_t get_event_info_result =
        pfm_get_event_info(id, PFM_OS_NONE, &event_info);
    if (get_event_info_result != PFM_SUCCESS) {
      return absl::InternalError(
          absl::StrCat("pfm_get_event_info() failed: ",
                       pfm_strerror(get_event_info_result)));
    }
    RETURN_IF_NOT_OK(AddEventAndSubEvents(event_info, events));
  }

  if (events.empty()) {
    return absl::FailedPreconditionError("No PMU found.");
  }

  ASSIGN_OR_RETURN_IF_NOT_OK(events, DeduplicateEvents(events));
  FilterEvents(events);
  return events;
}

absl::StatusOr<std::vector<PMUEventList>> ScheduleEventsForCounters(
    const PMUEventList& events) {
  RETURN_IF_NOT_OK(InitializeIfNecessary());

  // Input events are broken up into source groups based on opaque event
  // indices so that sub-events are grouped together. In scheduling we pick
  // as many source groups as the number of programmable event counters. Then
  // we pick one event from each of the chosen source groups to form an output
  // event group. The output event groups are what we use for perf event
  // measurement. This is done to avoid having multiple sub-events of the same
  // event to be measured together.
  //
  // Despite our attempt here, it is not guaranteed that events schedule in a
  // group can run together. One some platforms, the performance counters are
  // not all the same. Some event may be counted using particular counters only.
  // Such information is not available to us and we cannot avoid scheduling
  // conflicting events into the a group.
  using SourceGroup = std::queue<std::string>;
  std::vector<SourceGroup> source_groups;
  pfm_pmu_t pmu = GetCPUCorePMUOrDie();

  // Maps event index to scheduling groups.
  absl::flat_hash_map<int, size_t> event_index_to_source_group_map;

  for (const std::string& event : events) {
    struct EventEncodingInfo encoding_info;
    ASSIGN_OR_RETURN_IF_NOT_OK(encoding_info, GetEventEncodingInfo(event));
    pfm_event_info_t event_info{};
    pfm_err_t err =
        pfm_get_event_info(encoding_info.idx, PFM_OS_NONE, &event_info);
    if (err != PFM_SUCCESS) {
      return absl::InternalError(absl::StrCat("pfm_get_event_info(", event,
                                              ") failed: ", pfm_strerror(err)));
    }

    // Verify that this event belongs to the core CPU PMU.
    if (event_info.pmu != pmu) {
      return absl::InvalidArgumentError(
          absl::StrCat("PMU ", event_info.pmu, " of event ", event,
                       " does not match CPU core PMU ", pmu));
    }

    auto it = event_index_to_source_group_map.find(encoding_info.idx);
    if (it == event_index_to_source_group_map.end()) {
      // Add a new source group for this event select value.
      it = event_index_to_source_group_map
               .insert({encoding_info.idx, source_groups.size()})
               .first;
      source_groups.push_back({});
    }
    source_groups[it->second].push(event);
  }

  // Construct a priority queue for scheduling based on source group size.
  struct SourceGroupLarger {
    bool operator()(size_t a, size_t b) const {
      return source_groups[a].size() > source_groups[b].size();
    }
    std::vector<SourceGroup>& source_groups;
  };
  std::priority_queue<size_t, std::vector<size_t>, SourceGroupLarger>
      scheduling_queue({.source_groups = source_groups});
  for (size_t i = 0; i < source_groups.size(); ++i) {
    scheduling_queue.push(i);
  }

  const size_t num_counters = GetNumCounters();
  std::vector<PMUEventList> output_groups;
  while (!scheduling_queue.empty()) {
    PMUEventList output_group;
    std::vector<size_t> indices_to_reinsert;

    // Pick as many source groups as number of counters in PMU.
    for (size_t i = 0; i < num_counters && !scheduling_queue.empty(); ++i) {
      // Pick a source group from the scheduling queue with the largest size.
      const size_t source_group_index = scheduling_queue.top();
      scheduling_queue.pop();

      // Move one event from the source group and into the current
      // output group.
      SourceGroup& source_group = source_groups[source_group_index];
      output_group.push_back(source_group.front());
      source_group.pop();

      if (!source_group.empty()) {
        indices_to_reinsert.push_back(source_group_index);
      }
    }

    // Re-insert non-empty source groups.
    for (const auto& index : indices_to_reinsert) {
      scheduling_queue.push(index);
    }

    // Emit output event group.
    output_groups.push_back(output_group);
  }

  return output_groups;
}
}  // namespace silifuzz
