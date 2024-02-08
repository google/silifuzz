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

#include "./proxies/pmu_event_proxy/perf_event_fuzzer.h"

#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/call_once.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "./common/harness_tracer.h"
#include "./common/snapshot.h"
#include "./proxies/pmu_event_proxy/counter_read_trigger.h"
#include "./proxies/pmu_event_proxy/perf_event_buffer.h"
#include "./proxies/pmu_event_proxy/perf_event_records.h"
#include "./proxies/pmu_event_proxy/pmu_events.h"
#include "./runner/driver/runner_driver.h"
#include "./runner/make_snapshot.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "external/libpfm4/include/perfmon/pfmlib.h"
#include "external/libpfm4/include/perfmon/pfmlib_perf_event.h"

namespace silifuzz {

void PerfEventMeasurements::ComputeMeanAndStddev() {
  if (counts_.empty()) {
    mean_ = std::nullopt;
  } else {
    double sum_counts = 0;
    for (size_t count : counts_) {
      sum_counts += count;
    }
    mean_ = sum_counts / counts_.size();
  }

  if (counts_.size() < 2) {
    stddev_ = std::nullopt;
  } else {
    double sum_sqaure_diffs = 0;
    for (size_t count : counts_) {
      const double diff = count - mean_.value();
      sum_sqaure_diffs += diff * diff;
    }
    stddev_ = std::sqrt(sum_sqaure_diffs / (counts_.size() - 1));
  }
}

bool PerfEventMeasurements::operator==(
    const PerfEventMeasurements& other) const {
  return event_ == other.event_ && counts_ == other.counts_ &&
         mean_ == other.mean_ && stddev_ == other.stddev_;
}

bool PerfEventMeasurements::operator!=(
    const PerfEventMeasurements& other) const {
  return !(*this == other);
}

//---------------------------------------------------------------

PerfEventGroup::~PerfEventGroup() {
  CHECK(events_.empty()) << "PerfEventGroup::Destroy() not called.";
}

// static
absl::StatusOr<std::unique_ptr<PerfEventGroup>> PerfEventGroup::Create(
    absl::string_view event, perf_event_attr* attr, pid_t pid) {
  std::unique_ptr<PerfEventGroup> group(new PerfEventGroup);
  group->pid_ = pid;
  if ((attr->read_format & PERF_FORMAT_GROUP) == 0) {
    return absl::InvalidArgumentError("Invalid perf event format");
  }

  RETURN_IF_NOT_OK(group->OpenPerfEvent(event, attr, pid, -1));
  return group;
}

// static
absl::Status PerfEventGroup::Destroy(std::unique_ptr<PerfEventGroup> group) {
  return group->CloseAllEvents();
}

absl::Status PerfEventGroup::AddPerfEvent(absl::string_view event) {
  perf_event_attr attr{.size = sizeof(perf_event_attr)};
  pfm_perf_encode_arg_t arg{.attr = &attr,
                            .size = sizeof(pfm_perf_encode_arg_t)};
  pfm_err_t err = pfm_get_os_event_encoding(std::string(event).c_str(),
                                            PFM_PLM3, PFM_OS_PERF_EVENT, &arg);
  if (err != PFM_SUCCESS) {
    return absl::InvalidArgumentError(absl::StrCat(
        "pfm_get_os_event_encoding(", event, ") failed: ", pfm_strerror(err)));
  }
  // Count event in user context only.
  attr.exclude_kernel = 1;
  attr.exclude_hv = 1;
  return OpenPerfEvent(event, &attr, pid_, events_[0].fd);
}

absl::Status PerfEventGroup::OpenPerfEvent(absl::string_view event,
                                           perf_event_attr* attr, pid_t pid,
                                           int group_fd) {
  // Open the named perf event to monitor the runner process/thread on any CPU.
  // The new event will join the perf event group led by the breakpoint event.
  const int fd = perf_event_open(attr, pid, -1 /* any CPU */, group_fd, 0);
  if (fd == -1) {
    return absl::ErrnoToStatus(
        errno, absl::StrCat("Failed to open perf event ", event));
  }

  // Get the event ID that the kernel uses to tag samples from this event.
  uint64_t id = 0;
  if (ioctl(fd, PERF_EVENT_IOC_ID, &id) != 0) {
    const int ioctl_errno = errno;  // save errno before close().
    close(fd);
    return absl::ErrnoToStatus(
        ioctl_errno, absl::StrCat("Failed to get ID for perf event ", event));
  }

  events_.push_back(
      PerfEventDescriptor{.event = std::string(event), .fd = fd, .id = id});
  return absl::OkStatus();
}

absl::Status PerfEventGroup::CloseAllEvents() {
  // Close all perf events. We do not exit at the first error
  // to reduce the chance of descriptor leak.
  absl::Status last_error_status = absl::OkStatus();
  for (auto& event : events_) {
    if (close(event.fd) < 0) {
      last_error_status = absl::ErrnoToStatus(
          errno, absl::StrCat("Failed to close ", event.event));
    }
  }
  events_.clear();
  return last_error_status;
}

//---------------------------------------------------------------

absl::Status PerfEventFuzzer::CallbackState::InitPerfEvents(
    pid_t pid, const EventList& events) {
  CHECK(!perf_event_group);
  CHECK(!perf_event_buffer);
  struct perf_event_attr attr {
    .type = PERF_TYPE_BREAKPOINT, .size = sizeof(perf_event_attr),
    // Generate a sample everytime the leader event happens.
        .sample_period = 1, .sample_type = kSampleType,
    .read_format = kReadFormat, .pinned = 1, .exclude_kernel = 1,
    .exclude_hv = 1, .exclude_idle = 1,
    // The leader event is a data breakpoint.  It triggers whenever this
    // magic address is written.
        .bp_type = HW_BREAKPOINT_W, .bp_addr = breakpoint_data_addr,
    .bp_len = HW_BREAKPOINT_LEN_1,
  };
  ASSIGN_OR_RETURN_IF_NOT_OK(perf_event_group,
                             PerfEventGroup::Create("breakpoint", &attr, pid));
  EventList bad_events;
  absl::Status first_bad_status;
  for (const auto& event : events) {
    absl::Status status = perf_event_group->AddPerfEvent(event);
    if (!status.ok()) {
      bad_events.push_back(event);
      first_bad_status.Update(status);
    }
  }

  // We may fail to open a perf event for different reasons. An event counter
  // may not be supported by all kernel versions. Even for supported
  // counters, we may fail to open multiple counters in the same counter group
  // because of scheduling conflicts. We retry failed events if not all events
  // failed.
  if (!bad_events.empty()) {
    if (perf_event_group->size() == 1) {
      // If there is only the breakpoint event, it means all events in the
      // given group failed to open. Return the first error.
      LOG_FIRST_N(ERROR, 100) << "Failed to open event " << bad_events[0] << ":"
                              << first_bad_status;
      // TODO(dougkwan): report error when we can configure list of events
      // fuzzed by PMU event proxy. For now ignore this and continue.
      // We will not get any measurement for this event group.
    } else {
      // If only some of the events failed, retry failed events.
      for (const auto& event : bad_events) {
        // Re-queue failed events individually.
        work_queue.push({event});
      }
    }
  }

  // Use a 64kb buffer. This should be enough for several hundred events.
  constexpr size_t kPerfEventBufferSize = 1 << 16;
  ASSIGN_OR_RETURN_IF_NOT_OK(
      perf_event_buffer,
      PerfEventBuffer::Create(perf_event_group->event(0).fd,
                              kPerfEventBufferSize, kSampleType, kReadFormat));
  return absl::OkStatus();
}

absl::Status PerfEventFuzzer::CallbackState::CleanupPerfEvents() {
  absl::Status status;
  if (perf_event_buffer) {
    status.Update(PerfEventBuffer::Destroy(std::move(perf_event_buffer)));
    perf_event_buffer.reset();
  }
  if (perf_event_group) {
    status.Update(PerfEventGroup::Destroy(std::move(perf_event_group)));
    perf_event_group.reset();
  }
  return status;
}

void PerfEventFuzzer::CallbackState::UpdateEventCounts(
    const PerfEventSampleRecord& start, const PerfEventSampleRecord& end,
    IdToCountsMap& id_to_counts_maps) {
  // Paranoia check: The two records should have the exact same shape.
  CHECK_EQ(start.sample_type(), end.sample_type());
  CHECK_EQ(start.v().format(), end.v().format());
  CHECK_EQ(start.v().nr(), end.v().nr());

  // Do not record deltas if counters are not running all the time.
  // Otherwise, counters are multiplexed and we only have extrapolated values.
  const uint64_t time_enabled =
      end.v().time_enabled() - start.v().time_enabled();
  const uint64_t time_running =
      end.v().time_running() - start.v().time_running();
  if (time_enabled != time_running) {
    return;
  }

  for (size_t i = 0; i < end.v().nr(); ++i) {
    const uint64_t id = end.v().id(i);
    // Paranoia check: The kernel should not re-arrange the values
    // between records.
    CHECK_EQ(start.v().id(i), id);
    std::vector<uint64_t>& counts = id_to_counts_maps[id];
    counts.push_back(end.v().value(i) - start.v().value(i));
  }
}

absl::Status PerfEventFuzzer::CallbackState::ProcessPerfSamples() {
  IdToCountsMap id_to_counts_maps;
  id_to_counts_maps.reserve(perf_event_group->size());

  ssize_t record_number = 0;
  PerfEventSampleRecord start_sample_record;
  ssize_t start_record_number = -1;
  for (absl::StatusOr<perf_event_type> next_event_type =
           perf_event_buffer->NextEventType();
       next_event_type.ok();
       next_event_type = perf_event_buffer->NextEventType()) {
    switch (next_event_type.value()) {
      case PERF_RECORD_SAMPLE: {
        absl::StatusOr<PerfEventSampleRecord> sample_record =
            perf_event_buffer->ReadSampleRecord();
        RETURN_IF_NOT_OK(sample_record.status());
        if (sample_record->ip() == breakpoint_code_addr_1) {
          // Save sample record at breakpoint_address_1 so that we can match
          // it with the next record at breakpoint_address_2.
          start_sample_record = std::move(sample_record.value());
          start_record_number = record_number;
        } else if (sample_record->ip() == breakpoint_code_addr_2) {
          // Drop this measurement if there is anything between the pair of
          // sample records.
          if (record_number < 1 || record_number != start_record_number + 1) {
            break;
          }
          UpdateEventCounts(start_sample_record, sample_record.value(),
                            id_to_counts_maps);
        }
        break;
      }
      default:
        // We may end up here if the buffer is too small and the kernel cannot
        // store samples. Under such circumstance, we will get a
        // PERF_RECORD_LOST_SAMPLES event, which we cannot handled yet. For now,
        // just bump up the buffer size if that ever happens.
        LOG(FATAL) << "Unhandled type " << next_event_type.value();
    }
    record_number++;
  }

  for (size_t i = 1 /* skip leader */; i < perf_event_group->size(); ++i) {
    const PerfEventGroup::PerfEventDescriptor& event_descriptor =
        perf_event_group->event(i);
    // If we failed to open this perf event, counts will be an empty vector.
    std::vector<uint64_t>& counts = id_to_counts_maps[event_descriptor.id];
    auto it = event_index_map->find(event_descriptor.event);
    CHECK(it != event_index_map->end());
    CHECK_EQ(measurements[it->second].event(), event_descriptor.event);
    measurements[it->second] =
        PerfEventMeasurements{event_descriptor.event, std::move(counts)};
    counts.clear();
  }
  return absl::OkStatus();
}

// This callback always returns HarnessTracer::kStopTracing such that it is
// called twice before execution of each snapshot with 'reason'
// kSingleStepStop and kBecomingInactive. The callback is not called right after
// snapshot execution thus a perf sample record is not available until the
// callback is called before the next snapshot execution. This means that when
// TraceOne() finishes, there will be uncollected perf sample records in the
// perf event buffer. FuzzOneInput() does an extra call to TraceOne() after
// draining the work queue in order to collect the very last perf sample
// records.
HarnessTracer::ContinuationMode
PerfEventFuzzer::CallbackState::HarnessTracerCallback(
    pid_t pid, const user_regs_struct& regs,
    HarnessTracer::CallbackReason reason) {
  // To simplify counting, we only do real work if 'reason' is kSingleStepStop.
  if (reason != HarnessTracer::kSingleStepStop) {
    return HarnessTracer::kStopTracing;
  }

  // If this is the last time callback is visited for the current event group,
  // collect and process perf sample records.
  if (callback_counter == 0) {
    // Finish the current event group.
    if (perf_event_buffer) {
      // Process perf samples in buffer and release buffer afterwards.
      callback_status.Update(ProcessPerfSamples());
    }
    callback_status.Update(CleanupPerfEvents());

    // Get the next event group.
    if (!work_queue.empty()) {
      EventList events = std::move(work_queue.front());
      work_queue.pop();
      VLOG_INFO(1, "Fuzzing one event group: ", absl::StrJoin(events, ", "));
      callback_status.Update(InitPerfEvents(pid, events));
      // This many kSingleStepStop calls to callback remains for this group.
      callback_counter = measurements_per_event - 1;
    }
  } else {
    --callback_counter;
  }

  // Tell harness tracer that we are not tracing. If 'reason' is
  // kSingleStepStop, returning kStopTracing here causes the callback to be
  // called again at the same target address with kBecomingInactive.
  return HarnessTracer::kStopTracing;
}

//---------------------------------------------------------------

absl::Status PerfEventFuzzer::Init() {
  for (size_t i = 0; i < events_.size(); ++i) {
    event_index_map_[events_[i]] = i;
  }

  if (options_.schedule_events) {
    ASSIGN_OR_RETURN_IF_NOT_OK(std::vector<PMUEventList> schedule_events,
                               ScheduleEventsForCounters(events_));
    for (const auto& event_list : schedule_events) {
      scheduled_events_.push_back(event_list);
    }
  } else {
    for (const auto& event : events_) {
      scheduled_events_.push_back({event});
    }
  }
  return absl::OkStatus();
}

absl::StatusOr<PerfEventFuzzer::PerfEventMeasurementList>
PerfEventFuzzer::FuzzOneInput(const uint8_t* data, size_t size,
                              size_t num_iterations) {
  absl::call_once(init_once_flag_, [this]() { init_status_ = Init(); });
  if (!init_status_.ok()) {
    return absl::FailedPreconditionError(absl::StrCat(
        "Failed to initialize PerfEventFuzzer: ", init_status_.message()));
  }

  // Creates a snapshot using input data.
  // Bracket input with two breakpoints to trigger counter reading.
  const CounterReadTrigger counter_read_trigger = GetCounterReadTrigger<Host>();
  const std::string wrapped_input =
      absl::StrCat(counter_read_trigger.code,
                   absl::string_view(reinterpret_cast<const char*>(data), size),
                   counter_read_trigger.code);

  // Make snapshot from instruction data and record the end state and memory
  // bytes. Also verify that this is a good snapshot that runs to completion
  // without problems.
  MakingConfig config = MakingConfig::Quick();
  ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot made_snapshot,
                             MakeRawInstructions(wrapped_input, config));

  CallbackState callback_state;
  callback_state.measurements_per_event = num_iterations;

  // We need to know the starting PC of the snapshot to process perf events.
  // We perf events are generated as different addresses, we only want to
  // use samples front the start and end of the snapshot. When a data
  // breakpoint triggers, the perf event sample is associated with the address
  // after the triggering instruction.
  callback_state.breakpoint_data_addr =
      counter_read_trigger.breakpoint_data_address;
  uint64_t start_address = made_snapshot.ExtractRip(made_snapshot.registers());
  callback_state.breakpoint_code_addr_1 =
      start_address + counter_read_trigger.breakpoint_code_offset;
  callback_state.breakpoint_code_addr_2 =
      start_address + counter_read_trigger.code.size() + size +
      counter_read_trigger.breakpoint_code_offset;
  callback_state.event_index_map = &event_index_map_;

  // Construct a runner driver for the single snapshot.  The driver will be
  // re-used multiple times.
  ASSIGN_OR_RETURN_IF_NOT_OK(
      RunnerDriver runner_driver,
      RunnerDriverFromSnapshot(made_snapshot, config.runner_path));

  for (const EventList& event_group : scheduled_events_) {
    callback_state.work_queue.push(event_group);
  }

  // Pre-populate measurements with empty results in case some events cannot be
  // measured.
  callback_state.measurements.reserve(events_.size());
  for (size_t i = 0; i < events_.size(); ++i) {
    callback_state.measurements.push_back(
        PerfEventMeasurements{events_[i], {}});
  }

  // Drain work queue with 'num_iterations' of tracing. Return a combined
  // status of TraceOne() and callback state.
  auto drain_work_queue = [&runner_driver, &made_snapshot,
                           &callback_state](size_t num_iterations) {
    absl::StatusOr<RunnerDriver::RunResult> run_result = runner_driver.TraceOne(
        made_snapshot.id(),
        [&callback_state](pid_t pid, const user_regs_struct& regs,
                          HarnessTracer::CallbackReason reason) {
          return callback_state.HarnessTracerCallback(pid, regs, reason);
        },
        num_iterations);
    RETURN_IF_NOT_OK(callback_state.callback_status);
    RETURN_IF_NOT_OK(run_result.status());
    if (!run_result->success()) {
      return absl::InternalError("Snapshot failed to run.");
    }
    return absl::OkStatus();
  };

  absl::Status status;
  while (status.ok() && !callback_state.work_queue.empty()) {
    // Run all event groups currently in the work queue. Perf events that failed
    // to open may be re-queued. Requeue events are processed in the next
    // iteration.
    status.Update(drain_work_queue(callback_state.measurements_per_event *
                                   callback_state.work_queue.size()));
  }

  // If runner crashes for some reason, the harness tracer callback may not be
  // called the expected number of time.
  if (callback_state.callback_counter != 0) {
    status.Update(absl::InternalError((absl::StrCat(
        callback_state.callback_counter, " callbacks were not called."))));
  }

  // Call TraceOne() once more to collect the last perf sample records.
  // See HarnessTracerCallback() for why this is needed.
  status.Update(drain_work_queue(1));

  // If there is any error, fuzzer may be in an inconsistent state.
  // Try our best to clean up to avoid resource leak.
  if (!status.ok()) {
    absl::Status cleanup_status = callback_state.CleanupPerfEvents();
    if (!cleanup_status.ok()) {
      LOG(ERROR) << "Failed to clean up perf events: "
                 << cleanup_status.message();
      // Clear these for sanity check in destructor.
      WorkQueue empty_work_queue;
      callback_state.work_queue.swap(empty_work_queue);
      callback_state.callback_counter = 0;
    }
  }
  CHECK_EQ(callback_state.perf_event_buffer, nullptr);
  CHECK_EQ(callback_state.perf_event_group, nullptr);
  RETURN_IF_NOT_OK(status);

  // Inputs ending with partial instructions cannot be instrumented correctly
  // even though they may not cause any fuzzing error. Return an error if
  // none of the perf events have any measurements.
  if (std::all_of(callback_state.measurements.begin(),
                  callback_state.measurements.end(),
                  [](const PerfEventMeasurements& measurements) {
                    return measurements.event().empty();
                  })) {
    return absl::NotFoundError("No measurements found.");
  }

  return callback_state.measurements;
}

}  // namespace silifuzz
