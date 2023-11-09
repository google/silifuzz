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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_PERF_EVENT_FUZZER_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_PERF_EVENT_FUZZER_H_

#include <linux/perf_event.h>
#include <sys/user.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <queue>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/call_once.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "./common/harness_tracer.h"
#include "./proxies/pmu_event_proxy/perf_event_buffer.h"
#include "./proxies/pmu_event_proxy/perf_event_records.h"

namespace silifuzz {

// A container for perf event measurements used by the perf event fuzzer to
// return results.
//
// This class is thread-safe as it is read-only.
class PerfEventMeasurements {
 public:
  PerfEventMeasurements() = default;
  PerfEventMeasurements(absl::string_view event,
                        const std::vector<uint64_t>& counts)
      : event_(event), counts_(counts) {
    ComputeMeanAndStddev();
  }
  PerfEventMeasurements(absl::string_view event, std::vector<uint64_t>&& counts)
      : event_(event), counts_(std::move(counts)) {
    ComputeMeanAndStddev();
  }

  // Class by default copyable and movable.

  // Accessors.
  absl::string_view event() const { return event_; }
  const std::vector<uint64_t>& counts() const { return counts_; }
  const std::optional<double>& mean() const { return mean_; }
  const std::optional<double>& stddev() const { return stddev_; }

  // Equality operators defined for unit testing.
  // These are used in testing constructors, so bitwise equality is
  // assumed when comparing floating point values.
  bool operator==(const PerfEventMeasurements& other) const;
  bool operator!=(const PerfEventMeasurements& other) const;

 private:
  void ComputeMeanAndStddev();

  std::string event_;  // name of event.

  // Measured event counts.
  std::vector<uint64_t> counts_;

  // Mean of measurements or std::nullopt if counts is empty.
  std::optional<double> mean_;

  // Standard deviation of measurement or std::nullopt if size of counts
  // is less than 2.
  std::optional<double> stddev_;
};

// A helper class to manage a group of perf event descriptors. This is used by
// the perf event fuzzer. It is broken out as a separate class to facilitate
// testing.
//
// This class is thread-compatible.
class PerfEventGroup {
 public:
  // Information about an opened perf event descriptor.
  struct PerfEventDescriptor {
    // Name of the event for which descriptor is opened.
    // For non-leader event, this is used for look-up perf_event_attr from
    // libpfm4. For the leader event, it is for identification only.
    std::string event;
    // File descriptor of the opened perf event.
    int fd = -1;
    // unique ID of the event, valid only if fd >= 0.
    uint64_t id = 0;
  };

  // Destructor is public but clients should call Destroy() instead as there
  // is no way to report errors.
  ~PerfEventGroup();

  // Not copyable but movable.
  PerfEventGroup(const PerfEventGroup&) = delete;
  PerfEventGroup& operator=(const PerfEventGroup&) = delete;
  PerfEventGroup(PerfEventGroup&&) = default;
  PerfEventGroup& operator=(PerfEventGroup&&) = default;

  // Creates a perf event group with event called 'leader_event' with attributes
  // in '*attr' for the process/thread identified by 'pid' on any CPU. Read
  // format specified by '*attr' must have PERF_FORMAT_GROUP. For details about
  // read format, see man page of perf_event_open().  Returns a unique pointer
  // to a PerfEventGroup object or a status.
  static absl::StatusOr<std::unique_ptr<PerfEventGroup>> Create(
      absl::string_view leader_event, perf_event_attr* attr, pid_t pid);

  // Destroys 'group' and releases all resources. Returns a status.
  static absl::Status Destroy(std::unique_ptr<PerfEventGroup> group);

  // Adds a non-leading 'event' to this group and returns a status.
  // 'event' must be a recognized event name by libpfm4 for the current
  // platform. The added event is only enabled for user mode. Events
  // happen in kernel or hypervisor context are not counted.
  absl::Status AddPerfEvent(absl::string_view event);

  // Returns a const reference to the 'i'-th events of this. 'i' must be less
  // than number of events. The index is the order in which events are added,
  // with index 0 for the leader event.
  const PerfEventDescriptor& event(size_t i) const {
    DCHECK_LT(i, events_.size());
    return events_[i];
  }

  // Returns number of events in the group.
  size_t size() const { return events_.size(); }

 private:
  // Default constructor is private. Clients must use Create().
  PerfEventGroup() = default;

  // Wrapper for perf_event_open() API to return a status. Opens perf 'event'
  // using attributes in '*attr' for process/thread with id 'pid' on any CPU. If
  // 'group_fd' is not -1, the opened event will be a member of an existing
  // event group lead by test event with file descriptor 'group_fd'.
  absl::Status OpenPerfEvent(absl::string_view event, perf_event_attr* attr,
                             pid_t pid, int group_fd);

  // Closes all events and returns a status.  If there are multiple errors
  // this only reports one of them.
  absl::Status CloseAllEvents();

  // PID of the process/thread for which this event group is created.
  pid_t pid_ = -1;

  // Descriptors of opened perf events.
  std::vector<PerfEventDescriptor> events_;
};

// A PerfEventFuzzer takes a byte blobs and packages it as a snapshot for the
// current platform. It then execute the snapshot to generate perf event counter
// coverage.
//
// This class is thread-compatible.
class PerfEventFuzzer {
 public:
  using Event = std::string;
  using EventList = std::vector<Event>;
  using PerfEventMeasurementList = std::vector<PerfEventMeasurements>;

  // Options for the PerfEventFuzzer constructor.
  struct Options {
    static Options Default() { return {.schedule_events = true}; }

    // Schedule events to increase parallelism. This only works if
    // events belong to the native PMU of the current CPU.
    bool schedule_events;
  };

  // Constructs a PerfEventFuzzer with 'events' and 'options'.
  PerfEventFuzzer(const EventList& events, const Options& options)
      : options_(options), events_(events) {}

  // Constructs a PerfEventFuzzer with 'events' and default options.
  explicit PerfEventFuzzer(const EventList& events)
      : PerfEventFuzzer(events, Options::Default()) {}

  // Not copyable but movable.
  PerfEventFuzzer(const PerfEventFuzzer&) = delete;
  PerfEventFuzzer& operator=(const PerfEventFuzzer&) = delete;
  PerfEventFuzzer(PerfEventFuzzer&&) = default;
  PerfEventFuzzer& operator=(PerfEventFuzzer&&) = default;

  // Generate perf event counter coverage using 'data' of 'size' bytes.
  // Returns a PerfEventMeasurementList or an error status.
  absl::StatusOr<PerfEventMeasurementList> FuzzOneInput(const uint8_t* data,
                                                        size_t size,
                                                        size_t num_iterations);

 private:
  // Perf event sample types and formats used in perf_event_attr. See
  // perf_event_open() for details.
  static constexpr uint64_t kSampleType =
      PERF_SAMPLE_IP | PERF_SAMPLE_CPU | PERF_SAMPLE_READ;
  static constexpr uint64_t kReadFormat = PERF_FORMAT_GROUP | PERF_FORMAT_ID |
                                          PERF_FORMAT_TOTAL_TIME_ENABLED |
                                          PERF_FORMAT_TOTAL_TIME_RUNNING;

  // Maps sample ID to vector of successive counter measurements.
  using IdToCountsMap = absl::flat_hash_map<uint64_t, std::vector<uint64_t>>;

  // Queue of event groups. Events in each group are measured together.
  using WorkQueue = std::queue<EventList>;

  // Additional harness callback arguments and states packaged as a struct.
  struct CallbackState {
   public:
    ~CallbackState() {
      // Sanity checks to catch programming errors.
      CHECK(work_queue.empty());
      CHECK_EQ(callback_counter, 0);
      CHECK_EQ(perf_event_group, nullptr);
      CHECK_EQ(perf_event_buffer, nullptr);
    }

    // Initializes perf events counting for the process/thread associated with
    // 'pid' using the given 'events'. The fuzzer will create an extra event
    // acting as a leader for a group that contains all the given events.
    absl::Status InitPerfEvents(pid_t pid, const EventList& events);

    // Cleans up perf event monitoring for the current event group and returns
    // a status.
    absl::Status CleanupPerfEvents();

    // Helper of ProcessPerfSamples. Computes diffs of corresponding count
    // values in 'start' and 'end' and appends the deltas to 'id_to_counts_map'.
    void UpdateEventCounts(const PerfEventSampleRecord& start,
                           const PerfEventSampleRecord& end,
                           IdToCountsMap& id_to_counts_map);

    // Processes perf samples from currently in the perf event buffer and
    // and appends result to measurements
    absl::Status ProcessPerfSamples();

    // Callback for HarnessTracer.
    HarnessTracer::ContinuationMode HarnessTracerCallback(
        pid_t pid, const user_regs_struct& regs,
        HarnessTracer::CallbackReason reason);

    // Number of measurements per event.
    size_t measurements_per_event;

    // Data address of breakpoint.
    uintptr_t breakpoint_data_addr;

    // Code addresses of data breakpoints in the snapshot being fuzzed.
    uintptr_t breakpoint_code_addr_1;
    uintptr_t breakpoint_code_addr_2;

    // Maps event names to indices to measurements.
    const absl::flat_hash_map<Event, size_t>* event_index_map;

    // Queue of event groups to be measured.
    WorkQueue work_queue;

    // Reports any errors in callback.  If there are multiple errors, this
    // is the first error.
    absl::Status callback_status;

    // Decrements every time callback is invoked. This is used to sequence
    // successive measurements of event groups using a single tracing run.
    size_t callback_counter = 0;

    // Callback appends measurements to here. Elements of this must be in
    // same order as events_ of the perf event fuzzer.
    PerfEventMeasurementList measurements;

    // Group of opened perf events. This is initialized by InitPerfEvents().
    std::unique_ptr<PerfEventGroup> perf_event_group;

    // Perf event buffer. This is also initialized by InitPerfEvents().
    std::unique_ptr<PerfEventBuffer> perf_event_buffer;
  };

  // Initializes the fuzzer and returns status.
  absl::Status Init();

  // -------------------------------------------------------------------------
  // Fuzzer state that is unchanged for all inputs.

  // Options for the fuzzer.
  Options options_;

  // List of events to be fuzzed. This is passed to the constructor.
  EventList events_;

  // Cached exit status of Init().
  absl::Status init_status_;

  // List of events that are scheduled to be fuzzed.
  // This is initialized by Init().
  std::vector<EventList> scheduled_events_;

  // Map events into indices in events_.
  absl::flat_hash_map<Event, size_t> event_index_map_;

  // Once flag to ensure Init() is only called once.
  absl::once_flag init_once_flag_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_PERF_EVENT_FUZZER_H_
