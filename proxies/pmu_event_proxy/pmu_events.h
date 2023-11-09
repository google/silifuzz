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

#ifndef THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_PMU_EVENTS_H_
#define THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_PMU_EVENTS_H_
#include <string>
#include <vector>

#include "absl/status/statusor.h"

namespace silifuzz {

using PMUEventList = std::vector<std::string>;

// Returns a list of all unique CPU core hardware performance events
// and sub-events on the current platform. Event aliases are de-duped. The names
// of events and sub events returned are the same in version 4 of perform2
// library on Linux (libpfm4).
absl::StatusOr<PMUEventList> GetUniqueCPUCorePMUEvents();

// Returns a list of event groups, each of which contains events that can
// be measured together based on the number of variable counters in their
// PMUs. If there is any error, returns a status.
absl::StatusOr<std::vector<PMUEventList>> ScheduleEventsForCounters(
    const PMUEventList& events);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_PROXIES_PMU_EVENT_PROXY_PMU_EVENTS_H_
