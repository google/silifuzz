# Copyright 2023 The SiliFuzz Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Proxy using PMU events.

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

cc_library(
    name = "ring_buffer_view",
    hdrs = ["ring_buffer_view.h"],
    deps = [
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/log:check",
    ],
)

cc_test(
    name = "ring_buffer_view_test",
    srcs = ["ring_buffer_view_test.cc"],
    tags = ["manual"],
    deps = [
        ":ring_buffer_view",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "pmu_events",
    srcs = [
        "pmu_events.cc",
    ],
    hdrs = ["pmu_events.h"],
    deps = [
        "@silifuzz//util:checks",
        "@silifuzz//util:x86_cpuid",
        "@com_google_absl//absl/algorithm:container",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@libpfm4//:pfm4",
    ],
)

cc_test(
    name = "pmu_events_test",
    srcs = [
        "pmu_events_test.cc",
    ],
    tags = ["manual"],
    deps = [
        ":pmu_events",
        "@silifuzz//util/testing:status_macros",
        "@com_google_absl//absl/log",
        "@com_google_googletest//:gtest",
        "@com_google_googletest//:gtest_main",
        "@libpfm4//:pfm4",
    ],
)

cc_library(
    name = "perf_event_records",
    srcs = ["perf_event_records.cc"],
    hdrs = ["perf_event_records.h"],
    deps = [
        ":ring_buffer_view",
        "@silifuzz//util:checks",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "perf_event_records_test",
    srcs = ["perf_event_records_test.cc"],
    tags = ["manual"],
    deps = [
        ":perf_event_records",
        ":ring_buffer_view",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "perf_event_records_fuzz_test",
    srcs = ["perf_event_records_fuzz_test.cc"],
    tags = ["manual"],
    deps = [
        ":perf_event_records",
        ":ring_buffer_view",
        "@com_google_absl//absl/log:check",
        "@com_google_fuzztest//fuzztest",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "perf_event_buffer",
    srcs = ["perf_event_buffer.cc"],
    hdrs = ["perf_event_buffer.h"],
    deps = [
        ":perf_event_records",
        ":ring_buffer_view",
        "@silifuzz//util:checks",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@libpfm4//:pfm4",
    ],
)

cc_test(
    name = "perf_event_buffer_test",
    size = "small",
    srcs = ["perf_event_buffer_test.cc"],
    tags = ["manual"],
    deps = [
        ":perf_event_buffer",
        ":perf_event_records",
        "@silifuzz//util/testing:status_macros",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/random:distributions",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
        "@libpfm4//:pfm4",
    ],
)

cc_library(
    name = "perf_event_fuzzer",
    srcs = [
        "counter_read_trigger.cc",
        "counter_read_trigger.h",
        "perf_event_fuzzer.cc",
    ],
    hdrs = ["perf_event_fuzzer.h"],
    deps = [
        ":perf_event_buffer",
        ":perf_event_records",
        ":pmu_events",
        "@silifuzz//common:harness_tracer",
        "@silifuzz//common:raw_insns_util",
        "@silifuzz//common:snapshot",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//runner:snap_maker",
        "@silifuzz//runner/driver:runner_driver",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:string_view",
        "@libpfm4//:pfm4",
    ],
)

cc_test(
    name = "perf_event_fuzzer_test",
    size = "medium",
    srcs = ["perf_event_fuzzer_test.cc"],
    tags = ["manual"],
    deps = [
        ":perf_event_buffer",
        ":perf_event_fuzzer",
        "@silifuzz//common:harness_tracer",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_test_enum",
        "@silifuzz//common:snapshot_test_util",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//runner:snap_maker",
        "@silifuzz//runner/driver:runner_driver",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:string_view",
        "@com_google_googletest//:gtest_main",
        "@libpfm4//:pfm4",
    ],
)

cc_binary(
    name = "pmu_event_proxy",
    testonly = True,
    srcs = ["pmu_event_proxy.cc"],
    linkopts = [
        "-ldl",
        "-lrt",
        "-lpthread",
    ],
    deps = [
        ":perf_event_fuzzer",
        ":pmu_events",
        "@silifuzz//proxies:user_features",
        "@silifuzz//proxies/util:set_process_dumpable",
        "@silifuzz//util:checks",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_fuzztest//centipede:centipede_runner",
        "@com_google_fuzztest//centipede:feature",
        "@libpfm4//:pfm4",
    ],
)
