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
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/log:check",
    ],
)

cc_test(
    name = "ring_buffer_view_test",
    srcs = ["ring_buffer_view_test.cc"],
    tags = ["manual"],
    deps = [
        ":ring_buffer_view",
        "@googletest//:gtest_main",
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
        "@abseil-cpp//absl/algorithm:container",
        "@abseil-cpp//absl/base",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@libpfm//:pfm",
    ],  # buildifier: disable=platform-specific-binaries
    # This lint is not relevant; the library can be built for all platforms, but contains some
    # platform-specific logic which triggers the lint.
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
        "@abseil-cpp//absl/log",
        "@googletest//:gtest",
        "@googletest//:gtest_main",
        "@libpfm//:pfm",
    ],
)

cc_library(
    name = "perf_event_records",
    srcs = ["perf_event_records.cc"],
    hdrs = ["perf_event_records.h"],
    deps = [
        ":ring_buffer_view",
        "@silifuzz//util:checks",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
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
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "perf_event_records_fuzz_test",
    srcs = ["perf_event_records_fuzz_test.cc"],
    tags = ["manual"],
    deps = [
        ":perf_event_records",
        ":ring_buffer_view",
        "@abseil-cpp//absl/log:check",
        "@fuzztest//fuzztest",
        "@googletest//:gtest_main",
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
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@libpfm//:pfm",
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
        "@silifuzz//util:cpu_id",
        "@silifuzz//util/testing:status_macros",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/random:distributions",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/synchronization",
        "@abseil-cpp//absl/time",
        "@googletest//:gtest_main",
        "@libpfm//:pfm",
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
        "@silifuzz//common:snapshot",
        "@silifuzz//runner:make_snapshot",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//runner/driver:runner_driver",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@abseil-cpp//absl/base",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:string_view",
        "@libpfm//:pfm",
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
        "@silifuzz//runner:make_snapshot",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//runner/driver:runner_driver",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings:string_view",
        "@googletest//:gtest_main",
        "@libpfm//:pfm",
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
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:proxy_config",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//instruction:default_disassembler",
        "@silifuzz//proxies:arch_feature_generator",
        "@silifuzz//proxies:user_features",
        "@silifuzz//proxies/util:set_process_dumpable",
        "@silifuzz//tracing:extension_registers",
        "@silifuzz//tracing:native_tracer",
        "@silifuzz//tracing:tracer",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@fuzztest//centipede:centipede_runner",
        "@fuzztest//centipede:feature",
        "@libpfm//:pfm",
    ],
)
