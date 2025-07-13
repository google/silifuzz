# Copyright 2022 The SiliFuzz Authors.
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

load("//third_party/bazel_rules/rules_cc/cc:cc_library.bzl", "cc_library")
load("//third_party/bazel_rules/rules_cc/cc:cc_test.bzl", "cc_test")

# Library to drive a single SiliFuzz v2 runner binary.
#
package(default_visibility = ["//visibility:public"])

licenses(["notice"])

cc_library(
    name = "runner_options",
    srcs = ["runner_options.cc"],
    hdrs = ["runner_options.h"],
    deps = [
        "@silifuzz//util:checks",
        "@silifuzz//util:cpu_id",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
    ],
)

cc_library(
    name = "runner_driver",
    srcs = ["runner_driver.cc"],
    hdrs = ["runner_driver.h"],
    deps = [
        ":runner_options",
        "@silifuzz//common:harness_tracer",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//player:player_result_proto",
        "@silifuzz//proto:snapshot_execution_result_cc_proto",
        "@silifuzz//snap/gen:relocatable_snap_generator",
        "@silifuzz//util:arch",
        "@silifuzz//util:byte_io",
        "@silifuzz//util:checks",
        "@silifuzz//util:cpu_id",
        "@silifuzz//util:mmapped_memory_ptr",
        "@silifuzz//util:subprocess",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "@protobuf",
    ],
)

cc_test(
    name = "runner_driver_test",
    size = "medium",
    srcs = ["runner_driver_test.cc"],
    data = [
        "@silifuzz//snap/testing:test_corpus",
    ],
    deps = [
        ":runner_driver",
        "@silifuzz//common:harness_tracer",
        "@silifuzz//common:proxy_config",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//common:snapshot_test_enum",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//snap/testing:snap_test_snapshots",
        "@silifuzz//util:arch",
        "@silifuzz//util:data_dependency",
        "@silifuzz//util:itoa",
        "@silifuzz//util:path_util",
        "@silifuzz//util:user_regs_util",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/ucontext:serialize",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/status:statusor",
        "@googletest//:gtest_main",
    ],
)
