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

# Description:
#   Libraries and binaries for different variants/components of the snapshot
#   player.

load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

# =========================================================================== #

cc_library(
    name = "trace_options",
    srcs = ["trace_options.cc"],
    hdrs = ["trace_options.h"],
    deps = [
        ":play_options",
        "@silifuzz//util:arch",
    ],
)

cc_library(
    name = "play_options",
    srcs = ["play_options.cc"],
    hdrs = ["play_options.h"],
    deps = [
        "@silifuzz//util:cpu_id",
        "@abseil-cpp//absl/time",
    ],
)

cc_library(
    name = "player_result_proto",
    srcs = [
        "player_result_proto.cc",
    ],
    hdrs = ["player_result_proto.h"],
    deps = [
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//common:snapshot_proto",
        "@silifuzz//common:snapshot_types",
        "@silifuzz//proto:player_result_cc_proto",
        "@silifuzz//proto:snapshot_cc_proto",
        "@silifuzz//util:checks",
        "@silifuzz//util:cpu_id",
        "@silifuzz//util:misc_util",
        "@silifuzz//util:proto_util",
        "@silifuzz//util:time_proto_util",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/time",
    ],
)

cc_test(
    name = "player_result_proto_test",
    srcs = ["player_result_proto_test.cc"],
    deps = [
        ":player_result_proto",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//proto:player_result_cc_proto",
        "@silifuzz//proto:snapshot_cc_proto",
        "@silifuzz//util:checks",
        "@silifuzz//util:time_proto_util",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/time",
        "@googletest//:gtest_main",
        "@protobuf",
    ],
)
