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
#   Common libraries for various snapshot tools that operate on a collection
#   of snapshots.  The main focus here is manipulating snapshots as a group of
#   entities and not manipulating the internals of snapshots, which are handled
#   by various libraries in silifuzz/common/

load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

# =========================================================================== #

cc_library(
    name = "corpus_partitioner_lib",
    srcs = ["corpus_partitioner_lib.cc"],
    hdrs = ["corpus_partitioner_lib.h"],
    deps = [
        ":snap_group",
        "@silifuzz//util:checks",
        "@abseil-cpp//absl/algorithm:container",
    ],
)

cc_test(
    name = "corpus_partitioner_lib_test",
    srcs = ["corpus_partitioner_lib_test.cc"],
    deps = [
        ":corpus_partitioner_lib",
        ":snap_group",
        "@silifuzz//common:memory_mapping",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:snapshot",
        "@silifuzz//util:checks",
        "@abseil-cpp//absl/strings",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "fix_tool_common",
    srcs = ["fix_tool_common.cc"],
    hdrs = ["fix_tool_common.h"],
    deps = [
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_util",
        "@silifuzz//player:play_options",
        "@silifuzz//player:trace_options",
        "@silifuzz//runner:make_snapshot",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:hostname",
        "@silifuzz//util:itoa",
        "@silifuzz//util:page_util",
        "@silifuzz//util:platform",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
    ],
)

cc_library(
    name = "simple_fix_tool_counters",
    hdrs = ["simple_fix_tool_counters.h"],
    deps = [
        ":fix_tool_common",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/meta:type_traits",
        "@abseil-cpp//absl/strings",
    ],
)

cc_test(
    name = "simple_fix_tool_counters_test",
    srcs = ["simple_fix_tool_counters_test.cc"],
    deps = [
        ":simple_fix_tool_counters",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "snap_group",
    srcs = ["snap_group.cc"],
    hdrs = ["snap_group.h"],
    deps = [
        "@silifuzz//common:mapped_memory_map",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:snapshot",
        "@silifuzz//util:checks",
        "@silifuzz//util:thread_pool",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/status",
    ],
)

cc_test(
    name = "snap_group_test",
    srcs = ["snap_group_test.cc"],
    deps = [
        ":snap_group",
        "@silifuzz//common:mapped_memory_map",
        "@silifuzz//common:memory_mapping",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_test_enum",
        "@silifuzz//common:snapshot_test_util",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:platform",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/status",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "snapshot_summary_proto_util",
    srcs = ["snapshot_summary_proto_util.cc"],
    hdrs = ["snapshot_summary_proto_util.h"],
    deps = [
        ":snap_group",
        "@silifuzz//common:memory_mapping",
        "@silifuzz//common:snapshot_proto",
        "@silifuzz//proto:snapshot_cc_proto",
        "@silifuzz//util:checks",
        "@abseil-cpp//absl/status:statusor",
    ],
)
