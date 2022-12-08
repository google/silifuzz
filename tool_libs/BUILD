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

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

# =========================================================================== #

DISABLE_ARM_TAGS = [
    "not_build:arm",
    "not_test:arm",
]

cc_library(
    name = "corpus_partitioner_lib",
    srcs = ["corpus_partitioner_lib.cc"],
    hdrs = ["corpus_partitioner_lib.h"],
    deps = [
        ":snap_group",
        "@silifuzz//util:checks",
        "@com_google_absl//absl/algorithm:container",
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
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "fix_tool_common",
    srcs = ["fix_tool_common.cc"],
    hdrs = ["fix_tool_common.h"],
    deps = [
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//common:snapshot_util",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//runner:snap_maker",
        "@silifuzz//util:hostname",
        "@silifuzz//util:platform",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "simple_fix_tool_counters",
    hdrs = ["simple_fix_tool_counters.h"],
    deps = [
        ":fix_tool_common",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "simple_fix_tool_counters_test",
    srcs = ["simple_fix_tool_counters_test.cc"],
    deps = [
        ":simple_fix_tool_counters",
        "@com_google_googletest//:gtest_main",
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
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
    ],
)

cc_test(
    name = "snap_group_test",
    srcs = ["snap_group_test.cc"],
    deps = [
        ":snap_group",
        "@silifuzz//common:mapped_memory_map",
        "@silifuzz//common:snapshot_test_util",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
    ],
)
