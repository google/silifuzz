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
#   Various helper tools for Silifuzz.
#   Particularly, snap_toop is the swiss-army-knife for Silifuzz snapshots.

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

# =========================================================================== #

cc_binary(
    name = "snap_tool",
    srcs = ["snap_tool.cc"],
    # Link statically to eliminate shared libraries deps and make this binary
    # easier to deploy in an environment lacking libc.
    features = ["fully_static_link"],
    linkstatic = 1,
    deps = [
        "@silifuzz//common:memory_state",
        "@silifuzz//common:raw_insns_util",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_file_util",
        "@silifuzz//common:snapshot_printer",
        "@silifuzz//common:snapshot_util",
        "@silifuzz//player:trace_options",
        "@silifuzz//runner:disassembling_snap_tracer",
        "@silifuzz//runner:make_snapshot",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//runner/driver:runner_driver",
        "@silifuzz//snap/gen:relocatable_snap_generator",
        "@silifuzz//snap/gen:snap_generator",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:enum_flag",
        "@silifuzz//util:enum_flag_types",
        "@silifuzz//util:file_util",
        "@silifuzz//util:itoa",
        "@silifuzz//util:line_printer",
        "@silifuzz//util:mmapped_memory_ptr",
        "@silifuzz//util:platform",
        "@silifuzz//util:tool_util",
        "@silifuzz//util/ucontext:serialize",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/functional:bind_front",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
    ],
)

cc_binary(
    name = "silifuzz_platform_id",
    srcs = ["silifuzz_platform_id.cc"],
    features = ["fully_static_link"],
    linkstatic = 1,
    deps = [
        "@silifuzz//util:arch",
        "@silifuzz//util:cpu_features",
        "@silifuzz//util:itoa",
        "@silifuzz//util:platform",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/strings:str_format",
    ],
)

cc_library(
    name = "fuzz_filter_tool_lib",
    srcs = ["fuzz_filter_tool.cc"],
    hdrs = ["fuzz_filter_tool.h"],
    deps = [
        "@silifuzz//runner:make_snapshot",
        "@silifuzz//runner:runner_provider",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
    ],
)

cc_binary(
    name = "fuzz_filter_tool",
    srcs = ["fuzz_filter_tool_main.cc"],
    features = ["fully_static_link"],
    linkstatic = 1,
    deps = [
        ":fuzz_filter_tool_lib",
        "@silifuzz//util:checks",
        "@silifuzz//util:tool_util",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@fuzztest//centipede:runner_fork_server",  # Note: external dependency.
    ],
)

cc_test(
    name = "fuzz_filter_tool_test",
    size = "medium",
    srcs = ["fuzz_filter_tool_test.cc"],
    deps = [
        ":fuzz_filter_tool_lib",
        "@silifuzz//common:snapshot_test_enum",
        "@silifuzz//common:snapshot_test_util",
        "@silifuzz//util:arch",
        "@googletest//:gtest_main",
    ],
)

cc_binary(
    name = "snap_corpus_tool",
    srcs = ["snap_corpus_tool.cc"],
    # Link statically to eliminate shared libraries deps and make this binary
    # easier to deploy in an environment lacking libc.
    features = ["fully_static_link"],
    linkstatic = 1,
    deps = [
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_file_util",
        "@silifuzz//common:snapshot_printer",
        "@silifuzz//player:player_result_proto",
        "@silifuzz//proto:binary_log_entry_cc_proto",
        "@silifuzz//proto:snapshot_execution_result_cc_proto",
        "@silifuzz//snap",
        "@silifuzz//snap:snap_corpus_util",
        "@silifuzz//snap:snap_util",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:enum_flag_types",
        "@silifuzz//util:itoa",
        "@silifuzz//util:line_printer",
        "@silifuzz//util:mmapped_memory_ptr",
        "@silifuzz//util:platform",
        "@silifuzz//util:proto_util",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
    ],
)

sh_test(
    name = "snap_corpus_tool_test",
    size = "large",
    srcs = ["snap_corpus_tool_test.sh"],
    data = [
        ":snap_corpus_tool",
        "@silifuzz//snap/testing:test_corpus",
    ],
)

cc_library(
    name = "simple_fix_tool",
    srcs = ["simple_fix_tool.cc"],
    hdrs = ["simple_fix_tool.h"],
    deps = [
        "@silifuzz//common:raw_insns_util",
        "@silifuzz//common:snapshot",
        "@silifuzz//snap/gen:relocatable_snap_generator",
        "@silifuzz//snap/gen:snap_generator",
        "@silifuzz//tool_libs:corpus_partitioner_lib",
        "@silifuzz//tool_libs:fix_tool_common",
        "@silifuzz//tool_libs:simple_fix_tool_counters",
        "@silifuzz//tool_libs:snap_group",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:mmapped_memory_ptr",
        "@silifuzz//util:platform",
        "@silifuzz//util:span_util",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/meta:type_traits",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
        "@fuzztest//common:blob_file",
        "@fuzztest//common:defs",
    ],
)

cc_binary(
    name = "simple_fix_tool_main",
    srcs = ["simple_fix_tool_main.cc"],
    deps = [
        ":simple_fix_tool",
        "@silifuzz//tool_libs:simple_fix_tool_counters",
        "@silifuzz//util:checks",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/log:flags",
        "@abseil-cpp//absl/log:initialize",
        "@abseil-cpp//absl/strings",
    ],
)

cc_test(
    name = "simple_fix_tool_test",
    size = "medium",
    srcs = ["simple_fix_tool_test.cc"],
    deps = [
        ":simple_fix_tool",
        "@silifuzz//common:snapshot",
        "@silifuzz//snap",
        "@silifuzz//snap:snap_relocator",
        "@silifuzz//tool_libs:simple_fix_tool_counters",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:mmapped_memory_ptr",
        "@silifuzz//util:path_util",
        "@silifuzz//util/testing:status_macros",
        "@abseil-cpp//absl/cleanup",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/types:span",
        "@fuzztest//common:blob_file",
        "@googletest//:gtest_main",
    ],
)
