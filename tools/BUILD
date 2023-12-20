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
    srcs = ["snap_tool.cc"] + select({
        "@silifuzz//build_defs/platform:aarch64": ["aarch64/snap_tool_trace.cc"],
        "@silifuzz//build_defs/platform:x86_64": ["x86_64/snap_tool_trace.cc"],
    }),
    deps = [
        "@silifuzz//common:memory_state",
        "@silifuzz//common:raw_insns_util",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//common:snapshot_file_util",
        "@silifuzz//common:snapshot_printer",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//runner:snap_maker",
        "@silifuzz//runner/driver:runner_driver",
        "@silifuzz//snap/gen:relocatable_snap_generator",
        "@silifuzz//snap/gen:snap_generator",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:enum_flag",
        "@silifuzz//util:file_util",
        "@silifuzz//util:itoa",
        "@silifuzz//util:line_printer",
        "@silifuzz//util:mmapped_memory_ptr",
        "@silifuzz//util:platform",
        "@silifuzz//util:tool_util",
        "@silifuzz//util/ucontext",
        "@silifuzz//util/ucontext:serialize",
        "@silifuzz//util/ucontext:ucontext_types",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/functional:bind_front",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ] + select({
        "@silifuzz//build_defs/platform:aarch64": [],
        "@silifuzz//build_defs/platform:x86_64": [
            "@silifuzz//player:trace_options",
            "@silifuzz//runner:disassembling_snap_tracer",
        ],
    }),
)

cc_binary(
    name = "silifuzz_platform_id",
    srcs = ["silifuzz_platform_id.cc"],
    deps = [
        "@silifuzz//util:arch",
        "@silifuzz//util:itoa",
        "@silifuzz//util:platform",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
    ],
)

cc_library(
    name = "fuzz_filter_tool_lib",
    srcs = ["fuzz_filter_tool.cc"],
    hdrs = ["fuzz_filter_tool.h"],
    deps = [
        "@silifuzz//common:raw_insns_util",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//runner:snap_maker",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_binary(
    name = "fuzz_filter_tool",
    srcs = ["fuzz_filter_tool_main.cc"],
    deps = [
        ":fuzz_filter_tool_lib",
        "@silifuzz//util:checks",
        "@silifuzz//util:path_util",
        "@silifuzz//util:tool_util",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_fuzztest//centipede:runner_fork_server",  # Note: external dependency.
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
        "@com_google_googletest//:gtest_main",
    ],
)

cc_binary(
    name = "snap_corpus_tool",
    srcs = ["snap_corpus_tool.cc"],
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
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:line_printer",
        "@silifuzz//util:mmapped_memory_ptr",
        "@silifuzz//util:platform",
        "@silifuzz//util:proto_util",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
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
        "@silifuzz//util:checks",
        "@silifuzz//util:span_util",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/meta:type_traits",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:span",
        "@com_google_fuzztest//centipede:blob_file",
        "@com_google_fuzztest//centipede:defs",
    ],
)

cc_binary(
    name = "simple_fix_tool_main",
    srcs = ["simple_fix_tool_main.cc"],
    deps = [
        ":simple_fix_tool",
        "@silifuzz//tool_libs:simple_fix_tool_counters",
        "@silifuzz//util:checks",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:flags",
        "@com_google_absl//absl/log:initialize",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "simple_fix_tool_test",
    size = "medium",
    srcs = ["simple_fix_tool_test.cc"],
    deps = [
        ":simple_fix_tool",
        "@silifuzz//snap:snap_relocator",
        "@silifuzz//tool_libs:simple_fix_tool_counters",
        "@silifuzz//util:checks",
        "@silifuzz//util:mmapped_memory_ptr",
        "@silifuzz//util:path_util",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/cleanup",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
        "@com_google_absl//absl/types:span",
        "@com_google_fuzztest//centipede:blob_file",
        "@com_google_googletest//:gtest_main",
    ],
)
