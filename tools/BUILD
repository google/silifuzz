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
    deps = [
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//common:snapshot_printer",
        "@silifuzz//common:snapshot_util",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//runner:snap_maker",
        "@silifuzz//runner/driver:runner_driver",
        "@silifuzz//snap/gen:relocatable_snap_generator",
        "@silifuzz//snap/gen:snap_generator",
        "@silifuzz//util:checks",
        "@silifuzz//util:enum_flag",
        "@silifuzz//util:file_util",
        "@silifuzz//util:tool_util",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_binary(
    name = "silifuzz_platform_id",
    srcs = ["silifuzz_platform_id.cc"],
    deps = [
        "@silifuzz//util:itoa",
        "@silifuzz//util:platform",
    ],
)

cc_binary(
    name = "fuzz_filter_tool",
    srcs = ["fuzz_filter_tool.cc"],
    deps = [
        "@silifuzz//common:raw_insns_util",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//common:snapshot_util",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//runner:snap_maker",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:path_util",
        "@silifuzz//util:proto_util",
        "@silifuzz//util:tool_util",
        "@centipede//:runner_fork_server",  # Note: external dependency.
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

sh_test(
    name = "fuzz_filter_tool_test",
    srcs = ["fuzz_filter_tool_test.sh"],
    data = [":fuzz_filter_tool"],
)

cc_binary(
    name = "snap_corpus_tool",
    srcs = ["snap_corpus_tool.cc"],
    deps = [
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_printer",
        "@silifuzz//common:snapshot_util",
        "@silifuzz//player:player_result_proto",
        "@silifuzz//proto:binary_log_entry_cc_proto",
        "@silifuzz//proto:snapshot_execution_result_cc_proto",
        "@silifuzz//snap",
        "@silifuzz//snap:snap_corpus_util",
        "@silifuzz//snap:snap_util",
        "@silifuzz//util:checks",
        "@silifuzz//util:line_printer",
        "@silifuzz//util:platform",
        "@silifuzz//util:proto_util",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)
