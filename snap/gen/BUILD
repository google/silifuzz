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
#   Snap generator.
#

load(
    "@silifuzz//build_defs:constants.bzl",
    "SILIFUZZ_RUNNER_BASE_ADDRESS",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

# =========================================================================== #

genrule(
    name = "gen_runner_base_address_h",
    outs = ["runner_base_address.h"],
    cmd = "cat > $@ <<'EOF'\n" +
          "#ifndef THIRD_PARTY_SILIFUZZ_RUNNER_SILIFUZZ_RUNNER_BASE_ADDRESS_H_\n" +
          "#define THIRD_PARTY_SILIFUZZ_RUNNER_SILIFUZZ_RUNNER_BASE_ADDRESS_H_\n" +
          "#define SILIFUZZ_RUNNER_BASE_ADDRESS " + SILIFUZZ_RUNNER_BASE_ADDRESS + "ULL\n" +
          "#endif  // THIRD_PARTY_SILIFUZZ_RUNNER_SILIFUZZ_RUNNER_BASE_ADDRESS_H_\n" +
          "EOF\n",
)

cc_library(
    name = "runner_base_address",
    hdrs = ["runner_base_address.h"],
)

cc_library(
    name = "relocatable_data_block",
    srcs = ["relocatable_data_block.cc"],
    hdrs = ["relocatable_data_block.h"],
    deps = [
        "@silifuzz//util:checks",
        "@silifuzz//util:misc_util",
    ],
)

cc_test(
    name = "relocatable_data_block_test",
    srcs = ["relocatable_data_block_test.cc"],
    deps = [
        ":relocatable_data_block",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "relocatable_snap_generator",
    srcs = ["relocatable_snap_generator.cc"],
    hdrs = ["relocatable_snap_generator.h"],
    deps = [
        ":relocatable_data_block",
        ":repeating_byte_runs",
        "@silifuzz//common:mapped_memory_map",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:snapshot",
        "@silifuzz//snap",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:mmapped_memory_ptr",
        "@silifuzz//util/ucontext:serialize",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/hash",
    ],
)

cc_test(
    name = "relocatable_snap_generator_test",
    srcs = ["relocatable_snap_generator_test.cc"],
    deps = [
        ":relocatable_snap_generator",
        ":snap_generator",
        "@silifuzz//common:memory_mapping",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_test_util",
        "@silifuzz//snap:snap_relocator",
        "@silifuzz//snap:snap_util",
        "@silifuzz//snap/testing:snap_generator_test_lib",
        "@silifuzz//snap/testing:snap_test_snapshots",
        "@silifuzz//snap/testing:snap_test_types",
        "@silifuzz//util:misc_util",
        "@silifuzz//util:mmapped_memory_ptr",
        "@silifuzz//util:platform",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/container:flat_hash_set",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "repeating_byte_runs",
    srcs = ["repeating_byte_runs.cc"],
    hdrs = ["repeating_byte_runs.h"],
    deps = [
        "@silifuzz//common:snapshot",
        "@silifuzz//util:checks",
        "@silifuzz//util:mem_util",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "repeating_byte_runs_test",
    srcs = ["repeating_byte_runs_test.cc"],
    deps = [
        ":repeating_byte_runs",
        "@silifuzz//common:mapped_memory_map",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:snapshot",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "reserved_memory_mappings",
    srcs = ["reserved_memory_mappings.cc"],
    hdrs = ["reserved_memory_mappings.h"],
    deps = [
        ":runner_base_address",
        "@silifuzz//common:mapped_memory_map",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:snapshot",
        "@silifuzz//snap:exit_sequence",
    ],
)

cc_test(
    name = "reserved_memory_mappings_test",
    srcs = ["reserved_memory_mappings_test.cc"],
    deps = [
        ":reserved_memory_mappings",
        ":runner_base_address",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "snap_generator",
    srcs = [
        "snap_generator.cc",
        "snapify.cc",
    ],
    hdrs = [
        "snap_generator.h",
    ],
    deps = [
        ":repeating_byte_runs",
        ":reserved_memory_mappings",
        "@silifuzz//common:mapped_memory_map",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:memory_state",
        "@silifuzz//common:snapshot",
        "@silifuzz//snap",
        "@silifuzz//snap:exit_sequence",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:platform",
        "@silifuzz//util/ucontext:serialize",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_test(
    name = "snap_generator_test",
    srcs = ["snap_generator_test.cc"],
    deps = [
        ":snap_generator",
        "@silifuzz//common:mapped_memory_map",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:memory_state",
        "@silifuzz//common:snapshot",
        "@silifuzz//snap",
        "@silifuzz//snap:exit_sequence",
        "@silifuzz//snap/testing:snap_generator_test_lib",
        "@silifuzz//snap/testing:snap_test_snaps",
        "@silifuzz//snap/testing:snap_test_snapshots",
        "@silifuzz//snap/testing:snap_test_types",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)
