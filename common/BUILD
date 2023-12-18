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
#   Common utility libraries for SiliFuzz that *do* have something
#   SiliFuzz-specific in them. Contrast with silifuzz/util.

load("@rules_python//python:py_test.bzl", "py_test")
load("@silifuzz//util:nolibc.bzl", "cc_library_plus_nolibc")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

# =========================================================================== #

cc_library(
    name = "memory_mapping",
    srcs = ["memory_mapping.cc"],
    hdrs = ["memory_mapping.h"],
    deps = [
        ":memory_perms",
        ":snapshot_enums",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "memory_perms",
    srcs = ["memory_perms.cc"],
    hdrs = ["memory_perms.h"],
    deps = [
        "@silifuzz//util:checks",
        "@silifuzz//util:misc_util",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "mapped_memory_map",
    srcs = ["mapped_memory_map.cc"],
    hdrs = ["mapped_memory_map.h"],
    deps = [
        ":memory_mapping",
        ":memory_perms",
        ":snapshot_enums",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:range_map",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "mapped_memory_map_test",
    srcs = ["mapped_memory_map_test.cc"],
    deps = [
        ":mapped_memory_map",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "memory_bytes_set",
    srcs = ["memory_bytes_set.cc"],
    hdrs = ["memory_bytes_set.h"],
    deps = [
        ":snapshot_enums",
        "@silifuzz//util:itoa",
        "@silifuzz//util:range_map",
    ],
)

cc_test(
    name = "memory_bytes_set_test",
    srcs = ["memory_bytes_set_test.cc"],
    deps = [
        ":memory_bytes_set",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "snapshot_enums",
    srcs = ["snapshot_enums.cc"],
    hdrs = ["snapshot_enums.h"],
    as_is_deps = [
        "@com_google_absl//absl/time",
    ],
    deps = [
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:logging_util",
        "@silifuzz//util:misc_util",
        "@silifuzz//util/ucontext:signal",
        "@silifuzz//util/ucontext:ucontext_types",
    ],
)

cc_library(
    name = "snapshot",
    srcs = ["snapshot.cc"],
    hdrs = ["snapshot.h"],
    deps = [
        ":mapped_memory_map",
        ":memory_bytes_set",
        ":memory_mapping",
        ":memory_perms",
        ":snapshot_enums",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:misc_util",
        "@silifuzz//util:platform",
        "@silifuzz//util:reg_checksum_util",
        "@silifuzz//util/ucontext:serialize",
        "@silifuzz//util/ucontext:ucontext_types",
        "@com_google_absl//absl/algorithm:container",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "snapshot_test",
    srcs = ["snapshot_test.cc"],
    deps = [
        ":memory_perms",
        ":snapshot",
        ":snapshot_test_util",
        ":snapshot_util",
        "@silifuzz//util:platform",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "snapshot_types",
    hdrs = ["snapshot_types.h"],
    deps = [":snapshot"],
)

cc_library(
    name = "snapshot_proto",
    srcs = ["snapshot_proto.cc"],
    hdrs = ["snapshot_proto.h"],
    deps = [
        ":memory_perms",
        ":snapshot",
        ":snapshot_enums",
        ":snapshot_types",
        "@silifuzz//proto:snapshot_cc_proto",
        "@silifuzz//util:checks",
        "@silifuzz//util:misc_util",
        "@silifuzz//util:platform",
        "@silifuzz//util:proto_util",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "snapshot_proto_test",
    size = "small",
    srcs = ["snapshot_proto_test.cc"],
    deps = [
        ":raw_insns_util",
        ":snapshot_proto",
        ":snapshot_test_enum",
        ":snapshot_test_util",
        "@silifuzz//proto:snapshot_cc_proto",
        "@silifuzz//util:arch",
        "@silifuzz//util:reg_checksum",
        "@silifuzz//util/testing:status_macros",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "snapshot_util",
    srcs = ["snapshot_util.cc"],
    hdrs = ["snapshot_util.h"],
    deps = [
        ":snapshot",
        "@silifuzz//util:checks",
        "@silifuzz//util/ucontext:serialize",
        "@silifuzz//util/ucontext:ucontext_types",
        "@com_google_absl//absl/status",
    ],
)

cc_library(
    name = "snapshot_file_util",
    srcs = ["snapshot_file_util.cc"],
    hdrs = ["snapshot_file_util.h"],
    deps = [
        ":snapshot",
        ":snapshot_proto",
        "@silifuzz//util:checks",
        "@silifuzz//util:proto_util",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "snapshot_printer",
    srcs = ["snapshot_printer.cc"],
    hdrs = ["snapshot_printer.h"],
    deps = [
        ":memory_perms",
        ":memory_state",
        ":snapshot",
        ":snapshot_types",
        ":snapshot_util",
        "@silifuzz//instruction:default_disassembler",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:line_printer",
        "@silifuzz//util:logging_util",
        "@silifuzz//util:reg_checksum",
        "@silifuzz//util:reg_checksum_util",
        "@silifuzz//util:reg_group_set",
        "@silifuzz//util:text_table",
        "@silifuzz//util/ucontext:ucontext_types",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "memory_state",
    srcs = ["memory_state.cc"],
    hdrs = ["memory_state.h"],
    deps = [
        ":mapped_memory_map",
        ":snapshot",
        ":snapshot_types",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:range_map",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "memory_state_test",
    srcs = ["memory_state_test.cc"],
    deps = [
        ":memory_mapping",
        ":memory_perms",
        ":memory_state",
        "@com_github_google_benchmark//:benchmark_main",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "snapshot_test_enum",
    testonly = True,
    srcs = ["snapshot_test_enum.cc"],
    hdrs = ["snapshot_test_enum.h"],
    as_is_deps = [
        "@com_google_absl//absl/base:core_headers",
    ],
    deps = [
        "@silifuzz//util:itoa",
    ],
)

cc_test(
    name = "snapshot_test_enum_test",
    srcs = ["snapshot_test_enum_test.cc"],
    deps = [
        ":snapshot_test_enum",
        "@silifuzz//util:itoa",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "snapshot_test_util",
    testonly = True,
    srcs = [
        "snapshot_test_config.cc",
        "snapshot_test_util.cc",
    ],
    hdrs = [
        "snapshot_test_config.h",
        "snapshot_test_util.h",
    ],
    deps = [
        ":memory_mapping",
        ":memory_perms",
        ":memory_state",
        ":snapshot",
        ":snapshot_proto",
        ":snapshot_test_enum",
        ":snapshot_util",
        "@silifuzz//proto:snapshot_cc_proto",
        "@silifuzz//snap:exit_sequence",
        "@silifuzz//util:arch",
        "@silifuzz//util:arch_mem",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:platform",
        "@silifuzz//util/ucontext:ucontext_types",
        "@com_google_absl//absl/status:statusor",
    ],
)

# This script is not set up to run under CI.
# This test make sure it parses and runs (to some extent) to prevent regressions.
py_test(
    name = "generate_tests",
    srcs = ["generate_tests.py"],
    args = ["--test"],
)

cc_library(
    name = "raw_insns_util",
    srcs = ["raw_insns_util.cc"],
    hdrs = ["raw_insns_util.h"],
    linkopts = ["-lcrypto"],
    deps = [
        ":memory_perms",
        ":proxy_config",
        ":snapshot",
        ":snapshot_util",
        "@silifuzz//instruction:static_insn_filter",
        "@silifuzz//util:arch",
        "@silifuzz//util:arch_mem",
        "@silifuzz//util:checks",
        "@silifuzz//util/ucontext:ucontext_types",
        "@cityhash",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "raw_insns_util_test",
    size = "small",
    srcs = ["raw_insns_util_test.cc"],
    deps = [
        ":raw_insns_util",
        "@silifuzz//proto:snapshot_cc_proto",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "harness_tracer",
    srcs = ["harness_tracer.cc"],
    hdrs = ["harness_tracer.h"],
    deps = [
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:ptrace_util",
        "@silifuzz//util/ucontext:x86_traps",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/synchronization",
    ],
)

# Helper binary to test the harness tracer in isolation.
cc_binary(
    name = "harness_tracer_test_helper",
    testonly = 1,
    srcs = ["harness_tracer_test_helper.cc"],
    deps = [
        "@com_google_absl//absl/strings",
        "@lss",
    ],
)

cc_test(
    name = "harness_tracer_test",
    size = "medium",
    timeout = "short",
    srcs = ["harness_tracer_test.cc"],
    data = [":harness_tracer_test_helper"],
    deps = [
        ":harness_tracer",
        "@silifuzz//util:checks",
        "@silifuzz//util:data_dependency",
        "@silifuzz//util:subprocess",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "proxy_config",
    hdrs = ["proxy_config.h"],
    deps = [
        "@silifuzz//util:arch",
    ],
)

cc_test(
    name = "proxy_config_test",
    size = "small",
    srcs = ["proxy_config_test.cc"],
    deps = [
        ":proxy_config",
        "@com_google_googletest//:gtest_main",
    ],
)
