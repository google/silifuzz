# Copyright 2024 The SiliFuzz Authors.
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

load("@rules_python//python:proto.bzl", "py_proto_library")
load("@rules_python//python:py_test.bzl", "py_test")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

DISABLE_ARM_TAGS = [
    "not_build:arm",
    "not_run:arm",
]

cc_library(
    name = "hashtest_generator_lib",
    srcs = [
        "candidate.cc",
        "debugging.cc",
        "instruction_pool.cc",
        "prefilter.cc",
        "register_info.cc",
        "synthesize_base.cc",
        "synthesize_instruction.cc",
        "synthesize_shuffle.cc",
        "synthesize_test.cc",
        "xed_operand_util.cc",
    ],
    hdrs = [
        "candidate.h",
        "debugging.h",
        "instruction_pool.h",
        "prefilter.h",
        "rand_util.h",
        "register_info.h",
        "synthesize_base.h",
        "synthesize_instruction.h",
        "synthesize_shuffle.h",
        "synthesize_test.h",
        "version.h",
        "weighted_choose_one.h",
        "xed_operand_util.h",
    ],
    deps = [
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:checks",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/strings:string_view",
        "@libxed//:xed",
    ],
)

cc_test(
    name = "hashtest_generator_test",
    srcs = [
        "hashtest_generator_test.cc",
    ],
    deps = [
        ":hashtest_generator_lib",
        "@silifuzz//instruction:xed_util",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
        "@libxed//:xed",
    ],
)

cc_binary(
    name = "hashtest_generator",
    srcs = [
        "hashtest_generator_main.cc",
        "synthesize_snapshot.cc",
        "synthesize_snapshot.h",
    ],
    deps = [
        ":hashtest_generator_lib",
        "@silifuzz//common:raw_insns_util",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_file_util",
        "@silifuzz//common:snapshot_printer",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//runner:make_snapshot",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:enum_flag_types",
        "@silifuzz//util:itoa",
        "@silifuzz//util:line_printer",
        "@silifuzz//util:platform",
        "@silifuzz//util/ucontext:ucontext_types",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:string_view",
        "@libxed//:xed",
    ],
)

sh_test(
    name = "hashtest_generator_integration_test",
    srcs = ["hashtest_generator_integration_test.sh"],
    data = [
        ":hashtest_generator",
    ],
)

proto_library(
    name = "hashtest_result",
    srcs = ["hashtest_result.proto"],
    deps = ["@com_google_protobuf//:timestamp_proto"],
)

cc_proto_library(
    name = "hashtest_result_cc_proto",
    deps = [":hashtest_result"],
)

py_proto_library(
    name = "hashtest_result_py_proto",
    deps = [":hashtest_result"],
)

cc_library(
    name = "hashtest_runner_lib",
    srcs = [
        "hashtest_runner.cc",
        "hashtest_runner_widgits.S",
    ],
    hdrs = [
        "hashtest_runner.h",
        "hashtest_runner_widgits.h",
        "json.h",
        "mxcsr.h",
    ],
    deps = [
        ":hashtest_generator_lib",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:cpu_id",
        "@silifuzz//util:page_util",
        "@cityhash",
        "@com_google_absl//absl/log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/synchronization",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:span",
    ],
)

cc_test(
    name = "hashtest_runner_test",
    srcs = [
        "hashtest_runner_test.cc",
    ],
    deps = [
        ":hashtest_generator_lib",
        ":hashtest_runner_lib",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:platform",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:span",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "parallel_worker_pool",
    srcs = [
        "parallel_worker_pool.cc",
    ],
    hdrs = [
        "parallel_worker_pool.h",
    ],
    deps = [
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/synchronization",
    ],
)

cc_test(
    name = "parallel_worker_pool_test",
    srcs = [
        "parallel_worker_pool_test.cc",
    ],
    deps = [
        ":parallel_worker_pool",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_binary(
    name = "hashtest_runner",
    srcs = [
        "hashtest_runner_main.cc",
    ],
    deps = [
        ":hashtest_generator_lib",
        ":hashtest_result_cc_proto",
        ":hashtest_runner_lib",
        ":parallel_worker_pool",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:cpu_id",
        "@silifuzz//util:enum_flag_types",
        "@silifuzz//util:hostname",
        "@silifuzz//util:itoa",
        "@silifuzz//util:platform",
        "@silifuzz//util:time_proto_util",
        "@com_google_absl//absl/container:btree",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_absl//absl/types:span",
        "@com_google_protobuf//:protobuf",
    ],
)

py_test(
    name = "hashtest_runner_integration_test",
    size = "medium",
    srcs = ["hashtest_runner_integration_test.py"],
    data = [
        ":hashtest_runner",
    ],
    deps = [
        ":hashtest_result_py_proto",
        "@absl_py//absl/testing:absltest",
    ],
)
