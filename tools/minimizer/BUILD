# Copyright 2026 The SiliFuzz Authors.
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

# SiliFuzz reproducer minimizer toolchain.

load("@rules_proto//proto:defs.bzl", "proto_library")
load("@protobuf//bazel:py_proto_library.bzl", "py_proto_library")
load("@silifuzz//build_defs:nosan.bzl", "nosan_filegroup")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

nosan_filegroup(
    name = "nosan_reading_runner_main_nolibc",
    srcs = ["@silifuzz//runner:reading_runner_main_nolibc"],
)

py_library(
    name = "file_util",
    srcs = ["file_util.py"],
)

py_library(
    name = "engine_lib",
    srcs = ["engine.py"],
    data = [
        ":nosan_reading_runner_main_nolibc",
        "@silifuzz//tools:silifuzz_platform_id",
        "@silifuzz//tools:snap_tool",
    ],
    deps = [
        ":file_util",
        ":insn_lib",
        "@abseil-py//absl/logging",
        "@silifuzz//proto:player_result_py_proto",
        "@silifuzz//proto:snapshot_execution_result_py_proto",
        "@silifuzz//proto:snapshot_py_proto",
        "@protobuf//:protobuf_python",
    ],
)

py_test(
    name = "engine_test",
    srcs = ["engine_test.py"],
    deps = [
        ":engine_lib",
        ":file_util",
        ":insn_lib",
        "@abseil-py//absl/testing:absltest",
        "@abseil-py//absl/testing:parameterized",
        "@silifuzz//proto:player_result_py_proto",
        "@silifuzz//proto:snapshot_execution_result_py_proto",
        "@silifuzz//proto:snapshot_py_proto",
    ],
)

py_library(
    name = "insn_lib",
    srcs = ["insn.py"],
    deps = [
        "@silifuzz//proto:snapshot_py_proto",
    ],
)

py_test(
    name = "insn_test",
    srcs = ["insn_test.py"],
    deps = [
        ":insn_lib",
        "@abseil-py//absl/testing:absltest",
        "@abseil-py//absl/testing:parameterized",
        "@silifuzz//proto:snapshot_py_proto",
    ],
)

proto_library(
    name = "schedule_proto",
    srcs = ["schedule.proto"],
)

py_proto_library(
    name = "schedule_py_proto",
    deps = [":schedule_proto"],
)

py_library(
    name = "passes_lib",
    srcs = ["passes.py"],
    deps = [
        ":engine_lib",
        ":insn_lib",
        ":schedule_py_proto",
        "@abseil-py//absl/logging",
        "@silifuzz//proto:snapshot_py_proto",
    ],
)

py_test(
    name = "passes_test",
    srcs = ["passes_test.py"],
    deps = [
        ":engine_lib",
        ":insn_lib",
        ":passes_lib",
        ":schedule_py_proto",
        "@abseil-py//absl/testing:absltest",
        "@abseil-py//absl/testing:parameterized",
        "@silifuzz//proto:snapshot_py_proto",
        "@typing_extensions",
    ],
)

py_library(
    name = "minimizer_lib",
    srcs = ["minimizer.py"],
    deps = [
        ":engine_lib",
        ":file_util",
        ":passes_lib",
        ":schedule_py_proto",
        "@abseil-py//absl:app",
        "@abseil-py//absl/flags",
        "@abseil-py//absl/logging",
        "@silifuzz//proto:snapshot_py_proto",
    ],
)

py_binary(
    name = "minimizer",
    srcs = ["minimizer.py"],
    deps = [":minimizer_lib"],
)

py_test(
    name = "minimizer_test",
    srcs = ["minimizer_test.py"],
    deps = [
        ":engine_lib",
        ":file_util",
        ":minimizer_lib",
        ":passes_lib",
        "@abseil-py//absl:app",
        "@abseil-py//absl/flags",
        "@abseil-py//absl/testing:absltest",
        "@abseil-py//absl/testing:flagsaver",
        "@abseil-py//absl/testing:parameterized",
        "@silifuzz//proto:snapshot_py_proto",
        "@typing_extensions",
    ],
)
