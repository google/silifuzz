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

load("@rules_cc//cc:cc_binary.bzl", "cc_binary")
load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")
load("@rules_python//python:proto.bzl", "py_proto_library")
load("@rules_python//python:py_test.bzl", "py_test")
load("@rules_shell//shell:sh_test.bzl", "sh_test")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("@rules_cc//cc:defs.bzl", "cc_proto_library")

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

DISABLE_ARM_TAGS = [
    "not_build:arm",
    "not_run:arm",
]

cc_binary(
    name = "hashtest_generator",
    srcs = [
        "hashtest_generator_main.cc",
    ],
    deps = [
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_file_util",
        "@silifuzz//common:snapshot_printer",
        "@silifuzz//fuzzer/hashtest/testgeneration:snapshot_generation",
        "@silifuzz//fuzzer/hashtest/testgeneration:test_generation_lib",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:checks",
        "@silifuzz//util:enum_flag_types",
        "@silifuzz//util:itoa",
        "@silifuzz//util:line_printer",
        "@silifuzz//util:platform",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
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
    deps = [
        "@protobuf//:duration_proto",
        "@protobuf//:timestamp_proto",
    ],
)

cc_proto_library(
    name = "hashtest_result_cc_proto",
    deps = [":hashtest_result"],
)

py_proto_library(
    name = "hashtest_result_py_proto",
    deps = [":hashtest_result"],
)

# "Temporary" home for types being pulled out of hashtest_runner_main.cc and hashtest_runner.* until their final locations are know.
# TODO: b/473040142 - This shouldn't depend on types inside of test generation
cc_library(
    name = "api_types",
    srcs = [
        "entropy.cc",
    ],
    hdrs = [
        "corpus_config.h",
        "corpus_stats.h",
        "entropy.h",
        "hit.h",
        "json.h",
        "run_config.h",
    ],
    deps = [
        "@silifuzz//fuzzer/hashtest/testgeneration:test_generation_lib",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_test(
    name = "entropy_test",
    srcs = ["entropy_test.cc"],
    deps = [
        ":api_types",
        "@googletest//:gtest_main",
    ],
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
    ],
    deps = [
        ":api_types",
        "@silifuzz//fuzzer/hashtest/testgeneration:test_generation_lib",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:cpu_id",
        "@silifuzz//util:page_util",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/synchronization",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
        "@cityhash",
    ],
)

cc_test(
    name = "hashtest_runner_test",
    srcs = [
        "hashtest_runner_test.cc",
    ],
    deps = [
        ":api_types",
        ":hashtest_runner_lib",
        "@silifuzz//fuzzer/hashtest/testgeneration:test_generation_lib",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:platform",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
        "@googletest//:gtest_main",
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
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/synchronization",
    ],
)

cc_test(
    name = "parallel_worker_pool_test",
    srcs = [
        "parallel_worker_pool_test.cc",
    ],
    deps = [
        ":parallel_worker_pool",
        "@googletest//:gtest_main",
    ],
)

cc_binary(
    name = "hashtest_runner",
    srcs = [
        "hashtest_runner_main.cc",
    ],
    deps = [
        ":api_types",
        ":hashtest_result_cc_proto",
        ":hashtest_runner_lib",
        ":parallel_worker_pool",
        "@silifuzz//fuzzer/hashtest/resultsrecorder:results_recorder",
        "@silifuzz//fuzzer/hashtest/testgeneration:test_generation_lib",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:cpu_id",
        "@silifuzz//util:enum_flag_types",
        "@silifuzz//util:hostname",
        "@silifuzz//util:itoa",
        "@silifuzz//util:platform",
        "@silifuzz//util:time_proto_util",
        "@abseil-cpp//absl/algorithm:container",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
        "@protobuf",
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
        "@abseil-py//absl/testing:absltest",
    ],
)
