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

load("@rules_cc//cc:cc_binary.bzl", "cc_binary")
load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_shell//shell:sh_test.bzl", "sh_test")
load("@rules_proto//proto:defs.bzl", "proto_library")
load("@protobuf//bazel:cc_proto_library.bzl", "cc_proto_library")

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "version",
    hdrs = [
        "version.h",
    ],
    deps = [
        "@abseil-cpp//absl/strings",
    ],
)

proto_library(
    name = "corpus_values",
    srcs = ["corpus_values.proto"],
)

cc_proto_library(
    name = "corpus_values_cc_proto",
    deps = [":corpus_values"],
)

cc_library(
    name = "corpus_valuation",
    srcs = ["corpus_valuation.cc"],
    hdrs = ["corpus_valuation.h"],
    deps = [
        ":corpus_values_cc_proto",
        ":version",
        "@silifuzz//fuzzer/hashtest:corpus_api",
    ],
)

cc_library(
    name = "tested_corpus_configs",
    hdrs = ["tested_corpus_configs.h"],
    deps = [
        "@silifuzz//fuzzer/hashtest/testgeneration:corpus_generation",
        "@silifuzz//instruction:xed_util",
        "@abseil-cpp//absl/strings:string_view",
    ],
)

cc_binary(
    name = "versioning_tool",
    srcs = ["versioning_tool.cc"],
    deps = [
        ":corpus_valuation",
        ":corpus_values_cc_proto",
        ":tested_corpus_configs",
        "@silifuzz//fuzzer/hashtest:corpus_api",
        "@silifuzz//fuzzer/hashtest:parallel_worker_pool",
        "@silifuzz//fuzzer/hashtest/testgeneration:candidate_lib",
        "@silifuzz//fuzzer/hashtest/testgeneration:corpus_generation",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:proto_util",
        "@silifuzz//util:tool_util",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:string_view",
    ],
)

sh_test(
    name = "version_test",
    srcs = ["version_test.sh"],
    data = [
        ":versioning_tool",
    ] + glob(["goldens/**"]),
)
