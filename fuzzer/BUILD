# Copyright 2023 The SiliFuzz Authors.
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

load("//third_party/bazel_rules/rules_cc/cc:cc_binary.bzl", "cc_binary")
load("//third_party/bazel_rules/rules_cc/cc:cc_library.bzl", "cc_library")
load("//third_party/bazel_rules/rules_cc/cc:cc_test.bzl", "cc_test")

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "program_mutator",
    srcs = [
        "program.cc",
        "program_aarch64.cc",
        "program_batch_mutator.cc",
        "program_mutation_ops.cc",
        "program_x86_64.cc",
    ],
    hdrs = [
        "program.h",
        "program_arch.h",
        "program_batch_mutator.h",
        "program_mutation_ops.h",
        "program_mutator.h",
    ],
    deps = [
        "@silifuzz//instruction:capstone_disassembler",
        "@silifuzz//instruction:static_insn_filter",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:arch",
        "@silifuzz//util:bit_matcher",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/types:span",
        "@libxed//:xed",
    ],
)

cc_test(
    name = "program_mutator_test",
    size = "medium",
    srcs = ["program_mutator_test.cc"],
    deps = [
        ":program_mutator",
        "@silifuzz//util:arch",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "program_mutator_fuzz_test",
    srcs = ["program_mutator_fuzz_test.cc"],
    deps = [
        ":program_mutator",
        "@silifuzz//util:arch",
        "@fuzztest//fuzztest",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "silifuzz_centipede_main",
    srcs = ["silifuzz_centipede_main.cc"],
    deps = [
        ":program_mutator",
        "@silifuzz//util:arch",
        "@silifuzz//util:enum_flag_types",
        "@silifuzz//util:itoa",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/log:flags",
        "@fuzztest//centipede:centipede_callbacks",
        "@fuzztest//centipede:centipede_default_callbacks",
        "@fuzztest//centipede:centipede_interface",
        "@fuzztest//centipede:config_file",
        "@fuzztest//centipede:environment",
        "@fuzztest//centipede:environment_flags",
        "@fuzztest//centipede:mutation_input",
        "@fuzztest//centipede:util",
        "@fuzztest//common:defs",
    ],
)

cc_binary(
    name = "silifuzz_centipede",
    deps = [
        ":silifuzz_centipede_main",
    ],
)
