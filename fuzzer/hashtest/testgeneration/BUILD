# Copyright 2025 The SiliFuzz Authors.
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

load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "corpus_generation",
    srcs = [
        "corpus_generator.cc",
    ],
    hdrs = [
        "corpus_generator.h",
    ],
    deps = [
        ":candidate_lib",
        ":test_generation_lib",
        "@silifuzz//fuzzer/hashtest:corpus_api",
        "@silifuzz//fuzzer/hashtest:parallel_worker_pool",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:page_util",
        "@abseil-cpp//absl/functional:any_invocable",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_library(
    name = "candidate_lib",
    srcs = [
        "candidate.cc",
        "debugging.cc",
        "register_info.cc",
        "xed_operand_util.cc",
    ],
    hdrs = [
        "candidate.h",
        "debugging.h",
        "register_info.h",
        "xed_operand_util.h",
    ],
    deps = [
        "@silifuzz//util:checks",
        "@abseil-cpp//absl/base:core_headers",
        "@libxed//:xed",
    ],
)

cc_library(
    name = "test_generation_lib",
    srcs = [
        "instruction_pool.cc",
        "prefilter.cc",
        "synthesize_base.cc",
        "synthesize_instruction.cc",
        "synthesize_shuffle.cc",
        "synthesize_test.cc",
    ],
    hdrs = [
        "instruction_pool.h",
        "prefilter.h",
        "rand_util.h",
        "synthesis_config.h",
        "synthesize_base.h",
        "synthesize_instruction.h",
        "synthesize_shuffle.h",
        "synthesize_test.h",
        "weighted_choose_one.h",
    ],
    deps = [
        ":candidate_lib",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:checks",
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/types:span",
        "@libxed//:xed",
    ],
)

cc_library(
    name = "snapshot_generation",
    srcs = [
        "synthesize_snapshot.cc",
        "@silifuzz//fuzzer/hashtest:api_types",
    ],
    hdrs = [
        "synthesize_snapshot.h",
    ],
    deps = [
        ":test_generation_lib",
        "@silifuzz//common:raw_insns_util",
        "@silifuzz//common:snapshot",
        "@silifuzz//fuzzer/hashtest:api_types",
        "@silifuzz//fuzzer/hashtest/versioning:version",
        "@silifuzz//runner:make_snapshot",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:string_view",
        "@libxed//:xed",
    ],
)

cc_test(
    name = "rand_util_test",
    srcs = ["rand_util_test.cc"],
    deps = [
        ":test_generation_lib",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "register_info_test",
    srcs = ["register_info_test.cc"],
    deps = [
        ":candidate_lib",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "xed_operand_util_test",
    srcs = ["xed_operand_util_test.cc"],
    deps = [
        ":candidate_lib",
        ":test_generation_lib",
        "@silifuzz//instruction:xed_util",
        "@abseil-cpp//absl/strings",
        "@googletest//:gtest_main",
        "@libxed//:xed",
    ],
)

cc_test(
    name = "weighted_choose_one_test",
    srcs = ["weighted_choose_one_test.cc"],
    deps = [
        ":test_generation_lib",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "synthesize_shuffle_test",
    srcs = ["synthesize_shuffle_test.cc"],
    deps = [
        ":test_generation_lib",
        "@silifuzz//instruction:xed_util",
        "@googletest//:gtest_main",
        "@libxed//:xed",
    ],
)
