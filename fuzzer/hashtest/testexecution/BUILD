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
load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

DISABLE_ARM_TAGS = [
    "not_build:arm",
    "not_run:arm",
]

cc_library(
    name = "execution",
    srcs = [
        "execute_corpus.cc",
    ],
    hdrs = [
        "execute_corpus.h",
    ],
    deps = [
        ":hashtest_runner_widgets",
        "@silifuzz//fuzzer/hashtest:api_types",
        "@silifuzz//fuzzer/hashtest:corpus_api",
        "@silifuzz//fuzzer/hashtest:corpus_config",
        "@silifuzz//fuzzer/hashtest:parallel_worker_pool",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:cpu_id",
        "@silifuzz//util:page_util",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/synchronization",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_library(
    name = "hashtest_runner_widgets",
    srcs = [
        "hashtest_runner_widgits.S",
    ],
    hdrs = [
        "hashtest_runner_widgits.h",
    ],
)

cc_test(
    name = "execute_corpus_test",
    srcs = ["execute_corpus_test.cc"],
    local = True,
    deps = [
        ":execution",
        ":hashtest_runner_widgets",
        "@silifuzz//fuzzer/hashtest:corpus_api",
        "@silifuzz//fuzzer/hashtest:parallel_worker_pool",
        "@silifuzz//fuzzer/hashtest/testgeneration:corpus_generation",
        "@silifuzz//fuzzer/hashtest/versioning:tested_corpus_configs",
        "@silifuzz//instruction:xed_util",
        "@silifuzz//util:platform",
        "@googletest//:gtest_main",
    ],
)
