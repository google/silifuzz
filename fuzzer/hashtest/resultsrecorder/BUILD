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

cc_library(
    name = "results_recorder",
    srcs = [
        "human_readable_results_recorder.cc",
        "proto_results_recorder.cc",
    ],
    hdrs = [
        "human_readable_results_recorder.h",
        "proto_results_recorder.h",
        "results_recorder.h",
    ],
    deps = [
        "@silifuzz//fuzzer/hashtest:api_types",
        "@silifuzz//fuzzer/hashtest:corpus_api",
        "@silifuzz//fuzzer/hashtest:corpus_config",
        "@silifuzz//fuzzer/hashtest:hashtest_result_cc_proto",
        "@silifuzz//fuzzer/hashtest/versioning:version",
        "@silifuzz//util:time_proto_util",
        "@abseil-cpp//absl/container:btree",
        "@abseil-cpp//absl/container:flat_hash_set",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_test(
    name = "proto_results_recorder_test",
    srcs = ["proto_results_recorder_test.cc"],
    deps = [
        ":results_recorder",
        "@silifuzz//fuzzer/hashtest:api_types",
        "@silifuzz//fuzzer/hashtest:corpus_config",
        "@silifuzz//fuzzer/hashtest:hashtest_result_cc_proto",
        "@silifuzz//fuzzer/hashtest/versioning:version",
        "@silifuzz//util:time_proto_util",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/strings:string_view",
        "@abseil-cpp//absl/time",
        "@abseil-cpp//absl/types:span",
        "@googletest//:gtest_main",
    ],
)
