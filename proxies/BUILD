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

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "user_features",
    hdrs = ["user_features.h"],
    deps = [
        "@silifuzz//util:checks",
    ],
)

cc_library(
    name = "arch_feature_generator",
    hdrs = ["arch_feature_generator.h"],
    deps = [
        ":user_features",
        "@silifuzz//util:bitops",
        "@silifuzz//util:checks",
        "@silifuzz//util/ucontext:ucontext_types",
    ],
)

cc_library(
    name = "unicorn_aarch64_lib",
    srcs = ["unicorn_aarch64.cc"],
    deps = [
        ":arch_feature_generator",
        ":user_features",
        "@silifuzz//common:proxy_config",
        "@silifuzz//instruction:default_disassembler",
        "@silifuzz//tracing:tracer",
        "@silifuzz//tracing:unicorn_tracer_aarch64",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
    ],
    alwayslink = True,
)

cc_test(
    name = "unicorn_aarch64_test",
    size = "medium",
    srcs = ["unicorn_aarch64_test.cc"],
    deps = [
        ":unicorn_aarch64_lib",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "unicorn_x86_64_lib",
    srcs = ["unicorn_x86_64.cc"],
    deps = [
        ":arch_feature_generator",
        ":user_features",
        "@silifuzz//common:proxy_config",
        "@silifuzz//instruction:default_disassembler",
        "@silifuzz//tracing:tracer",
        "@silifuzz//tracing:unicorn_tracer_x86_64",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
    ],
    alwayslink = True,
)

cc_test(
    name = "unicorn_x86_64_test",
    size = "medium",
    srcs = ["unicorn_x86_64_test.cc"],
    deps = [
        ":unicorn_x86_64_lib",
        "@googletest//:gtest_main",
    ],
)

cc_binary(
    name = "unicorn_aarch64",
    testonly = True,
    linkopts = [
        "-ldl",
        "-lrt",
        "-lpthread",
    ],
    deps = [
        ":unicorn_aarch64_lib",
        "@fuzztest//centipede:centipede_runner",
    ],
)

cc_binary(
    name = "unicorn_x86_64",
    testonly = True,
    linkopts = [
        "-ldl",
        "-lrt",
        "-lpthread",
    ],
    deps = [
        ":unicorn_x86_64_lib",
        "@fuzztest//centipede:centipede_runner",
    ],
)
