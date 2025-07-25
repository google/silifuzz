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

# Description: absl::Status matchers for GoogleTest. This is a fork of
# Tensorflow's StatusMatchers code.

load("@rules_cc//cc:cc_library.bzl", "cc_library")
load("@rules_cc//cc:cc_test.bzl", "cc_test")

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

cc_library(
    name = "status_macros",
    testonly = 1,
    hdrs = ["status_macros.h"],
    deps = [
        ":status_matchers",
        "@abseil-cpp//absl/status:statusor",
    ],
)

cc_library(
    name = "status_matchers",
    testonly = 1,
    srcs = ["status_matchers.cc"],
    hdrs = ["status_matchers.h"],
    deps = [
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@googletest//:gtest",
    ],
)

cc_test(
    name = "status_macros_test",
    srcs = ["status_macros_test.cc"],
    deps = [
        ":status_macros",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "status_matchers_test",
    srcs = ["status_matchers_test.cc"],
    deps = [
        ":status_matchers",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "vsyscall",
    testonly = 1,
    srcs = ["vsyscall.cc"],
    hdrs = ["vsyscall.h"],
    deps = [
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
    ],
)
