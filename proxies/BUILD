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
    name = "unicorn_tracer_aarch64",
    testonly = True,
    srcs = [
        "unicorn_tracer_aarch64.cc",
        "unicorn_util.cc",
        "unicorn_util.h",
    ],
    hdrs = [
        "unicorn_tracer.h",
    ],
    deps = [
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:proxy_config",
        "@silifuzz//common:raw_insns_util",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_util",
        "@silifuzz//util:arch",
        "@silifuzz//util:arch_mem",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:page_util",
        "@silifuzz//util/ucontext",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@unicorn//:unicorn_arm64",
    ],
)

cc_library(
    name = "unicorn_aarch64_lib",
    testonly = True,
    srcs = ["unicorn_aarch64.cc"],
    deps = [
        ":unicorn_tracer_aarch64",
        "@silifuzz//common:proxy_config",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
    ],
    alwayslink = True,
)

cc_test(
    name = "unicorn_aarch64_test",
    size = "medium",
    srcs = ["unicorn_aarch64_test.cc"],
    deps = [
        ":unicorn_aarch64_lib",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "unicorn_x86_64_lib",
    testonly = True,
    srcs = ["unicorn_x86_64.cc"],
    deps = [
        "@silifuzz//common:proxy_config",
        "@silifuzz//common:raw_insns_util",
        "@silifuzz//common:snapshot_util",
        "@silifuzz//util:arch",
        "@silifuzz//util:arch_mem",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util/ucontext",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@unicorn//:unicorn_x86",
    ],
    alwayslink = True,
)

cc_test(
    name = "unicorn_x86_64_test",
    size = "medium",
    srcs = ["unicorn_x86_64_test.cc"],
    deps = [
        ":unicorn_x86_64_lib",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/random:distributions",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
        "@unicorn//:unicorn_x86",
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
        "@centipede//:centipede_runner",
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
        "@centipede//:centipede_runner",
    ],
)
