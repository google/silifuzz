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

licenses(["notice"])

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "execution_trace",
    hdrs = ["execution_trace.h"],
    deps = [
        ":tracer",
        "@silifuzz//instruction:disassembler",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/status",
    ],
)

cc_test(
    name = "execution_trace_test",
    srcs = ["execution_trace_test.cc"],
    deps = [
        ":execution_trace",
        ":unicorn_tracer",
        "@silifuzz//common:snapshot_test_enum",
        "@silifuzz//common:snapshot_test_util",
        "@silifuzz//instruction:capstone_disassembler",
        "@silifuzz//instruction:disassembler",
        "@silifuzz//instruction:xed_disassembler",
        "@silifuzz//util:arch",
        "@silifuzz//util/testing:status_matchers",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/status",
        "@com_google_googletest//:gtest_main",
    ],
)

# Due to how the Unicorn BUILD file is structured, we cannot get header files as a separate target.
# This means we need to link against a specific library (unicorn, unicorn_arm64, unicorn_x86) to get
# the headers. The makes it difficult to extract "unicorn_util.cc" into its own target because
# although it doesn't care about the exact version of unicorn being used, the targets that use
# unicorn_util.cc do.  So it ends up being directly included in multiple targets rather than being
# factored into a library.
cc_library(
    name = "unicorn_tracer_aarch64",
    srcs = [
        "unicorn_tracer_aarch64.cc",
        "unicorn_util.cc",
        "unicorn_util.h",
    ],
    hdrs = [
        "unicorn_tracer.h",
    ],
    deps = [
        ":tracer",
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
        "@silifuzz//util:reg_group_io",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/crc:crc32c",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@unicorn//:unicorn_arm64",
    ],
)

cc_library(
    name = "unicorn_tracer_x86_64",
    srcs = [
        "unicorn_tracer_x86_64.cc",
        "unicorn_util.cc",
        "unicorn_util.h",
    ],
    hdrs = [
        "unicorn_tracer.h",
    ],
    deps = [
        ":tracer",
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
        "@silifuzz//util:reg_group_io",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/crc:crc32c",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@unicorn//:unicorn_x86",
    ],
)

cc_library(
    name = "unicorn_tracer",
    srcs = [
        "unicorn_tracer_aarch64.cc",
        "unicorn_tracer_x86_64.cc",
        "unicorn_util.cc",
        "unicorn_util.h",
    ],
    hdrs = [
        "unicorn_tracer.h",
    ],
    deps = [
        ":tracer",
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
        "@silifuzz//util:reg_group_io",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/crc:crc32c",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@unicorn",
    ],
)

cc_test(
    name = "unicorn_tracer_test",
    srcs = [
        "unicorn_tracer_test.cc",
    ],
    deps = [
        ":tracer",
        ":unicorn_tracer",
        "@silifuzz//common:snapshot_test_enum",
        "@silifuzz//common:snapshot_test_util",
        "@silifuzz//util:arch",
        "@silifuzz//util/testing:status_matchers",
        "@silifuzz//util/ucontext",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/log:check",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "analysis",
    srcs = ["analysis.cc"],
    hdrs = ["analysis.h"],
    deps = [
        ":execution_trace",
        ":tracer",
        ":tracer_factory",
        "@silifuzz//instruction:default_disassembler",
        "@silifuzz//util:checks",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
    ],
)

cc_binary(
    name = "trace_tool",
    srcs = [
        "trace_tool.cc",
    ],
    features = ["fully_static_link"],
    linkstatic = 1,
    deps = [
        ":analysis",
        ":execution_trace",
        ":tracer",
        ":tracer_factory",
        "@silifuzz//instruction:default_disassembler",
        "@silifuzz//instruction:disassembler",
        "@silifuzz//util:arch",
        "@silifuzz//util:bitops",
        "@silifuzz//util:checks",
        "@silifuzz//util:enum_flag",
        "@silifuzz//util:enum_flag_types",
        "@silifuzz//util:line_printer",
        "@silifuzz//util:logging_util",
        "@silifuzz//util:tool_util",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/flags:flag",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_library(
    name = "native_tracer",
    srcs = [
        "native_tracer.cc",
    ],
    hdrs = [
        "native_tracer.h",
    ],
    deps = [
        ":extension_registers",
        ":tracer",
        "@silifuzz//common:harness_tracer",
        "@silifuzz//common:mapped_memory_map",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:proxy_config",
        "@silifuzz//common:snapshot",
        "@silifuzz//common:snapshot_enums",
        "@silifuzz//runner:make_snapshot",
        "@silifuzz//runner:runner_provider",
        "@silifuzz//runner/driver:runner_driver",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@silifuzz//util:page_util",
        "@silifuzz//util:ptrace_util",
        "@silifuzz//util:reg_group_io",
        "@silifuzz//util:reg_groups",
        "@silifuzz//util:user_regs_util",
        "@silifuzz//util/ucontext:serialize",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/crc:crc32c",
        "@abseil-cpp//absl/log",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings:string_view",
    ],
)

cc_test(
    name = "native_tracer_test",
    srcs = ["native_tracer_test.cc"],
    deps = [
        ":native_tracer",
        ":tracer",
        "@silifuzz//common:snapshot_test_enum",
        "@silifuzz//common:snapshot_test_util",
        "@silifuzz//snap:exit_sequence",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:reg_group_io",
        "@silifuzz//util:reg_groups",
        "@silifuzz//util/testing:status_matchers",
        "@silifuzz//util/ucontext",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/strings:string_view",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "tracer",
    hdrs = ["tracer.h"],
    deps = [
        "@silifuzz//common:proxy_config",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:reg_group_io",
        "@silifuzz//util/ucontext:ucontext_types",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings:string_view",
    ],
)

cc_library(
    name = "tracer_factory",
    hdrs = ["tracer_factory.h"],
    deps = [
        ":native_tracer",
        ":tracer",
        ":unicorn_tracer",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
    ],
)

cc_library(
    name = "extension_registers",
    srcs = select({
        "@silifuzz//build_defs/platform:aarch64": [],
        "@silifuzz//build_defs/platform:x86_64": ["save_x86_xstate.S"],
    }),
    hdrs = ["extension_registers.h"],
    deps = [
        "@silifuzz//util:arch",
        "@silifuzz//util:reg_group_io",
    ],
)
