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

# Description:
#   Utility libraries for SiliFuzz that *** have nothing SiliFuzz-specific ***
#   in them and thus could be potentially moved/usable elsewhere.
#   Contrast with silifuzz/common.

load("@bazel_skylib//:bzl_library.bzl", "bzl_library")
load(
    "@silifuzz//util:nolibc.bzl",
    "cc_binary_nolibc",
    "cc_library_plus_nolibc",
    "cc_test_nolibc",
    "cc_test_plus_nolibc",
)

package(default_visibility = ["//visibility:public"])

licenses(["notice"])

# =========================================================================== #

DISABLE_ARM_TAGS = [
    "not_build:arm",
    "not_test:arm",
]

bzl_library(
    name = "nolibc_bzl",
    srcs = ["nolibc.bzl"],
)

cc_library_plus_nolibc(
    name = "atoi",
    srcs = [
        "atoi.cc",
        "atoi_internal.cc",
    ],
    hdrs = [
        "atoi.h",
        "atoi_internal.h",
    ],
    deps = [":checks"],
)

cc_test_plus_nolibc(
    name = "atoi_test",
    srcs = ["atoi_test.cc"],
    libc_deps = [
        "@com_google_googletest//:gtest_main",
    ],
    deps = [
        ":atoi",
        ":checks",
        ":itoa",
        ":nolibc_gunit",
    ],
)

cc_library_plus_nolibc(
    name = "avx",
    srcs = [
        "avx.cc",
        "x86_64/clear_avx512_only_state.S",
    ],
    hdrs = ["avx.h"],
    deps = [
        ":checks",
        ":x86_cpuid",
    ],
)

cc_test(
    name = "avx_test",
    srcs = [
        "avx_test.cc",
        "avx_test_helper.S",
    ],
    deps = [
        ":avx",
        ":platform",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "byte_io",
    srcs = ["byte_io.cc"],
    hdrs = ["byte_io.h"],
    deps = [
        ":checks",
        ":itoa",
    ],
)

cc_test_plus_nolibc(
    name = "byte_io_test",
    size = "small",
    srcs = ["byte_io_test.cc"],
    libc_deps = [
        "@com_google_googletest//:gtest_main",
    ],
    deps = [
        ":byte_io",
        ":checks",
        ":nolibc_gunit",
    ],
)

cc_library_plus_nolibc(
    name = "checks",
    srcs = [
        "checks.cc",
        "vlog_is_on.h",
    ],
    hdrs = ["checks.h"],
    as_is_deps = [
        "@com_google_absl//absl/base:core_headers",
    ],
    libc_deps = [
        "@com_google_absl//absl/log:log",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/strings",
    ],
    deps = [":itoa"],
)

cc_test_plus_nolibc(
    name = "checks_test",
    size = "small",
    srcs = ["checks_test.cc"],
    libc_deps = [
        "@com_google_googletest//:gtest_main",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
    ],
    deps = [
        ":checks",
        ":itoa",
        ":nolibc_gunit",
    ],
)

cc_library_plus_nolibc(
    name = "cache",
    hdrs = ["cache.h"],
)

cc_library_plus_nolibc(
    name = "types",
    hdrs = ["types.h"],
    as_is_deps = [
        "@com_google_absl//absl/base:core_headers",
    ],
)

cc_library_plus_nolibc(
    name = "misc_util",
    hdrs = ["misc_util.h"],
)

cc_library(
    name = "libc_util",
    hdrs = ["libc_util.h"],
)

cc_library(
    name = "hostname",
    srcs = ["hostname.cc"],
    hdrs = ["hostname.h"],
    deps = [
        "@silifuzz//util:checks",
        "@silifuzz//util:itoa",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "hostname_test",
    srcs = ["hostname_test.cc"],
    deps = [
        ":hostname",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "itoa",
    srcs = ["itoa.cc"],
    hdrs = ["itoa.h"],
    as_is_deps = [
        "@com_google_absl//absl/base:core_headers",
    ],
)

cc_test(
    name = "itoa_test",
    size = "small",
    srcs = ["itoa_test.cc"],
    deps = [
        ":itoa",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "strcat",
    srcs = ["strcat.cc"],
    hdrs = ["strcat.h"],
    as_is_deps = [
        "@com_google_absl//absl/strings",
    ],
    deps = [":checks"],
)

cc_test(
    name = "strcat_test",
    size = "small",
    srcs = ["strcat_test.cc"],
    deps = [
        ":itoa",
        ":strcat",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "enum_flag",
    hdrs = ["enum_flag.h"],
    deps = [
        ":checks",
        ":itoa",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "enum_flag_test",
    srcs = ["enum_flag_test.cc"],
    deps = [
        ":enum_flag",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "flag_matcher",
    srcs = ["flag_matcher.cc"],
    hdrs = ["flag_matcher.h"],
    deps = [":checks"],
)

cc_test_plus_nolibc(
    name = "flag_matcher_test",
    srcs = ["flag_matcher_test.cc"],
    libc_deps = [
        "@com_google_googletest//:gtest_main",
    ],
    deps = [
        ":checks",
        ":flag_matcher",
        ":nolibc_gunit",
    ],
)

cc_library_plus_nolibc(
    name = "logging_util",
    srcs = ["logging_util.cc"] + select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/logging_util.cc",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/logging_util.cc",
        ],
    }),
    hdrs = ["logging_util.h"],
    as_is_deps = [
        "@com_google_absl//absl/base:core_headers",
    ],
    deps = [
        ":checks",
        ":itoa",
        ":misc_util",
        ":strcat",
        "@silifuzz//util/ucontext:signal",
        "@silifuzz//util/ucontext:ucontext_types",
    ],
)

cc_test(
    name = "logging_util_test",
    size = "small",
    srcs = ["logging_util_test.cc"],
    deps = [
        ":logging_util",
        "@silifuzz//util/ucontext",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "mem_util",
    srcs = ["mem_util.cc"],
    hdrs = ["mem_util.h"],
    copts = [
        # TODO(dougkwan): [as-needed] break out x86_64 only option as a per-architecture copt.
        "-mno-sse",
        # Suppress builtin memcmp & memcpy as we are implementing our own.
        "-fno-builtin-memcmp",
        "-fno-builtin-memcpy",
    ],
    deps = [":checks"],
)

cc_test_plus_nolibc(
    name = "mem_util_test",
    srcs = ["mem_util_test.cc"],
    libc_deps = [
        "@com_google_googletest//:gtest_main",
    ],
    deps = [
        ":checks",
        ":mem_util",
        ":nolibc_gunit",
    ],
)

cc_library_plus_nolibc(
    name = "nolibc",
    hdrs = ["nolibc.h"],
)

cc_library_plus_nolibc(
    name = "nolibc_main",
    srcs = [
        "nolibc_main.cc",
        "syscalls.cc",
    ] + select({
        "@silifuzz//build_defs/platform:aarch64": ["aarch64/start.S"],
        "@silifuzz//build_defs/platform:x86_64": ["x86_64/start.S"],
    }),
    as_is_deps = ["@lss"],
    # As a precaution disables builtins for some mem and string functions that are
    # defined by nolibc_main.cc  Otherwise we may run into an infinite recursion.
    copts = [
        "-fno-builtin-memcmp",
        "-fno-builtin-bcmp",
        "-fno-builtin-memcpy",
        "-fno-builtin-memset",
        "-fno-builtin-strlen",
    ],
    # Prepare for --warn-backrefs being on by default: There's a circular
    # dependency between this lib and others.
    # This lib depends on :checks for convenience of doing some checking,
    # while any lib using things like memcpy or strlen (like :checks does)
    # will depend on this lib that provides them instead of libc.
    # Similarly, this lib declares and calls main(), which other sources
    # under //third_party/silifuzz will provide.
    # To fix we simply suppress all these warnings.
    linkopts = ["-Wl,--warn-backrefs-exclude=*/third_party/silifuzz/*"],
    deps = [":checks"],
)

# Copy the compiler-rt builtins library into the output directory.
# Giving it a consistent name makes it easier to link against.
# compiler-rt builtins will contain functions such as __clear_cache that the compiler may generate
# references to even when we're building nolibc binaries. When we build nolibc binaries, however,
# we specify -nostdlib which prevents the compiler from injecting the builtins library into the link
# step. We don't want the other libraries nostdlib eliminates, but we do want builtins. As such, we
# need to do a little magic to find it and link against it.
# Longer term, using the prebuilt builtins library in a nolibc context might cause issues, for
# example if it adds a dependency on libc or another library under the "stdlib" umbrella. If this
# happens, we'll need to create our own custom version of the builtins library. For now it's easier
# to link against the library that comes with the toolchain, as this ensures it stays in sync with
# the needs of the codegen.
genrule(
    name = "builtins_ar",
    outs = ["libbuiltins.a"],
    cmd = "cp \"$$($(CC) $(CC_FLAGS) --rtlib=compiler-rt -print-libgcc-file-name)\" \"$@\"",
    toolchains = [
        "@bazel_tools//tools/cpp:current_cc_toolchain",
        "@bazel_tools//tools/cpp:cc_flags",
    ],
)

# A target that can be depended on to inject the builtins library into the build.
cc_import(
    name = "builtins",
    static_library = "libbuiltins.a",
)

cc_test_nolibc(
    name = "nolibc_test",
    size = "small",
    srcs = ["nolibc_test.cc"],
    copts = [
        "-fno-builtin-memcmp",
    ],
    deps = [
        ":checks",
        ":nolibc_gunit",
    ],
)

cc_test_nolibc(
    name = "syscalls_test",
    size = "small",
    srcs = ["syscalls_test.cc"],
    as_is_deps = ["@lss"],
    deps = [
        ":checks",
        ":itoa",
        ":nolibc_gunit",
        ":strcat",
    ],
)

cc_library_plus_nolibc(
    name = "nolibc_gunit",
    testonly = 1,
    hdrs = ["nolibc_gunit.h"],
    libc_deps = [
        "@com_google_googletest//:gtest",
    ],
)

cc_binary_nolibc(
    name = "start_test_helper",
    srcs = ["start_test_helper.cc"],
)

sh_test(
    name = "start_test",
    srcs = ["start_test.sh"],
    data = [":start_test_helper_nolibc"],
)

cc_library_plus_nolibc(
    name = "proc_maps_parser",
    srcs = ["proc_maps_parser.cc"],
    hdrs = ["proc_maps_parser.h"],
    deps = [
        ":atoi",
        ":checks",
    ],
)

cc_test_plus_nolibc(
    name = "proc_maps_parser_test",
    srcs = ["proc_maps_parser_test.cc"],
    libc_deps = [
        "@com_google_googletest//:gtest_main",
    ],
    deps = [
        ":checks",
        ":nolibc_gunit",
        ":proc_maps_parser",
    ],
)

cc_library(
    name = "proto_util",
    srcs = ["proto_util.cc"],
    hdrs = ["proto_util.h"],
    deps = [
        ":checks",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_protobuf//:protobuf",
        "@com_google_protobuf//:protobuf_lite",
    ],
)

cc_library(
    name = "range_map",
    hdrs = ["range_map.h"],
    deps = [":checks"],
)

cc_test(
    name = "range_map_test",
    size = "small",
    srcs = ["range_map_test.cc"],
    deps = [
        ":checks",
        ":range_map",
        "@com_google_absl//absl/base:core_headers",
        "@com_google_absl//absl/random",
        "@com_google_absl//absl/random:seed_sequences",
        "@com_google_absl//absl/strings",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "line_printer",
    srcs = ["line_printer.cc"],
    hdrs = ["line_printer.h"],
    deps = [
        ":checks",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "text_table",
    srcs = ["text_table.cc"],
    hdrs = ["text_table.h"],
    deps = [
        ":checks",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/types:span",
    ],
)

cc_library(
    name = "time_proto_util",
    srcs = ["time_proto_util.cc"],
    hdrs = ["time_proto_util.h"],
    deps = [
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_test(
    name = "time_proto_util_test",
    srcs = ["time_proto_util_test.cc"],
    deps = [
        ":time_proto_util",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/time",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library_plus_nolibc(
    name = "x86_cpuid",
    hdrs = ["x86_cpuid.h"],
)

cc_test_plus_nolibc(
    name = "x86_cpuid_test",
    size = "small",
    srcs = ["x86_cpuid_test.cc"],
    libc_deps = [
        "@com_google_googletest//:gtest_main",
    ],
    deps = [
        ":checks",
        ":nolibc_gunit",
        ":x86_cpuid",
    ],
)

cc_library(
    name = "platform",
    srcs = ["platform.cc"],
    hdrs = ["platform.h"],
    deps = [
        ":checks",
        ":enum_flag",
        ":itoa",
        ":misc_util",
        ":x86_cpuid",
        "@com_google_absl//absl/container:flat_hash_map",
    ],
)

cc_test(
    name = "platform_test",
    size = "small",
    srcs = ["platform_test.cc"],
    deps = [
        ":platform",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "ptrace_util",
    srcs = ["ptrace_util.cc"],
    hdrs = ["ptrace_util.h"],
    deps = [
        ":checks",
        ":itoa",
    ],
)

cc_library_plus_nolibc(
    name = "cpu_id",
    srcs = ["cpu_id.cc"] + select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/cpu_id.cc",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/cpu_id.cc",
        ],
    }),
    hdrs = ["cpu_id.h"],
    as_is_deps = [
        "@lss",
    ],
    deps = [
        ":checks",
        ":x86_cpuid",
    ],
)

cc_test(
    name = "cpu_id_test",
    srcs = ["cpu_id_test.cc"],
    deps = [
        ":checks",
        ":cpu_id",
        ":itoa",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "text_proto_printer",
    srcs = [
        "text_proto_printer.cc",
    ],
    hdrs = [
        "text_proto_printer.h",
    ],
    # This can only be built as a static library as it would
    # crash the dynamic linker due to invalid fs_base on x86.
    deps = [
        ":checks",
        ":itoa",
    ],
)

cc_test_plus_nolibc(
    name = "text_proto_printer_test",
    srcs = ["text_proto_printer_test.cc"],
    libc_deps = [
        "@com_google_googletest//:gtest_main",
    ],
    deps = [
        ":checks",
        ":nolibc_gunit",
        ":text_proto_printer",
    ],
)

cc_test(
    name = "text_proto_printer_integration_test",
    srcs = ["text_proto_printer_integration_test.cc"],
    deps = [
        ":text_proto_printer",
        "@silifuzz//proto:player_result_cc_proto",
        "@silifuzz//proto:snapshot_cc_proto",
        "@com_google_googletest//:gtest_main",
        "@com_google_protobuf//:protobuf",
    ],
)

cc_library(
    name = "subprocess",
    srcs = ["subprocess.cc"],
    hdrs = ["subprocess.h"],
    deps = [
        ":checks",
        ":itoa",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/time",
    ],
)

cc_test(
    name = "subprocess_test",
    size = "medium",
    srcs = ["subprocess_test.cc"],
    deps = [
        ":subprocess",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "file_util",
    srcs = ["file_util.cc"],
    hdrs = ["file_util.h"],
    as_is_deps = [
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/base:core_headers",
    ],
    deps = [
        ":byte_io",
        ":checks",
        ":itoa",
    ],
)

cc_library(
    name = "path_util",
    srcs = ["path_util.cc"],
    hdrs = ["path_util.h"],
    deps = [
        ":itoa",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "path_util_test",
    size = "medium",
    srcs = ["path_util_test.cc"],
    deps = [
        ":checks",
        ":path_util",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_library(
    name = "owned_file_descriptor",
    hdrs = ["owned_file_descriptor.h"],
    deps = [
        ":checks",
    ],
)

cc_library_plus_nolibc(
    name = "mmapped_memory_ptr",
    hdrs = ["mmapped_memory_ptr.h"],
    deps = [
        "@silifuzz//util:checks",
    ],
)

cc_library_plus_nolibc(
    name = "tool_util",
    srcs = ["tool_util.cc"],
    hdrs = ["tool_util.h"],
    as_is_deps = [
        "@com_google_absl//absl/strings",
    ],
    deps = [
        "@silifuzz//util:checks",
    ],
)
