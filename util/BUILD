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
    "not_run:arm",
]

DISABLE_X86_TAGS = [
    "not_build:haswell",
    "not_build:k8",
    "not_run:haswell",
    "not_run:k8",
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
        "@googletest//:gtest_main",
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
        ":cpu_features",
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
        ":checks",
        ":platform",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "bitops",
    hdrs = ["bitops.h"],
)

cc_library(
    name = "bit_matcher",
    hdrs = ["bit_matcher.h"],
)

cc_test(
    name = "bitops_test",
    size = "small",
    srcs = ["bitops_test.cc"],
    deps = [
        ":bitops",
        "@googletest//:gtest_main",
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
        "@googletest//:gtest_main",
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
    ],
    hdrs = ["checks.h"],
    as_is_deps = [
        "@abseil-cpp//absl/base:core_headers",
    ],
    libc_deps = [
        "@abseil-cpp//absl/log:log",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/log:vlog_is_on",
        "@abseil-cpp//absl/strings",
    ],
)

cc_test_plus_nolibc(
    name = "checks_test",
    size = "small",
    srcs = ["checks_test.cc"],
    libc_deps = [
        "@googletest//:gtest_main",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
    ],
    deps = [
        ":checks",
        ":itoa",
        ":nolibc_gunit",
    ],
)

cc_library_plus_nolibc(
    name = "cpu_features",
    srcs = select({
        "@silifuzz//build_defs/platform:aarch64": [],
        "@silifuzz//build_defs/platform:x86_64": ["x86_64/cpu_features.cc"],
    }),
    hdrs = ["cpu_features.h"],
    as_is_deps = [
        "@abseil-cpp//absl/base:core_headers",
    ],
    deps = [
        ":itoa",
        ":x86_cpuid",
    ],
)

cc_test(
    name = "cpu_features_test",
    srcs = ["cpu_features_test.cc"] + select({
        "@silifuzz//build_defs/platform:aarch64": [],
        "@silifuzz//build_defs/platform:x86_64": ["x86_64/cpu_features_test.cc"],
    }),
    deps = [
        ":cpu_features",
        ":itoa",
        "@abseil-cpp//absl/strings",
        "@googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "crc32c_internal",
    srcs = [
        "crc32c_internal.cc",
    ],
    hdrs = ["crc32c_internal.h"],
)

cc_binary(
    name = "gen_crc32c_zero_extension_tables",
    srcs = ["gen_crc32c_zero_extension_tables.cc"],
    deps = [":crc32c_internal"],
)

genrule(
    name = "gen_crc32c_zero_extension_tables_cc",
    outs = ["crc32c_zero_extension_tables.cc"],
    cmd = "$(location :gen_crc32c_zero_extension_tables) > $@",
    tools = [":gen_crc32c_zero_extension_tables"],
)

cc_library_plus_nolibc(
    name = "crc32c",
    srcs = [
        "crc32c.cc",
        "crc32c_zero_extension_tables.cc",
    ],
    hdrs = ["crc32c.h"],
    deps = [
        ":cpu_features",
        ":crc32c_internal",
    ],
)

cc_test_plus_nolibc(
    name = "crc32c_test",
    srcs = ["crc32c_test.cc"],
    libc_deps = [
        "@googletest//:gtest_main",
    ],
    deps = [
        ":checks",
        ":crc32c",
        ":crc32c_internal",
        ":nolibc_gunit",
    ],
)

cc_test(
    name = "crc32c_benchmarks",
    srcs = ["crc32c_benchmarks.cc"],
    deps = [
        ":crc32c",
        "@com_github_google_benchmark//:benchmark_main",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "data_dependency",
    srcs = ["data_dependency.cc"],
    hdrs = ["data_dependency.h"],
    deps = [
        ":checks",
        "@abseil-cpp//absl/strings",
    ],
)

cc_test(
    name = "data_dependency_test",
    size = "medium",
    timeout = "short",
    srcs = [
        "data_dependency_test.cc",
    ],
    data = [
        "testdata/data_dependency_testdata",
    ],
    deps = [
        ":data_dependency",
        "@googletest//:gtest_main",
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
        "@abseil-cpp//absl/base:core_headers",
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
        "@abseil-cpp//absl/strings",
    ],
)

cc_test(
    name = "hostname_test",
    srcs = ["hostname_test.cc"],
    deps = [
        ":hostname",
        "@abseil-cpp//absl/strings",
        "@googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "itoa",
    srcs = ["itoa.cc"],
    hdrs = ["itoa.h"],
    as_is_deps = [
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/strings",
    ],
    deps = [":checks"],
)

cc_test(
    name = "itoa_test",
    size = "small",
    srcs = ["itoa_test.cc"],
    deps = [
        ":itoa",
        "@abseil-cpp//absl/strings:str_format",
        "@googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "strcat",
    srcs = ["strcat.cc"],
    hdrs = ["strcat.h"],
    as_is_deps = [
        "@abseil-cpp//absl/strings",
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
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "enum_flag",
    hdrs = ["enum_flag.h"],
    deps = [
        ":checks",
        ":itoa",
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
    ],
)

cc_test(
    name = "enum_flag_test",
    srcs = ["enum_flag_test.cc"],
    deps = [
        ":enum_flag",
        ":itoa",
        "@silifuzz//util/testing:status_matchers",
        "@abseil-cpp//absl/status",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "enum_flag_types",
    srcs = ["enum_flag_types.cc"],
    hdrs = ["enum_flag_types.h"],
    deps = [
        ":arch",
        ":enum_flag",
        ":platform",
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
        "@googletest//:gtest_main",
    ],
    deps = [
        ":checks",
        ":flag_matcher",
        ":nolibc_gunit",
    ],
)

cc_library_plus_nolibc(
    name = "logging_util",
    srcs = [
        "aarch64/logging_util.cc",
        "logging_util.cc",
        "x86_64/logging_util.cc",
    ],
    hdrs = [
        "internal/logging_util_macros.h",
        "logging_util.h",
    ],
    as_is_deps = [
        "@abseil-cpp//absl/base:core_headers",
    ],
    deps = [
        ":arch",
        ":checks",
        ":itoa",
        ":misc_util",
        ":reg_checksum",
        ":reg_group_io",
        ":reg_group_set",
        ":strcat",
        ":sve",
        "@silifuzz//util/ucontext:signal",
        "@silifuzz//util/ucontext:ucontext_types",
    ],
)

cc_test(
    name = "logging_util_test",
    size = "small",
    srcs = ["logging_util_test.cc"],
    deps = [
        ":arch",
        ":logging_util",
        ":reg_checksum",
        ":reg_group_io",
        ":reg_group_set",
        "@silifuzz//util/ucontext",
        "@googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "math",
    hdrs = ["math.h"],
    deps = [":checks"],
)

cc_test_plus_nolibc(
    name = "math_test",
    srcs = ["math_test.cc"],
    libc_deps = [
        "@googletest//:gtest_main",
    ],
    deps = [
        ":checks",
        ":math",
        ":nolibc_gunit",
    ],
)

cc_library_plus_nolibc(
    name = "mem_util",
    srcs = ["mem_util.cc"],
    hdrs = ["mem_util.h"],
    copts = [
        # Suppress builtin memcmp & memcpy as we are implementing our own.
        "-fno-builtin-memcmp",
        "-fno-builtin-memcpy",
    ],
    deps = [":checks"],
)

cc_binary_nolibc(
    name = "mem_util_benchmark",
    srcs = [
        "mem_util_benchmark.cc",
    ],
    as_is_deps = [
        "@lss",
    ],
    deps = [
        ":avx",
        ":checks",
        ":itoa",
        ":math",
        ":mem_util",
    ],
)

cc_test_plus_nolibc(
    name = "mem_util_test",
    srcs = ["mem_util_test.cc"],
    libc_deps = [
        "@googletest//:gtest_main",
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
        # TODO: b/359507086 - Figure out `extern "C" int main` and remove this.
        "-Wno-error=main",
        "-Wno-error=uninitialized",
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
        "@bazel_tools//tools/cpp:cc_flags",
        "@bazel_tools//tools/cpp:current_cc_toolchain",
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
        "@googletest//:gtest",
    ],
    deps = [":checks"],
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
        "@googletest//:gtest_main",
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
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@protobuf//:protobuf_lite",
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
        "@abseil-cpp//absl/random",
        "@abseil-cpp//absl/strings",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "line_printer",
    srcs = ["line_printer.cc"],
    hdrs = ["line_printer.h"],
    deps = [
        ":checks",
        "@abseil-cpp//absl/strings",
    ],
)

cc_library(
    name = "signals",
    srcs = ["signals.cc"],
    hdrs = ["signals.h"],
    deps = [
        ":checks",
    ],
)

cc_test(
    name = "signals_test",
    srcs = ["signals_test.cc"],
    deps = [
        ":checks",
        ":signals",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "span_util",
    hdrs = ["span_util.h"],
    deps = [
        ":checks",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_test(
    name = "span_util_test",
    srcs = ["span_util_test.cc"],
    deps = [
        ":span_util",
        "@abseil-cpp//absl/types:span",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "text_table",
    srcs = ["text_table.cc"],
    hdrs = ["text_table.h"],
    deps = [
        ":checks",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_library(
    name = "time_proto_util",
    srcs = ["time_proto_util.cc"],
    hdrs = ["time_proto_util.h"],
    deps = [
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
        "@protobuf",
    ],
)

cc_test(
    name = "time_proto_util_test",
    srcs = ["time_proto_util_test.cc"],
    deps = [
        ":time_proto_util",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/time",
        "@googletest//:gtest_main",
        "@protobuf",
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
        "@googletest//:gtest_main",
    ],
    deps = [
        ":checks",
        ":nolibc_gunit",
        ":x86_cpuid",
    ],
)

cc_library(
    name = "platform",
    srcs = ["platform.cc"] + select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/platform.cc",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/platform.cc",
        ],
    }),
    hdrs = ["platform.h"],
    deps = [
        ":arch",
        ":checks",
        ":itoa",
        ":misc_util",
        ":x86_cpuid",
        "@abseil-cpp//absl/container:flat_hash_map",
    ],
)

cc_test(
    name = "platform_test",
    size = "small",
    srcs = ["platform_test.cc"],
    deps = [
        ":arch",
        ":itoa",
        ":platform",
        "@silifuzz//proto:snapshot_cc_proto",
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/strings",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "ptrace_util",
    srcs = ["ptrace_util.cc"],
    hdrs = ["ptrace_util.h"],
    deps = [
        ":checks",
        ":itoa",
        ":subprocess",
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
        ":itoa",
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
        "@googletest//:gtest_main",
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
        "@googletest//:gtest_main",
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
        "@googletest//:gtest_main",
        "@protobuf",
    ],
)

cc_library(
    name = "subprocess",
    srcs = ["subprocess.cc"],
    hdrs = ["subprocess.h"],
    deps = [
        ":checks",
        ":itoa",
        ":signals",
        "@abseil-cpp//absl/base",
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/time",
    ],
)

cc_test(
    name = "subprocess_test",
    size = "medium",
    timeout = "short",
    srcs = ["subprocess_test.cc"],
    deps = [
        ":subprocess",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/time",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "thread_pool",
    hdrs = ["thread_pool.h"],
    deps = [
        ":checks",
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/functional:any_invocable",
        "@abseil-cpp//absl/synchronization",
    ],
)

cc_library_plus_nolibc(
    name = "file_util",
    srcs = ["file_util.cc"],
    hdrs = ["file_util.h"],
    as_is_deps = [
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/base:core_headers",
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
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
    ],
)

cc_test(
    name = "path_util_test",
    size = "medium",
    srcs = ["path_util_test.cc"],
    deps = [
        ":checks",
        ":path_util",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@googletest//:gtest_main",
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
        ":page_util",
        "@silifuzz//util:checks",
    ],
)

cc_library(
    name = "tool_util",
    srcs = ["tool_util.cc"],
    hdrs = ["tool_util.h"],
    deps = [
        ":checks",
        ":line_printer",
        "@abseil-cpp//absl/base:core_headers",
        "@abseil-cpp//absl/flags:parse",
        "@abseil-cpp//absl/flags:usage",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/types:span",
    ],
)

cc_test(
    name = "tool_util_test",
    srcs = ["tool_util_test.cc"],
    deps = [
        ":checks",
        ":file_util",
        ":path_util",
        ":tool_util",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@abseil-cpp//absl/strings:string_view",
        "@googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "arch",
    hdrs = [
        "arch.h",
    ],
    as_is_deps = [
        "@abseil-cpp//absl/base:core_headers",
    ],
    deps = [
        ":checks",
        ":itoa",
    ],
)

cc_test(
    name = "arch_test",
    srcs = ["arch_test.cc"],
    deps = [
        ":arch",
        ":checks",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "arch_mem",
    srcs = ["arch_mem.cc"],
    hdrs = ["arch_mem.h"],
    deps = [
        ":arch",
        ":checks",
        "@silifuzz//util/ucontext:ucontext_types",
    ],
)

cc_library_plus_nolibc(
    name = "page_util",
    hdrs = ["page_util.h"],
    deps = [":math"],
)

cc_test_plus_nolibc(
    name = "page_util_test",
    size = "small",
    srcs = ["page_util_test.cc"],
    libc_deps = [
        "@googletest//:gtest_main",
    ],
    deps = [
        ":checks",
        ":nolibc_gunit",
        ":page_util",
    ],
)

cc_library_plus_nolibc(
    name = "extension_registers",
    srcs =
        select({
            "@silifuzz//build_defs/platform:aarch64": [
                "aarch64/sve.S",
            ],
            "@silifuzz//build_defs/platform:x86_64": [
                "x86_64/opmask.S",
                "x86_64/xmm.S",
                "x86_64/ymm.S",
                "x86_64/zmm.S",
            ],
        }),
    hdrs = select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/extension_registers.h",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/extension_registers.h",
        ],
    }),
)

cc_test_plus_nolibc(
    name = "extension_registers_test",
    srcs =
        select({
            "@silifuzz//build_defs/platform:aarch64": [
                "aarch64/extension_registers_test.cc",
            ],
            "@silifuzz//build_defs/platform:x86_64": [
                "x86_64/extension_registers_test.cc",
                "x86_64/extension_registers_test_helpers.S",
                "x86_64/extension_registers_test_helpers.h",
            ],
        }),
    libc_deps = [
        "@googletest//:gtest_main",
    ],
    # We don't want calls in test helpers to go through PLTs.
    # The dynamic linker may clobber some extention registers.
    linkstatic = True,
    deps = [
        ":cpu_features",
        ":extension_registers",
        ":itoa",
        ":nolibc_gunit",
        ":reg_group_io",
        ":strcat",
        ":sve",
    ],
)

cc_library_plus_nolibc(
    name = "reg_group_bits",
    hdrs = ["reg_group_bits.h"],
)

cc_library_plus_nolibc(
    name = "reg_group_set",
    hdrs = ["reg_group_set.h"],
    deps = [
        ":arch",
        ":checks",
        ":reg_group_bits",
    ],
)

cc_test_plus_nolibc(
    name = "reg_group_set_test",
    srcs = ["reg_group_set_test.cc"],
    libc_deps = [
        "@googletest//:gtest_main",
    ],
    deps = [
        ":arch",
        ":checks",
        ":nolibc_gunit",
        ":reg_group_bits",
        ":reg_group_set",
    ],
)

cc_library_plus_nolibc(
    name = "reg_groups",
    srcs =
        select({
            "@silifuzz//build_defs/platform:aarch64": [
                "aarch64/reg_group_io_buffer_offsets.h",
                "aarch64/reg_groups.cc",
                "aarch64/sve_vector_width.S",
            ],
            "@silifuzz//build_defs/platform:x86_64": ["x86_64/reg_groups.cc"],
        }),
    hdrs = ["reg_groups.h"],
    # This dependency is only needed for x86. However, cc_library_plus_nolibc rule does not
    # support select() in deps.  So we unconditionally add this dependency.
    deps = [
        ":arch",
        ":cpu_features",
        ":extension_registers",
        ":reg_group_set",
        ":sve",
    ],
)

cc_test_plus_nolibc(
    name = "reg_groups_test",
    srcs = select({
        "@silifuzz//build_defs/platform:aarch64": ["aarch64/reg_groups_test.cc"],
        "@silifuzz//build_defs/platform:x86_64": ["x86_64/reg_groups_test.cc"],
    }),
    libc_deps = [
        "@googletest//:gtest_main",
    ],
    deps = [
        ":arch",
        ":byte_io",
        ":checks",
        ":nolibc_gunit",
        ":reg_group_set",
        ":reg_groups",
        ":sve",
    ],
)

cc_library_plus_nolibc(
    name = "reg_group_io",
    srcs = ["reg_group_io.cc"] + select({
        "@silifuzz//build_defs/platform:aarch64": [
            "aarch64/clear_register_groups.S",
            "aarch64/reg_group_io.cc",
            "aarch64/reg_group_io_buffer_offsets.h",
            "aarch64/save_register_groups_to_buffer.S",
            "aarch64/sve_vector_width.S",
        ],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/reg_group_io.cc",
            "x86_64/reg_group_io_buffer_offsets.h",
            "x86_64/save_register_groups_to_buffer.S",
        ],
    }),
    hdrs = ["reg_group_io.h"],
    # We don't want to produce a .so for this library as some code in this library is used
    # when the GOT pointer may not be set up properly.
    linkstatic = True,
    deps = [
        ":arch",
        ":checks",
        ":cpu_features",
        ":crc32c",
        ":extension_registers",
        ":reg_checksum",
        ":reg_group_bits",
        ":reg_group_set",
        ":sve",
        ":sve_constants",
    ],
)

cc_test_plus_nolibc(
    name = "reg_group_io_test",
    srcs = select({
        "@silifuzz//build_defs/platform:aarch64": ["aarch64/reg_group_io_test.cc"],
        "@silifuzz//build_defs/platform:x86_64": [
            "x86_64/reg_group_io_test.cc",
            "x86_64/reg_group_io_test_helpers.S",
        ],
    }),
    libc_deps = [
        "@googletest//:gtest_main",
    ],
    # We don't want calls in test helpers to go through PLTs.
    # The dynamic linker may clobber some extention registers.
    linkstatic = True,
    deps = [
        ":arch",
        ":checks",
        ":cpu_features",
        ":crc32c",
        ":extension_registers",
        ":nolibc_gunit",
        ":reg_checksum",
        ":reg_group_io",
        ":reg_group_set",
        ":reg_groups",
        ":sve",
    ],
)

cc_library_plus_nolibc(
    name = "reg_checksum",
    srcs = ["reg_checksum.cc"],
    hdrs = ["reg_checksum.h"],
    as_is_deps = [
        "@abseil-cpp//absl/base:endian",
    ],
    deps = [
        ":arch",
        ":reg_group_set",
    ],
)

cc_test_plus_nolibc(
    name = "reg_checksum_test",
    srcs = ["reg_checksum_test.cc"],
    libc_deps = [
        "@googletest//:gtest_main",
    ],
    deps = [
        ":arch",
        ":checks",
        ":nolibc_gunit",
        ":reg_checksum",
    ],
)

cc_library(
    name = "reg_checksum_util",
    srcs = ["reg_checksum_util.cc"],
    hdrs = ["reg_checksum_util.h"],
    deps = [
        ":arch",
        ":reg_checksum",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
    ],
)

cc_library(
    name = "user_regs_util",
    hdrs = ["user_regs_util.h"],
)

cc_test(
    name = "reg_checksum_util_test",
    srcs = ["reg_checksum_util_test.cc"],
    deps = [
        ":arch",
        ":reg_checksum",
        ":reg_checksum_util",
        "@silifuzz//util/testing:status_matchers",
        "@abseil-cpp//absl/status",
        "@googletest//:gtest_main",
    ],
)

cc_library_plus_nolibc(
    name = "sve_constants",
    hdrs = ["sve_constants.h"],
)

cc_library_plus_nolibc(
    name = "sve",
    hdrs = select({
        "@silifuzz//build_defs/platform:aarch64": ["aarch64/sve.h"],
        "@silifuzz//build_defs/platform:x86_64": [],
    }),
    deps = [
        ":checks",
        ":itoa",
        ":sve_constants",
    ],
)

cc_test_plus_nolibc(
    name = "sve_test",
    srcs = select({
        "@silifuzz//build_defs/platform:aarch64": ["aarch64/sve_test.cc"],
        "@silifuzz//build_defs/platform:x86_64": ["x86_64/sve_noop_test.cc"],
    }),
    libc_deps = [
        "@googletest//:gtest_main",
    ],
    deps = [
        ":checks",
        ":itoa",
        ":nolibc_gunit",
        ":sve",
    ],
)
