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

# Libraries related to creating page tables for proxies with limited memory.

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "bit_struct",
    hdrs = ["bit_struct.h"],
    deps = [
        "@com_google_absl//absl/log:check",
    ],
)

cc_library(
    name = "page_descriptor_entry",
    hdrs = [
        "aarch64/page_descriptor_entry.h",
        "x86_64/page_descriptor_entry.h",
    ],
    deps = [
        ":bit_struct",
        "@silifuzz//util:arch",
    ],
)

cc_library(
    name = "page_table_creator",
    srcs = ["page_table_creator.cc"],
    hdrs = ["page_table_creator.h"],
    deps = [
        ":page_table_entry_util",
        ":physical_address",
        ":virtual_address",
        "@silifuzz//common:memory_mapping",
        "@silifuzz//common:memory_perms",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@com_google_absl//absl/container:flat_hash_map",
        "@com_google_absl//absl/log:check",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/strings",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "page_table_entry_util",
    srcs = ["page_table_entry_util.cc"],
    hdrs = ["page_table_entry_util.h"],
    deps = [
        ":page_descriptor_entry",
        ":physical_address",
        ":table_descriptor_entry",
        "@silifuzz//util:arch",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_absl//absl/strings:str_format",
    ],
)

cc_library(
    name = "physical_address",
    hdrs = ["physical_address.h"],
    deps = [
        ":bit_struct",
    ],
)

cc_library(
    name = "table_descriptor_entry",
    hdrs = [
        "aarch64/table_descriptor_entry.h",
        "x86_64/table_descriptor_entry.h",
    ],
    deps = [
        ":bit_struct",
        "@silifuzz//util:arch",
    ],
)

cc_library(
    name = "virtual_address",
    hdrs = ["virtual_address.h"],
    deps = [
        ":bit_struct",
        "@com_google_absl//absl/log",
    ],
)

cc_test(
    name = "page_table_entry_util_test",
    size = "small",
    srcs = ["page_table_entry_util_test.cc"],
    deps = [
        ":page_table_entry_util",
        ":physical_address",
        "@silifuzz//util:arch",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/status",
        "@com_google_googletest//:gtest_main",
    ],
)

cc_test(
    name = "page_table_creator_test",
    size = "small",
    srcs = ["page_table_creator_test.cc"],
    deps = [
        ":page_table_creator",
        ":page_table_entry_util",
        ":physical_address",
        ":virtual_address",
        "@silifuzz//common:memory_mapping",
        "@silifuzz//common:memory_perms",
        "@silifuzz//util:arch",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@com_google_absl//absl/base",
        "@com_google_absl//absl/status",
        "@com_google_absl//absl/status:statusor",
        "@com_google_googletest//:gtest_main",
    ],
)
