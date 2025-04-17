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
        "@abseil-cpp//absl/log:check",
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
        "@abseil-cpp//absl/container:flat_hash_map",
        "@abseil-cpp//absl/log:check",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/strings",
        "@abseil-cpp//absl/strings:str_format",
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
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
        "@abseil-cpp//absl/strings:str_format",
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
        "@abseil-cpp//absl/log",
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
        "@abseil-cpp//absl/status",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "page_table_test_util",
    testonly = True,
    hdrs = ["page_table_test_util.h"],
    deps = [
        ":page_table_entry_util",
        ":physical_address",
        ":virtual_address",
        "@silifuzz//util:checks",
        "@abseil-cpp//absl/status:statusor",
    ],
)

cc_test(
    name = "page_table_creator_test",
    size = "small",
    srcs = ["page_table_creator_test.cc"],
    deps = [
        ":page_table_creator",
        ":page_table_test_util",
        "@silifuzz//common:memory_mapping",
        "@silifuzz//common:memory_perms",
        "@silifuzz//util:arch",
        "@silifuzz//util/testing:status_macros",
        "@silifuzz//util/testing:status_matchers",
        "@abseil-cpp//absl/base",
        "@abseil-cpp//absl/status",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "memory_state_image",
    srcs = ["memory_state_image.cc"],
    hdrs = ["memory_state_image.h"],
    deps = [
        ":page_table_creator",
        "@silifuzz//common:mapped_memory_map",
        "@silifuzz//common:memory_mapping",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:memory_state",
        "@silifuzz//util:arch",
        "@silifuzz//util:checks",
        "@abseil-cpp//absl/status",
        "@abseil-cpp//absl/status:statusor",
    ],
)

cc_test(
    name = "memory_state_image_test",
    srcs = ["memory_state_image_test.cc"],
    deps = [
        ":memory_state_image",
        ":page_table_test_util",
        "@silifuzz//common:memory_mapping",
        "@silifuzz//common:memory_perms",
        "@silifuzz//common:memory_state",
        "@silifuzz//common:snapshot",
        "@silifuzz//util:arch",
        "@silifuzz//util/testing:status_macros",
        "@abseil-cpp//absl/cleanup",
        "@googletest//:gtest_main",
    ],
)
