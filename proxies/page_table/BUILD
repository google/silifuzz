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
    ],
    deps = [
        ":bit_struct",
        "@silifuzz//util:arch",
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
