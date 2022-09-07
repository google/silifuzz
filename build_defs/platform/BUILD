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

"""Build system  platform configuration values."""

load("@bazel_skylib//lib:selects.bzl", "selects")

selects.config_setting_group(
    name = "x86_64",
    match_any = ["@platforms//cpu:x86_64"],
)

selects.config_setting_group(
    name = "aarch64",
    match_any = ["@platforms//cpu:aarch64"],
)
