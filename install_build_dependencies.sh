#!/bin/bash
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

# Tested on Debian GNU/Linux 11 (bullseye)
#
# * git: to get the SiliFuzz sources.
# * bazel, clang, lld, python: to build SiliFuzz
# * libssl-dev: silifuzz uses SHA1.
#   Clang 11 or newer will work.
#   To get all of the functionality you may need to install fresh clang from
#   source: https://llvm.org/.

set -eu

apt update
apt install -y curl gnupg apt-transport-https ca-certificates

# Add Bazel distribution URI as a package source following:
# https://docs.bazel.build/versions/main/install-ubuntu.html
curl -fsSL https://bazel.build/bazel-release.pub.gpg \
  | gpg --dearmor > /etc/apt/trusted.gpg.d/bazel.gpg
echo "deb [arch=amd64] https://storage.googleapis.com/bazel-apt stable jdk1.8" \
  | tee /etc/apt/sources.list.d/bazel.list
apt update

# Install dependencies.
apt install --no-install-recommends -y git bazel libssl-dev clang libclang-rt-dev lld python3 libpython3-stdlib
