# Copyright 2026 The SiliFuzz Authors.
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

"""File utilities for SiliFuzz minimizer.

Provides a unified interface for file operations, using internal file APIs
internally in Google3 and standard python file operations in open-source.
"""

from typing import Any, IO

import os

def open_file(name: str, mode: str = "r") -> IO[Any]:
  return open(name, mode)

def file_exists(name: str) -> bool:
  return os.path.exists(name)

def get_resource_filename(name: str) -> str:
  curr = os.path.abspath(__file__)
  for _ in range(3):
    curr = os.path.dirname(curr)
  path = os.path.join(curr, name)
  if os.path.exists(path):
    return path
  return os.path.basename(name)
