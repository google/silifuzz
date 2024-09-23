// Copyright 2024 The SiliFuzz Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

        .bss
// Flag to tell if SVE is supported.
        .align  1
        .globl  reg_group_io_supports_sve
        .type   reg_group_io_supports_sve, @object
        .size   reg_group_io_supports_sve, 1
reg_group_io_supports_sve:
        .zero   1
