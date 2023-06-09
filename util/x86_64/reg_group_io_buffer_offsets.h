// Copyright 2023 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_UTIL_X86_64_REG_GROUP_IO_BUFFER_OFFSETS_H_
#define THIRD_PARTY_SILIFUZZ_UTIL_X86_64_REG_GROUP_IO_BUFFER_OFFSETS_H_

// Offsets of data members of RegisterGroupIOBuffer.  These are used by
// assembly functions.
#define REGISTER_GROUP_IO_BUFFER_REGISTER_GROUPS_OFFSET 0
#define REGISTER_GROUP_IO_BUFFER_YMM_OFFSET 32
#define REGISTER_GROUP_IO_BUFFER_ZMM_OFFSET 576
#define REGISTER_GROUP_IO_BUFFER_OPMASK_OFFSET 2624

#endif  // THIRD_PARTY_SILIFUZZ_UTIL_X86_64_REG_GROUP_IO_BUFFER_OFFSETS_H_
