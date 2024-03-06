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

#include "./common/proxy_config.h"

#include "./common/mapped_memory_map.h"
#include "./common/memory_perms.h"
#include "./util/arch.h"

namespace silifuzz {

namespace {

void AddCodeRange(const MemoryRange& range,
                  MappedMemoryMap& mapped_memory_map) {
  mapped_memory_map.AddNew(range.start_address,
                           range.start_address + range.num_bytes,
                           MemoryPerms::XR());
}

void AddDataRange(const MemoryRange& range,
                  MappedMemoryMap& mapped_memory_map) {
  mapped_memory_map.AddNew(range.start_address,
                           range.start_address + range.num_bytes,
                           MemoryPerms::RW());
}

}  // namespace

MappedMemoryMap FuzzConfigToMappedMemoryMap(
    const FuzzingConfig<X86_64>& config) {
  MappedMemoryMap mapped_memory_map;
  AddCodeRange(config.code_range, mapped_memory_map);
  AddDataRange(config.data1_range, mapped_memory_map);
  AddDataRange(config.data2_range, mapped_memory_map);
  return mapped_memory_map;
}

MappedMemoryMap FuzzConfigToMappedMemoryMap(
    const FuzzingConfig<AArch64>& config) {
  MappedMemoryMap mapped_memory_map;
  AddCodeRange(config.code_range, mapped_memory_map);
  AddDataRange(config.stack_range, mapped_memory_map);
  AddDataRange(config.data1_range, mapped_memory_map);
  AddDataRange(config.data2_range, mapped_memory_map);
  return mapped_memory_map;
}

}  // namespace silifuzz
