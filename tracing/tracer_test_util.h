// Copyright 2025 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_TRACING_TRACER_TEST_UTIL_H_
#define THIRD_PARTY_SILIFUZZ_TRACING_TRACER_TEST_UTIL_H_

#include "./common/mapped_memory_map.h"
#include "./common/memory_perms.h"
#include "./common/proxy_config.h"
#include "./util/arch.h"

namespace silifuzz {

namespace tracer_test_internal {

template <typename Arch>
MappedMemoryMap GetMemoryMapFromConfig(
    const FuzzingConfig<Arch>& fuzzing_config) {
  MappedMemoryMap expected_data_memory_map;
  expected_data_memory_map.Add(fuzzing_config.data1_range.start_address,
                               fuzzing_config.data1_range.start_address +
                                   fuzzing_config.data1_range.num_bytes,
                               MemoryPerms::RW());
  expected_data_memory_map.Add(fuzzing_config.data2_range.start_address,
                               fuzzing_config.data2_range.start_address +
                                   fuzzing_config.data2_range.num_bytes,
                               MemoryPerms::RW());
  expected_data_memory_map.Add(fuzzing_config.code_range.start_address,
                               fuzzing_config.code_range.start_address +
                                   fuzzing_config.code_range.num_bytes,
                               MemoryPerms::XR());
  return expected_data_memory_map;
}

}  // namespace tracer_test_internal

inline MappedMemoryMap GetMemoryMapFromConfig(
    const FuzzingConfig<X86_64>& fuzzing_config) {
  return tracer_test_internal::GetMemoryMapFromConfig<X86_64>(fuzzing_config);
}

inline MappedMemoryMap GetMemoryMapFromConfig(
    const FuzzingConfig<AArch64>& fuzzing_config) {
  MappedMemoryMap expected_data_memory_map =
      tracer_test_internal::GetMemoryMapFromConfig<AArch64>(fuzzing_config);
  // Aarch64 fuzzing config has a separate stack region.
  expected_data_memory_map.Add(fuzzing_config.stack_range.start_address,
                               fuzzing_config.stack_range.start_address +
                                   fuzzing_config.stack_range.num_bytes,
                               MemoryPerms::RW());
  return expected_data_memory_map;
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_TRACING_TRACER_TEST_UTIL_H_
