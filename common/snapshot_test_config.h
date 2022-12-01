// Copyright 2022 The SiliFuzz Authors.
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

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TEST_CONFIG_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TEST_CONFIG_H_

#include "./common/snapshot.h"
#include "./common/snapshot_test_enum.h"

namespace silifuzz {

struct TestSnapshotConfig {
  TestSnapshot type;
  Snapshot::Architecture arch;
  uint64_t code_addr;
  uint64_t code_num_bytes;
  uint64_t data_addr;
  uint64_t data_num_bytes;
  std::string instruction_bytes;
  bool normal_end;
  uint64_t stack_bytes_used;
};

// Return a configuration that describes how to construct the Snapshot for a
// particular TestSnapshot. The configuration may vary across different target
// architectures. Some configurations may not exist for a some target
// architectures. If the configuration does not exist, nullptr will be returned.
const TestSnapshotConfig* GetTestSnapshotConfig(Snapshot::Architecture arch,
                                                TestSnapshot type);

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_TEST_CONFIG_H_
