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

#include "./util/reg_checksum.h"

#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {

namespace {

template <typename Arch>
void RoundTripTestImpl() {
  RegisterChecksum<Arch> register_checksum;
  register_checksum.register_groups =
      RegisterGroupSet<Arch>::Deserialize(0x0123456789abcdef);
  register_checksum.checksum = 0xdeadbeefcafebabe;

  constexpr size_t kBufferSize = 256;
  uint8_t buffer[kBufferSize];
  ssize_t serialized_size = Serialize(register_checksum, buffer, kBufferSize);
  CHECK_NE(serialized_size, -1);
  CHECK_EQ(serialized_size, SerializedSize<Arch>());

  RegisterChecksum<Arch> deserialized;
  ssize_t deserialized_size =
      Deserialize(buffer, serialized_size, deserialized);
  CHECK_NE(deserialized_size, -1);
  CHECK_EQ(deserialized_size, serialized_size);

  CHECK(deserialized.register_groups == register_checksum.register_groups);
  CHECK_EQ(deserialized.checksum, register_checksum.checksum);
}

TEST(RegisterChecksum, RoundTripTest) {
  RoundTripTestImpl<X86_64>();
  RoundTripTestImpl<AArch64>();
}

TEST(RegisterChecksum, SerializeShouldFail) {
  RegisterChecksum<X86_64> register_checksum;
  register_checksum.register_groups =
      RegisterGroupSet<X86_64>::Deserialize(0x0123456789abcdef);
  register_checksum.checksum = 0xdeadbeefcafebabe;

  constexpr size_t kBufferSize = 1;
  uint8_t buffer[kBufferSize];
  ssize_t serialized_size = Serialize(register_checksum, buffer, kBufferSize);
  CHECK_EQ(serialized_size, -1);
}

TEST(RegisterChecksum, DeserializeShouldFail) {
  RegisterChecksum<X86_64> register_checksum;
  register_checksum.register_groups =
      RegisterGroupSet<X86_64>::Deserialize(0x0123456789abcdef);
  register_checksum.checksum = 0xdeadbeefcafebabe;

  constexpr size_t kBufferSize = 256;
  uint8_t buffer[kBufferSize];
  ssize_t serialized_size = Serialize(register_checksum, buffer, kBufferSize);

  // Insufficient data.
  RegisterChecksum<X86_64> deserialized;
  ssize_t deserialized_size =
      Deserialize(buffer, serialized_size - 1, deserialized);
  CHECK_EQ(deserialized_size, -1);

  // Wrong architecture.
  RegisterChecksum<AArch64> deserialized_other_arch;
  deserialized_size =
      Deserialize(buffer, serialized_size, deserialized_other_arch);
  CHECK_EQ(deserialized_size, -1);

  // Bad header.
  buffer[0] ^= 0xff;
  deserialized_size = Deserialize(buffer, serialized_size, deserialized);
  buffer[0] ^= 0xff;
  CHECK_EQ(deserialized_size, -1);

  // Bad version. This assumes knowledge of the header fields.  May be
  // we should export the header to this test.
  buffer[3] ^= 0xff;
  deserialized_size = Deserialize(buffer, serialized_size, deserialized);
  buffer[3] ^= 0xff;
  CHECK_EQ(deserialized_size, -1);
}

TEST(RegisterChecksum, SerializeResultDeterministic) {
  RegisterChecksum<Host> register_checksum;
  register_checksum.register_groups =
      RegisterGroupSet<Host>::Deserialize(0x0123456789abcdef);
  register_checksum.checksum = 0xdeadbeefcafebabe;

  constexpr size_t kBufferSize = 256;
  uint8_t buffer1[kBufferSize], buffer2[kBufferSize];
  memset(buffer1, 0xaa, sizeof(buffer1));
  memset(buffer2, 0x55, sizeof(buffer2));
  ssize_t serialized_size1 = Serialize(register_checksum, buffer1, kBufferSize);
  ssize_t serialized_size2 = Serialize(register_checksum, buffer2, kBufferSize);

  CHECK_EQ(serialized_size1, serialized_size2);
  CHECK_EQ(memcmp(buffer1, buffer2, serialized_size1), 0);
}
}  // namespace

}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(RegisterChecksum, RoundTripTest);
  RUN_TEST(RegisterChecksum, SerializeShouldFail);
  RUN_TEST(RegisterChecksum, DeserializeShouldFail);
  RUN_TEST(RegisterChecksum, SerializeResultDeterministic);
})
