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

#include "./util/byte_io.h"

#include <asm-generic/errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <stdlib.h>  // getenv()
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

namespace silifuzz {
namespace {

TEST(ByteIO, ReadEmpty) { CHECK_EQ(Read(STDIN_FILENO, nullptr, 0), 0); }

TEST(ByteIO, ReadBadFD) {
  uint8_t buffer[100];
  CHECK_LT(Read(-1, buffer, sizeof(buffer)), 0);
}

TEST(ByteIO, ReadBasicTest) {
  constexpr size_t kBufferSize = 1024;
  constexpr size_t kBlockSize = kBufferSize / 2;
  constexpr size_t kBlockOffset = kBufferSize / 4;
  uint8_t buffer[kBufferSize];
  memset(buffer, 0xff, sizeof(buffer));
  static uint8_t kBlockOfZeros[kBlockSize];

  // Read a block from /dev/zero.
  int fd = open("/dev/zero", O_RDONLY);
  CHECK_GT(fd, 0);
  ssize_t bytes_read = Read(fd, buffer + kBlockOffset, kBlockSize);

  // Check number of bytes read.
  CHECK_EQ(bytes_read, kBlockSize);

  // Check that Read() did not overwrite.
  CHECK_EQ(buffer[kBlockOffset - 1], 0xff);
  CHECK_EQ(buffer[kBlockOffset + kBlockSize], 0xff);

  // Check read contents.
  CHECK_EQ(memcmp(buffer + kBlockOffset, kBlockOfZeros, kBlockSize), 0);

  CHECK_EQ(close(fd), 0);
}

TEST(ByteIO, WriteEmpty) { CHECK_EQ(Read(STDOUT_FILENO, nullptr, 0), 0); }

TEST(ByteIO, WriteBadFD) {
  uint8_t buffer[100];
  memset(buffer, 0, sizeof(buffer));
  CHECK_LT(Write(-1, buffer, sizeof(buffer)), 0);
}

TEST(ByteIO, WriteBasicTest) {
  const char* tmp_dir = ::getenv("TEST_TMPDIR");
  CHECK_NE(tmp_dir, nullptr);
  const int fd = open(tmp_dir, O_TMPFILE | O_RDWR, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    if (errno == EOPNOTSUPP) {
      LOG_ERROR("Skipping test because O_TMPFILE is not supported on ",
                tmp_dir);
      return;
    }
    CHECK_EQ(errno, 0);
    CHECK_GT(fd, 0);
  }
  const uint8_t kTestData[] = "Hello World";
  const size_t kTestDataSize = sizeof(kTestData);
  const ssize_t bytes_written = Write(fd, kTestData, kTestDataSize);
  CHECK_EQ(bytes_written, kTestDataSize);

  // Read it back to verify correct contents being written.
  CHECK_EQ(lseek(fd, 0, SEEK_SET), 0);
  uint8_t read_back_buffer[kTestDataSize];
  const ssize_t bytes_read = Read(fd, read_back_buffer, kTestDataSize);
  CHECK_EQ(bytes_read, kTestDataSize);
  CHECK_EQ(memcmp(kTestData, read_back_buffer, kTestDataSize), 0);

  CHECK_EQ(close(fd), 0);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(ByteIO, ReadEmpty);
  RUN_TEST(ByteIO, ReadBadFD);
  RUN_TEST(ByteIO, ReadBasicTest);
  RUN_TEST(ByteIO, WriteEmpty);
  RUN_TEST(ByteIO, WriteBadFD);
  RUN_TEST(ByteIO, WriteBasicTest);
})
