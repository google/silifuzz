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

// Test for lss wrappers. We assume linux_syscall_support works so these are
// lightly tested.
#include <fcntl.h>
#include <linux/limits.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <csignal>
#include <cstring>

#include "third_party/lss/lss/linux_syscall_support.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/nolibc_gunit.h"
#include "./util/strcat.h"

// ========================================================================= //

namespace silifuzz {

namespace {

// By default test files are create readable and writable.
static constexpr int kDefaultOpenFlags = O_CREAT | O_TRUNC | O_RDWR;

// By default files are created to be user readable and writable only.
static constexpr mode_t kDefaultCreationMode = S_IRUSR | S_IWUSR;

// Holds a temporary file path.
class TempFilePath {
 public:
  explicit TempFilePath(const char* label) {
    // Temp file path is /tmp/syscalls_test.<label>.<pid>
    pid_t pid = sys_getpid();
    CHECK_NE(pid, -1)
    set_path(StrCat({"/tmp/syscalls_test.", label, ".", IntStr(pid)}));
  }
  ~TempFilePath() = default;

  // Copyable and movable by default.
  TempFilePath(const TempFilePath&) = default;
  TempFilePath& operator=(const TempFilePath&) = default;
  TempFilePath(TempFilePath&&) = default;
  TempFilePath& operator=(TempFilePath&&) = default;

  const char* path() const { return path_; }

 private:
  void set_path(const char* value) {
    // Neither strcpy() nor strncpy() is available in nolibc environment.
    size_t size = strlen(value) + 1;
    CHECK_LE(size, PATH_MAX);
    memcpy(path_, value, size);
  }

  char path_[PATH_MAX];
};

// In all tests below, use linux_syscall_support functions direct for unless
// it is for the syscall being tested.

TEST(Syscalls, close) {
  int fd = sys_open("/dev/zero", O_RDONLY, 0);
  CHECK_NE(fd, -1);
  errno = 0;
  int result = close(fd);
  CHECK_EQ(result, 0);
  CHECK_EQ(errno, 0);
}

TEST(Syscalls, getegid) { CHECK_EQ(getegid(), sys_getegid()); }

TEST(Syscalls, geteuid) { CHECK_EQ(geteuid(), sys_geteuid()); }

TEST(Syscalls, getpid) { CHECK_EQ(getpid(), sys_getpid()); }

TEST(Syscalls, kill) {
  // A process should have permission to signal itself.
  errno = 0;
  CHECK_EQ(kill(getpid(), 0), 0);
  CHECK_EQ(errno, 0);

  // Bad signal number.
  CHECK_EQ(kill(getpid(), 1000000), -1);
  CHECK_EQ(errno, EINVAL)
}

TEST(Syscalls, lseek) {
  TempFilePath temp("lseek");
  int fd = sys_open(temp.path(), kDefaultOpenFlags, kDefaultCreationMode);
  CHECK_NE(fd, -1);
  constexpr char kTestData[] = "Hello world.";
  constexpr size_t kTestDataSize = sizeof(kTestData);
  CHECK_EQ(sys_write(fd, kTestData, kTestDataSize), kTestDataSize);

  errno = 0;
  CHECK_EQ(lseek(fd, 2, SEEK_SET), 2);
  CHECK_EQ(errno, 0);
  CHECK_EQ(lseek(fd, 2, SEEK_CUR), 4);
  CHECK_EQ(errno, 0);
  CHECK_EQ(lseek(fd, -2, SEEK_END), kTestDataSize - 2);
  CHECK_EQ(errno, 0);

  CHECK_EQ(sys_close(fd), 0);
  CHECK_EQ(sys_unlink(temp.path()), 0);
}

TEST(Syscalls, mmap) {
  // mapping a length of 0 should return EINVAL.
  errno = 0;
  CHECK_EQ(mmap(nullptr, 0, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS,
                -1, 0),
           MAP_FAILED);
  CHECK_EQ(errno, EINVAL);

  size_t page_size = getpagesize();
  errno = 0;
  void* ptr = mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK_NE(ptr, MAP_FAILED);
  CHECK_EQ(errno, 0);

  // Check that memory is mapped.
  int fd = open("/dev/zero", O_RDONLY);
  CHECK_NE(fd, -1);
  CHECK_EQ(read(fd, ptr, page_size), page_size);

  CHECK_EQ(munmap(ptr, page_size), 0);
  CHECK_EQ(close(fd), 0);
}

TEST(Syscalls, mprotect) {
  // Check error reproting.
  // mprotect unaligned address should return EINVAL.
  errno = 0;
  size_t page_size = getpagesize();
  CHECK_EQ(
      mprotect(reinterpret_cast<void*>(1), page_size, PROT_READ | PROT_WRITE),
      -1);
  CHECK_EQ(errno, EINVAL);

  errno = 0;
  void* ptr =
      mmap(nullptr, page_size, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK_NE(ptr, MAP_FAILED);

  errno = 0;
  CHECK_EQ(mprotect(ptr, page_size, PROT_READ | PROT_WRITE), 0);
  CHECK_EQ(errno, 0);

  // Check memory is writable.
  constexpr size_t kReadSize = 1;
  int fd = open("/dev/zero", O_RDONLY);
  CHECK_NE(fd, -1);
  CHECK_EQ(read(fd, ptr, kReadSize), kReadSize);

  // Change permission again.
  errno = 0;
  CHECK_EQ(mprotect(ptr, page_size, PROT_READ), 0);
  CHECK_EQ(errno, 0);

  // Check memory is not writable.
  CHECK_EQ(read(fd, ptr, kReadSize), -1);
  CHECK_EQ(errno, EFAULT);

  // Check that syscall accepts an unaligned length and does the right thing.
  errno = 0;
  CHECK_EQ(mprotect(ptr, page_size - 1, PROT_READ | PROT_WRITE), 0);
  CHECK_EQ(errno, 0);

  // Memory should be writable now.
  CHECK_EQ(read(fd, ptr, kReadSize), kReadSize);

  CHECK_EQ(munmap(ptr, page_size), 0);
  CHECK_EQ(close(fd), 0);
}

TEST(Syscalls, munmap) {
  size_t page_size = getpagesize();
  errno = 0;
  void* ptr = sys_mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  CHECK_NE(ptr, MAP_FAILED);
  CHECK_EQ(errno, 0);

  errno = 0;
  CHECK_EQ(munmap(ptr, page_size), 0);
  CHECK_EQ(errno, 0);

  // Check that memory is not mapped.
  int fd = open("/dev/zero", O_RDONLY);
  CHECK_NE(fd, -1);
  constexpr size_t kReadSize = 1;
  CHECK_EQ(read(fd, ptr, kReadSize), -1);
  CHECK_EQ(errno, EFAULT);

  CHECK_EQ(close(fd), 0);
}

TEST(Syscalls, open) {
  // Try opening some well known file.
  errno = 0;
  int fd = open("/dev/zero", O_RDONLY, 0);
  CHECK_NE(fd, -1);
  CHECK_EQ(errno, 0);
  CHECK_EQ(sys_close(fd), 0);

  // Try opening non-existant file.
  fd = open("/this does not exist", O_RDONLY);
  CHECK_EQ(fd, -1);
  CHECK_EQ(errno, ENOENT);

  // Test passing mode.
  errno = 0;
  TempFilePath temp("open");
  fd = open(temp.path(), kDefaultOpenFlags, kDefaultCreationMode);
  if (fd == -1) {
    LOG_ERROR("open()", ErrnoStr(errno));
  }
  CHECK_NE(fd, -1);

  kernel_stat ks;
  CHECK_EQ(sys_fstat(fd, &ks), 0);
  const mode_t kMask = S_IRWXU | S_IRWXG | S_IRWXO;
  CHECK_EQ(ks.st_mode & kMask, kDefaultCreationMode);
  CHECK_EQ(sys_close(fd), 0);
  CHECK_EQ(sys_unlink(temp.path()), 0);
}

TEST(Syscalls, prctl) {
  // Lightly test the interface using PR_GET_DUMPABLE & PR_SET_DUMPABLE.
  // Most other functionalities require newer kernels, are platforms specific,
  // or do very significant changes that may affect other tests (.e.g SECCOMP).
  // Passing of arguments arg3 to arg5 is not exercised.
  errno = 0;
  int old_dumpable = prctl(PR_GET_DUMPABLE);
  CHECK_NE(old_dumpable, -1);
  CHECK_EQ(errno, 0);

  int new_dumpable = old_dumpable == 0 ? 1 : 0;
  CHECK_EQ(prctl(PR_SET_DUMPABLE, new_dumpable), 0);
  CHECK_EQ(errno, 0);
  CHECK_EQ(prctl(PR_GET_DUMPABLE), new_dumpable);
  CHECK_EQ(errno, 0);

  CHECK_EQ(prctl(PR_SET_DUMPABLE, 9999), -1);
  CHECK_EQ(errno, EINVAL);

  // Restore old dumpable setting.
  CHECK_EQ(prctl(PR_SET_DUMPABLE, old_dumpable), 0);
  CHECK_EQ(errno, EINVAL);
}

TEST(Syscalls, read) {
  int fd = sys_open("/dev/zero", O_RDONLY, 0);
  CHECK_NE(fd, -1);
  constexpr size_t kBufferSize = 20;
  char buffer[kBufferSize];
  constexpr char kFiller = 'a';
  memset(buffer, kFiller, kBufferSize);

  errno = 0;
  constexpr size_t kReadSize = kBufferSize / 2;
  constexpr size_t kOffset = 1;
  ssize_t bytes_read = read(fd, buffer + kOffset, kReadSize);
  CHECK_EQ(bytes_read, kReadSize);
  CHECK_EQ(errno, 0);
  // Test that data read as expected and read() does not overwrite.
  for (size_t i = 0; i < kBufferSize; ++i) {
    const char kExpected =
        (i < kOffset) || (i >= kOffset + kReadSize) ? kFiller : 0;
    CHECK_EQ(buffer[i], kExpected);
  }

  CHECK_EQ(sys_close(fd), 0);
}

TEST(Syscalls, sigaltstack) {
  // Get old alt-stack.
  stack_t old_ss;
  CHECK_EQ(sigaltstack(nullptr, &old_ss), 0);

  // Allocate a block big enough for a signal stack.
  static char alt_stack[64 * 1024] = {0};

  // Using a zero-sized stack should fail.
  stack_t ss{.ss_sp = alt_stack, .ss_flags = 0, .ss_size = 0};
  errno = 0;
  CHECK_EQ(sigaltstack(&ss, nullptr), -1);
  CHECK_EQ(errno, ENOMEM);

  // This should work.
  ss.ss_size = sizeof(alt_stack);
  errno = 0;
  CHECK_EQ(sigaltstack(&ss, nullptr), 0);

  // Restore old signal stack. We should read back our stack.
  stack_t ss_check;
  CHECK_EQ(sigaltstack(&old_ss, &ss_check), 0);
  CHECK_EQ(ss_check.ss_sp, alt_stack);
  CHECK_EQ(ss_check.ss_size, sizeof(alt_stack));
  CHECK_EQ(ss_check.ss_flags, 0);
}

TEST(Syscalls, write) {
  TempFilePath temp("write");
  int fd = sys_open(temp.path(), kDefaultOpenFlags, kDefaultCreationMode);
  CHECK_NE(fd, -1);
  constexpr char kTestData[] = "Hello world.";
  constexpr size_t kTestDataSize = sizeof(kTestData);
  errno = 0;
  ssize_t bytes_written = write(fd, kTestData, kTestDataSize);
  CHECK_EQ(bytes_written, kTestDataSize);
  CHECK_EQ(errno, 0);

  // Read back to ensure write() is correct.
  char buffer[kTestDataSize];
  CHECK_EQ(sys_lseek(fd, 0, SEEK_SET), 0);
  CHECK_EQ(sys_read(fd, buffer, kTestDataSize), kTestDataSize);
  CHECK_EQ(bcmp(kTestData, buffer, kTestDataSize), 0);

  CHECK_EQ(sys_close(fd), 0);
  CHECK_EQ(sys_unlink(temp.path()), 0);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(Syscalls, close);
  RUN_TEST(Syscalls, getegid);
  RUN_TEST(Syscalls, geteuid);
  RUN_TEST(Syscalls, getpid);
  RUN_TEST(Syscalls, kill);
  RUN_TEST(Syscalls, lseek);
  RUN_TEST(Syscalls, mmap);
  RUN_TEST(Syscalls, mprotect);
  RUN_TEST(Syscalls, munmap);
  RUN_TEST(Syscalls, open);
  RUN_TEST(Syscalls, prctl);
  RUN_TEST(Syscalls, read);
  RUN_TEST(Syscalls, sigaltstack);
  RUN_TEST(Syscalls, write);
})
