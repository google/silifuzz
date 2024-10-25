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

// This file contains OS interface functions like open() and mmap().
// These should be thin wrappers for functions in linux_syscall_support.h.
//
// This file should only depend on system headers and linux_syscall_support.h.

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstddef>

#include "third_party/lss/lss/linux_syscall_support.h"

extern "C" {

int close(int fd) { return sys_close(fd); }

// _exit() calls sys_exit_group() instead of sys_exit(). sys_exit() just
// terminates the current thread where as sys_exit_group() terminates the thread
// group of the current process. This is what a user expects when calling
// _exit().
void _exit(int status) {
  sys_exit_group(status);
  __builtin_unreachable();
}

gid_t getegid(void) { return sys_getegid(); }

uid_t geteuid(void) { return sys_geteuid(); }

pid_t getpid(void) { return sys_getpid(); }

int kill(pid_t pid, int sig) { return sys_kill(pid, sig); }

off_t lseek(int fd, off_t offset, int whence) {
  return sys_lseek(fd, offset, whence);
}

void *mmap(void *addr, size_t length, int prot, int flags, int fd,
           off_t offset) {
  return sys_mmap(addr, length, prot, flags, fd, offset);
}

int mprotect(void *addr, size_t len, int prot) {
  return sys_mprotect(addr, len, prot);
}

int munmap(void *addr, size_t length) { return sys_munmap(addr, length); }

int open(const char *pathname, int flags, ...) {
  int mode = 0;

  // `mode` is ignored unless one of O_CREAT|O_TMPFILE is given. The Linux man
  // page says an arbitratry value from the stack is used if callee does not
  // supply a mode and any of O_CREAT|O_TMPFILE is set.
  if ((flags & (O_CREAT | O_TMPFILE)) != 0) {
    va_list ap;
    va_start(ap, flags);
    mode = va_arg(ap, mode_t);
    va_end(ap);
  }
  return sys_open(pathname, flags, mode);
}

// The Linux man page says prctl() always take 5 arguments but the header
// sys/prctl.h declares prctl() to have varargs. Here we follow the header.
int prctl(int option, ...) {
  unsigned long arg2, arg3, arg4, arg5;  // NOLINT(runtime/int)
  // We always take 4 arguments after option. Most prctl() functions do not
  // need all 4. We may get some garbage on stack but those should be ignored
  // unless arguments are specified. See "man prctl" for details.
  va_list ap;
  va_start(ap, option);
  arg2 = va_arg(ap, unsigned long);  // NOLINT(runtime/int)
  arg3 = va_arg(ap, unsigned long);  // NOLINT(runtime/int)
  arg4 = va_arg(ap, unsigned long);  // NOLINT(runtime/int)
  arg5 = va_arg(ap, unsigned long);  // NOLINT(runtime/int)
  va_end(ap);
  return sys_prctl(option, arg2, arg3, arg4, arg5);
}

ssize_t read(int fd, void *buf, size_t count) {
  return sys_read(fd, buf, count);
}

pid_t setsid() { return sys_setsid(); }

int sigaltstack(const stack_t *ss, stack_t *old_ss) {
  return sys_sigaltstack(ss, old_ss);
}

ssize_t write(int fd, const void *buf, size_t count) {
  return sys_write(fd, buf, count);
}

}  // extern "C"
