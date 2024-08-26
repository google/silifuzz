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

// This library (when built in the "nolibc" mode - see nolibc.bzl)
// provides definitions for the few utils from libc and libc++
// that are necessary to successfully link a basic binary without libc
// that does not use much of libc and C++ runtime libs.
//
// The cc_binary_plus_nolibc rule from nolibc.bzl will automatically
// bring this library in.
//
// See also nolibc.h.

#ifdef SILIFUZZ_BUILD_FOR_NOLIBC

#include <stdint.h>  // for uintptr_t
#include <stdio.h>   // for FILE
#include <string.h>  // for strlen()
#include <sys/auxv.h>
#include <unistd.h>  // for _exit()

#include <cstddef>  // for std::size_t

#include "./util/checks.h"

// Points to the auxiliary vector.
static const Elf64_auxv_t* aux_vector;

// Environment.
static char** envp;

int main(int argc, char** argv, char** envp);

// Process initialization and termination. This is called by assembly function
// _start().
extern "C" void _start_1(long* raw_stack) {  // NOLINT
  int argc = raw_stack[0];
  char** argv = reinterpret_cast<char**>(raw_stack + 1);
  // envp is after a null-terminated argv.
  envp = argv + argc + 1;
  // Find address of the auxiliary vector, which is right after envp array.
  char** ptr = envp;
  while (*ptr != nullptr) ++ptr;
  aux_vector = reinterpret_cast<const Elf64_auxv_t*>(ptr + 1);

  const int exit_code = main(argc, argv, envp);
  _exit(exit_code);
  __builtin_unreachable();
}

// Provide a glibc compatible implementation for errno. Currently, Silifuzz
// is built on systems with glibc headers.  This needs to be changed should
// we build Silifuzz using headers from other C libraries.
//
// This only works in a single-threaded environment. One some platforms like
// x86_64, we cannot save and restore the thread local storage pointer without
// using syscalls. Therefore we cannot use thread locals in the runner, which
// is allowed to use a few syscalls. Unless we lift this restriction, nolibc
// environment remains single-threaded.
//
extern "C" int* __errno_location() {
  static int errno_var = 0;
  return &errno_var;
}

// ========================================================================= //
// Provide impl for __assert_fail().
// E.g. impl of checksum.cc calls assert() and needs it.

#ifndef NDEBUG
extern "C" void __assert_fail(const char* assertion, const char* file,
                              unsigned int line, const char* function) __THROW {
  // Do a little abstraction breakage into the impl parts of checks.h:
  silifuzz::checks_internal::LogImpl(
      silifuzz::checks_internal::kFatal,
      silifuzz::checks_internal::Basename(file, strlen(file)), line,
      "assert() failed: ", silifuzz::checks_internal::kNotChopped, assertion,
      " in ", function);
  __builtin_unreachable();
}
#endif  // ndef NDEBUG

// ========================================================================= //
// Provide impls for operator new/delete.

// Some code for destructors to derived classes calls operator delete and is not
// thrown-away during static binary linkage because vtable references it.
void operator delete(void*, std::size_t) noexcept {
  LOG_FATAL("operator delete called");
}

// Uncomment these if calls to them exist but are not happening when
// executing the _nolibc code.
#if 0
void* operator new(std::size_t) {
  LOG_FATAL("operator new called");
}

void* operator new[](std::size_t) {
  LOG_FATAL("operator new[] called");
}

void operator delete[](void*, std::size_t) noexcept {
  LOG_FATAL("operator delete[] called");
}
#endif  // 0

// ========================================================================= //
// Provide impl for __cxa_pure_virtual().
// code for non-abstract classes with pure-virtual functions calls it.

extern "C" void __cxa_pure_virtual() {
  LOG_FATAL("A pure virtual function is called");
}

// ========================================================================= //
// Provide impl for abort().

extern "C" void abort() { LOG_FATAL("abort() is called"); }

// ========================================================================= //
// Provide impls for some ctype.h functions.
// These only work as if we are always using "C" locale.
extern "C" int isxdigit(int c) {
  return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') ||
         (c >= 'a' && c <= 'f');
}

// ========================================================================= //
// Provide impls for memcpy(), memset(), strlen(), memcmp(), bcmp().
// C++ code and/or some of silifuzz code calls these.
// Simple non-optimized impls suffice for now.

void* memcpy(void* dest, const void* src, size_t len) {
  auto d = reinterpret_cast<char*>(dest);
  auto s = reinterpret_cast<const char*>(src);
  auto end = d + len;
  while (d < end) {
    *(d++) = *(s++);
  }
  return dest;
}

void* memset(void* dest, int c, size_t len) {
  auto d = reinterpret_cast<char*>(dest);
  auto end = d + len;
  while (d < end) {
    *(d++) = c;
  }
  return dest;
}

size_t strlen(const char* str) {
  const char* s = str;
  for (; *s != '\0'; ++s) {
  }
  return s - str;
}

int memcmp(const void* s1, const void* s2, size_t len) {
  // C standards require objects compared to be intepreted as unsigned chars.
  const unsigned char* uc_ptr1 = reinterpret_cast<const unsigned char*>(s1);
  const unsigned char* uc_ptr2 = reinterpret_cast<const unsigned char*>(s2);
  for (size_t i = 0; i < len; ++i) {
    // Widened to ints for generating negative comparison results.
    int c = static_cast<int>(uc_ptr1[i]) - static_cast<int>(uc_ptr2[i]);
    if (c != 0) return c;
  }
  return 0;
}

int bcmp(const void* s1, const void* s2, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (reinterpret_cast<const char*>(s1)[i] !=
        reinterpret_cast<const char*>(s2)[i]) {
      return 1;
    }
  }
  return 0;
}

int strcmp(const char* str1, const char* str2) {
  // Comparison is done using unsigned character.
  const unsigned char* uc_ptr1 = reinterpret_cast<const unsigned char*>(str1);
  const unsigned char* uc_ptr2 = reinterpret_cast<const unsigned char*>(str2);
  for (;; ++uc_ptr1, ++uc_ptr2) {
    // Widen to int type so that we can compute difference easily.
    const int c1 = *uc_ptr1;
    const int c2 = *uc_ptr2;
    if (c1 == '\0' && c2 == '\0') return 0;
    if (c1 != c2) return c1 - c2;
  }
}

int strncmp(const char* str1, const char* str2, size_t n) {
  // Comparison is done using unsigned character.
  const unsigned char* uc_ptr1 = reinterpret_cast<const unsigned char*>(str1);
  const unsigned char* uc_ptr2 = reinterpret_cast<const unsigned char*>(str2);
  for (size_t i = 0; i < n; ++i) {
    // Widen to int type so that we can compute difference easily.
    const int c1 = uc_ptr1[i];
    const int c2 = uc_ptr2[i];
    if (c1 == '\0' && c2 == '\0') return 0;
    if (c1 != c2) return c1 - c2;
  }
  return 0;
}

// TODO(ksteuck): [as-needed] Provide memmove() if necessary.
// static void* no_memmove(void* dest, const void* src, size_t n) {
//   return nullptr;
// }

// This works almost like getauxval() in libc except it does not set errno
// if no value of the given type is found. errno is not supported.
uint64_t getauxval(uint64_t type) {
  // Find the first entry of 'type' and return its value.
  for (const Elf64_auxv_t* ptr = aux_vector; ptr->a_type != AT_NULL; ++ptr) {
    if (ptr->a_type != AT_IGNORE && ptr->a_type == type) {
      return ptr->a_un.a_val;
    }
  }
  return 0;
}

int getpagesize() {
  int page_size = getauxval(AT_PAGESZ);
  if (page_size == 0) {
    LOG_FATAL("Cannot find page size");
  }
  return page_size;
}

extern "C" char* getenv(const char* name) {
  char** ptr = envp;
  size_t len = strlen(name);
  while (*ptr != nullptr) {
    char* c = *ptr;
    if (strncmp(c, name, len) == 0) {
      c += len;
      if (*c == '=') return ++c;
    }
    ++ptr;
  }
  return nullptr;
}

// Dummies for stderr, fprintf and vfprintf which are used in assert(). Without
// these debug build fails.
FILE* stderr;

int fprintf(FILE* stream, const char* format, ...) {
  LOG_FATAL("fprintf() not implemented, format = \"", format,
            "\". This is probably called by assert()");
}

int vfprintf(FILE* stream, const char* format, va_list ap) {
  LOG_FATAL("vfprintf() not implemented, format = \"", format,
            "\". This is probably called by assert()");
}

#endif  // def SILIFUZZ_BUILD_FOR_NOLIBC
