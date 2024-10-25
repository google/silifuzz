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

#include <elf.h>
#include <errno.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "./util/checks.h"
#include "./util/nolibc_gunit.h"

// ========================================================================= //

extern "C" {
void _start();  // Refereneced by getauxval() test.
char* getenv(char const*);
};

namespace silifuzz {
namespace {

TEST(Nolibc, errno) { CHECK_EQ(&errno, __errno_location()); }

TEST(Nolibc, getenv) {
  CHECK_NE(::getenv("TEST_TMPDIR"), nullptr);
  LOG_INFO("$TEST_TMPDIR = ", ::getenv("TEST_TMPDIR"));
}

TEST(Nolibc, getauxval) {
  // Check that some of the aux vector values are sane.
  CHECK_EQ(getauxval(AT_EGID), getegid());
  CHECK_EQ(getauxval(AT_ENTRY), reinterpret_cast<uintptr_t>(&_start));
  CHECK_EQ(getauxval(AT_EUID), geteuid());
  CHECK_EQ(getauxval(AT_IGNORE), 0);
  CHECK_NE(getauxval(AT_PAGESZ), 0);
  CHECK_EQ(getauxval(AT_NOTELF), 0);
  CHECK_EQ(getauxval(AT_NULL), 0);
  CHECK_NE(getauxval(AT_PHDR), 0);
  CHECK_EQ(getauxval(AT_PHENT), sizeof(Elf64_Phdr));
  CHECK_NE(getauxval(AT_PHNUM), 0);
}

TEST(Nolibc, getpagesize) {
  const int page_size = getpagesize();

  // It must be a power of 2
  CHECK_EQ(page_size & (page_size - 1), 0);

  // To check that getpagesize() returns the correct value without
  // hard-coding the expected result, we use mmap() and mprotect().

  // Frist, checks that mmap() returns an address aligned to this size.
  char* address =
      reinterpret_cast<char*>(mmap(nullptr, page_size, PROT_READ | PROT_WRITE,
                                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
  CHECK_NE(address, MAP_FAILED);
  CHECK_EQ(reinterpret_cast<uintptr_t>(address) % page_size, 0);

  // Then check that it is the minimum power of 2 that mprotect() accepts.
  // First check that mprotect() allows this size.
  CHECK_EQ(mprotect(address, page_size, PROT_READ), 0);

  // Finally check that mprotect() disallows the next smaller power of 2.
  CHECK_NE(mprotect(address + page_size / 2, page_size / 2, PROT_WRITE), 0);
}

TEST(Nolibc, memcmp) {
  unsigned char c1 = 0x7f;
  unsigned char c2 = 0x81;  // negative if interpreted as signed char.
  // C standards require memcmp to do pairwise comparisons of unsigned chars.
  CHECK_LT(memcmp(&c1, &c2, 1), 0);
}

TEST(Nolibc, strcmp) {
  CHECK_EQ(strcmp("", ""), 0);

  const char* kStr1 = "hello";
  CHECK_EQ(strcmp(kStr1, kStr1), 0);
  CHECK_GT(strcmp(kStr1, ""), 0);
  CHECK_LT(strcmp("", kStr1), 0);

  const char* kStr2 = "world";
  CHECK_LT(strcmp(kStr1, kStr2), 0);
  CHECK_GT(strcmp(kStr2, kStr1), 0);

  // C standards require strcmp to do pairwise comparisons of unsigned chars.
  char kStr3[] = {0x7f, '\0'};
  char kStr4[] = {0x81,
                  '\0'};  // 0x81 is negative if interpreted as signed char.
  CHECK_LT(strcmp(kStr3, kStr4), 0);
}

TEST(Nolibc, strncmp) {
  // Check comparing 0 character.
  CHECK_EQ(strncmp("", "", 1), 0);
  CHECK_EQ(strncmp("a", "b", 0), 0);

  const char kStr1[] = "hello";
  const size_t kStr1Length = sizeof(kStr1) - 1;
  CHECK_EQ(strncmp(kStr1, kStr1, kStr1Length), 0);
  CHECK_GT(strncmp(kStr1, "", kStr1Length), 0);
  CHECK_LT(strncmp("", kStr1, kStr1Length), 0);

  const char kStr2[] = "world";
  const size_t kStr2Length = sizeof(kStr2) - 1;
  const size_t kCommonLength = std::min(kStr1Length, kStr2Length);
  CHECK_LT(strncmp(kStr1, kStr2, kCommonLength), 0);
  CHECK_GT(strncmp(kStr2, kStr1, kCommonLength), 0);

  const char kStr3[] = "hello world";  // kStr1 with a suffix.
  CHECK_EQ(strncmp(kStr1, kStr3, kStr1Length), 0);
  CHECK_EQ(strncmp(kStr3, kStr1, kStr1Length), 0);

  // C standards require strcmp to do pairwise comparisons of unsigned chars.
  char kStr4[] = {0x7f, '\0'};
  char kStr5[] = {0x81,
                  '\0'};  // 0x81 is negative if interpreted as signed char.
  CHECK_LT(strncmp(kStr4, kStr5, 1), 0);
}

}  // namespace
}  // namespace silifuzz

// ========================================================================= //

NOLIBC_TEST_MAIN({
  RUN_TEST(Nolibc, getenv);
  RUN_TEST(Nolibc, errno);
  RUN_TEST(Nolibc, getpagesize);
  RUN_TEST(Nolibc, getauxval);
  RUN_TEST(Nolibc, memcmp);
  RUN_TEST(Nolibc, strcmp);
  RUN_TEST(Nolibc, strncmp);
})
