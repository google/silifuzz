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

// Helper for start_test.sh
// This returns the last argument as an unsigned value to start_test.sh.
#include <cstdint>

// Convert string *s into an unsigned decimal integer.
uint32_t atou32(const char* s) {
  uint32_t u = 0;
  for (; *s >= '0' && *s <= '9'; ++s) {
    u = u * 10 + (*s - '0');
  }
  return u;
}

int main(int argc, char* argv[]) {
#ifdef __x86_64__
  // Check that frame pointer is 16-byte aligned on x86_64.
  // The stack pointer before main() is called should be 16-byte aligned.
  // The frame pointer should have the value of old stack pointer + 16 here.
  const uintptr_t frame_ptr =
      reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
  if (frame_ptr % 16 != 0) {
    return 1;
  }
#endif

  // Just use the last command line argument as exit code.
  return argc > 1 ? atou32(argv[argc - 1]) : 0;
}
