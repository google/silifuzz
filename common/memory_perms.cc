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

#include "./common/memory_perms.h"

#include <sys/mman.h>

#include <string>

#include "absl/strings/string_view.h"
#include "./util/checks.h"

namespace silifuzz {

void MemoryPerms::Join(MemoryPerms y, JoinMode mode) {
  switch (mode) {
    case kOr:
      Add(y);
      break;
    case kAnd:
      Intersect(y);
      break;
  }
}

bool MemoryPerms::Has(Permission p) const {
  return (permission_bits_ & ToInt(p)) != 0;
}

bool MemoryPerms::Has(MemoryPerms y) const {
  return (permission_bits_ & y.permission_bits_) == y.permission_bits_;
}

bool MemoryPerms::HasSomeOf(MemoryPerms y) const {
  return (permission_bits_ & y.permission_bits_) != 0;
}

// static
MemoryPerms MemoryPerms::FromMProtect(int mprotect_prot) {
  MemoryPerms r;
  if (mprotect_prot & PROT_READ) r.permission_bits_ |= ToInt(kReadable);
  if (mprotect_prot & PROT_WRITE) r.permission_bits_ |= ToInt(kWritable);
  if (mprotect_prot & PROT_EXEC) r.permission_bits_ |= ToInt(kExecutable);
  return r;
}

int MemoryPerms::ToMProtect() const {
  int r = 0;
  if (Has(kReadable)) r |= PROT_READ;
  if (Has(kWritable)) r |= PROT_WRITE;
  if (Has(kExecutable)) r |= PROT_EXEC;
  return r;
}

// static
MemoryPerms MemoryPerms::FromProcMaps(absl::string_view perms) {
  DCHECK_EQ(perms.size(), 4);  // Could also check for regex [-r][-w][-x][ps].
  MemoryPerms r;
  if (perms.find('r') != perms.npos) r.permission_bits_ |= ToInt(kReadable);
  if (perms.find('w') != perms.npos) r.permission_bits_ |= ToInt(kWritable);
  if (perms.find('x') != perms.npos) r.permission_bits_ |= ToInt(kExecutable);
  return r;
}

std::string MemoryPerms::ToString() const {
  std::string r("---");
  if (Has(kReadable)) r[0] = 'r';
  if (Has(kWritable)) r[1] = 'w';
  if (Has(kExecutable)) r[2] = 'x';
  return r;
}

std::string MemoryPerms::DebugString() const {
  auto r = ToString();
  r.push_back(Has(kMapped) ? 'm' : '-');
  return r;
}

}  // namespace silifuzz
