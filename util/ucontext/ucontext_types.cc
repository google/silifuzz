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

#include "./util/ucontext/ucontext_types.h"

#include "./util/checks.h"
#include "./util/misc_util.h"

namespace silifuzz {

// Verify that alignas(16) is respected (it matters -- see class definition in
// ucontext_types.h).
// Use std::aligned_storage<> to fix if this check fails.
template <typename Arch>
UContext<Arch>::UContext() {
  DCHECK_EQ(AsInt(this) % alignof(UContext<Arch>), 0);
}

template UContext<X86_64>::UContext();
template UContext<AArch64>::UContext();

}  // namespace silifuzz
