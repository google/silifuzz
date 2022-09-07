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

#ifndef THIRD_PARTY_SILIFUZZ_MEMORY_PERMS_H_
#define THIRD_PARTY_SILIFUZZ_MEMORY_PERMS_H_

#include <initializer_list>

#include "absl/strings/string_view.h"
#include "./util/misc_util.h"

namespace silifuzz {

// A simple helper class to represent RWX permissions on a region of process
// memory.
//
// Note that, similarly to boolean operations, there's considerable amount of
// duplication in this interface (i.e. operations that can easily be expressed
// via other operations). This is so that a caller can choose an operation
// that is most readable for their use case.
//
// This class is a thread-compatible value type.
// It's small enough to be passed by value.
class MemoryPerms {
 public:
  // Bits for the possible permissions on memory to be binary-or-ed.
  //
  // Note that bit values here match those in snapshot.proto;
  // snapshot_proto.cc makes sure it's the case - it cares about this.
  enum Permission {
    kReadable = 1,
    kWritable = 2,
    kExecutable = 4,
    // Special bit for MappedMemoryMap (see ./mapped_memory_map.h) to
    // explicitly represent if given memory is mapped into a process.
    kMapped = 8,
  };

  // ----------------------------------------------------------------------- //
  // C-tors, factories.

  // Same as None().
  MemoryPerms() : permission_bits_(0) {}

  // Consists of all `perms`.
  explicit MemoryPerms(std::initializer_list<Permission> perms);

  ~MemoryPerms() = default;

  // No permission bits.
  static constexpr MemoryPerms None() { return MemoryPerms(0); }

  // All permission bits except for kMapped.
  static constexpr MemoryPerms All();

  // All permission bits including kMapped.
  static constexpr MemoryPerms AllPlusMapped();

  // Various commonly-used permission combinations.
  static constexpr MemoryPerms R() { return MemoryPerms(kReadable); }
  static constexpr MemoryPerms W() { return MemoryPerms(kWritable); }
  static constexpr MemoryPerms X() { return MemoryPerms(kExecutable); }
  static constexpr MemoryPerms RW();
  static constexpr MemoryPerms XR();
  static constexpr MemoryPerms XW();
  static constexpr MemoryPerms RWX();

  // Intentionally movable and copyable.

  // ----------------------------------------------------------------------- //
  // Mutators.

  // Removes all permission.
  void Clear() { *this = None(); }

  // Adds (i.e. or-s) a given permission to *this.
  void Add(Permission p) { permission_bits_ |= ToInt(p); }

  // Adds (i.e. or-s) *this with the permissions from `y`.
  void Add(MemoryPerms y) { permission_bits_ |= y.permission_bits_; }

  // Returns *this after Add(p), Add(y) resp.
  MemoryPerms Plus(Permission p) const { return Plus(MemoryPerms({p})); }
  MemoryPerms Plus(MemoryPerms y) const;

  // Intersects (i.e. and-s) *this with the permissions from `y`.
  void Intersect(MemoryPerms y) { permission_bits_ &= y.permission_bits_; }

  // Or-s or and-s *this with the permissions from `y` depending on `mode`.
  enum JoinMode { kOr, kAnd };
  void Join(MemoryPerms y, JoinMode mode);

  // Removes a given permission.
  void Clear(Permission p) { permission_bits_ &= ~ToInt(p); }

  // Removes the permissions of `y` from *this,
  void Clear(MemoryPerms y) { permission_bits_ &= ~y.permission_bits_; }

  // ----------------------------------------------------------------------- //
  // Accessors/querying.

  bool operator==(MemoryPerms y) const {
    return permission_bits_ == y.permission_bits_;
  }
  bool operator!=(MemoryPerms y) const { return !(*this == y); }

  // Returns true iff no permissions are set.
  bool IsEmpty() const { return permission_bits_ == 0; }

  // Tells if a given permission is set.
  bool Has(Permission p) const;
  bool HasNo(Permission p) const { return !Has(p); }

  // Tells if all permission from `y` are set.
  bool Has(MemoryPerms y) const;
  bool HasAllOf(MemoryPerms y) const { return Has(y); }

  // Tells if some permission from `y` are set.
  bool HasSomeOf(MemoryPerms y) const;

  // Tells if no permission from `y` are set.
  bool HasNoneOf(MemoryPerms y) const { return !HasSomeOf(y); }

  // ----------------------------------------------------------------------- //
  // Convertors.

  // Set *this from mprotect_prot - it's interpreted as the `prot` arg
  // for mprotect().
  static MemoryPerms FromMProtect(int mprotect_prot);

  // Return *this mapped to the format of `prot` arg for mprotect().
  // kMapped bit is ignored.
  int ToMProtect() const;

  // Set *this from a string from /proc/.../maps: e.g. "rw-p".
  // Never sets kMapped bit.
  static MemoryPerms FromProcMaps(absl::string_view perms);

  // Return *this mapped to [r-][w-][x-] string.
  // I.e. kMapped bit is ignored.
  std::string ToString() const;

  // For logging (does include the kMapped bit).
  std::string DebugString() const;

 private:
  friend class SnapshotProto;

  // Low-level interfaces on permissions as binary-or of the
  // `Permission` enum bit values.
  int permission_bits() const { return permission_bits_; }
  void set_permission_bits(int bits) { permission_bits_ = bits; }

 private:
  constexpr explicit MemoryPerms(int bits) : permission_bits_(bits) {}

  // The permissions: binary-or of Permission enum bit values.
  int permission_bits_;
};

// ========================================================================= //
// Inline impls for MemoryPerms follow.

inline MemoryPerms::MemoryPerms(std::initializer_list<Permission> perms)
    : MemoryPerms() {
  for (const auto p : perms) {
    Add(p);
  }
}

// static
inline constexpr MemoryPerms MemoryPerms::All() {
  return MemoryPerms(kReadable | kWritable | kExecutable);
}

// static
inline constexpr MemoryPerms MemoryPerms::AllPlusMapped() {
  return MemoryPerms(kReadable | kWritable | kExecutable | kMapped);
}

// static
inline constexpr MemoryPerms MemoryPerms::RW() {
  return MemoryPerms(kReadable | kWritable);
}

// static
inline constexpr MemoryPerms MemoryPerms::XR() {
  return MemoryPerms(kReadable | kExecutable);
}

// static
inline constexpr MemoryPerms MemoryPerms::XW() {
  return MemoryPerms(kWritable | kExecutable);
}

// static
inline constexpr MemoryPerms MemoryPerms::RWX() {
  return MemoryPerms(kReadable | kWritable | kExecutable);
}

inline MemoryPerms MemoryPerms::Plus(MemoryPerms y) const {
  MemoryPerms r = *this;
  r.Add(y);
  return r;
}

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_MEMORY_PERMS_H_
