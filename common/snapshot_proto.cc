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

#include "./common/snapshot_proto.h"

#include <cstdint>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "./common/snapshot.h"
#include "./proto/snapshot.pb.h"
#include "./util/checks.h"
#include "./util/misc_util.h"
#include "./util/platform.h"
#include "./util/proto_util.h"

namespace silifuzz {

// Make sure that architecture enum values match.
static_assert(ToInt(Snapshot::Architecture::kUnsupported) ==
              ToInt(proto::Snapshot::UNDEFINED_ARCH));
static_assert(ToInt(Snapshot::Architecture::kX86_64) ==
              ToInt(proto::Snapshot::X86_64));
static_assert(ToInt(Snapshot::Architecture::kAArch64) ==
              ToInt(proto::Snapshot::AARCH64));

// Make sure that permission bit values match.
static_assert(ToInt(MemoryPerms::kReadable) ==
              ToInt(proto::MemoryMapping::READABLE));
static_assert(ToInt(MemoryPerms::kWritable) ==
              ToInt(proto::MemoryMapping::WRITABLE));
static_assert(ToInt(MemoryPerms::kExecutable) ==
              ToInt(proto::MemoryMapping::EXECUTABLE));

// Make sure that Endpoint::SigNum values match.
static_assert(ToInt(Snapshot::Endpoint::kSigSegv) ==
              ToInt(proto::Endpoint::SIG_SEGV));
static_assert(ToInt(Snapshot::Endpoint::kSigTrap) ==
              ToInt(proto::Endpoint::SIG_TRAP));
static_assert(ToInt(Snapshot::Endpoint::kSigFPE) ==
              ToInt(proto::Endpoint::SIG_FPE));
static_assert(ToInt(Snapshot::Endpoint::kSigIll) ==
              ToInt(proto::Endpoint::SIG_ILL));
static_assert(ToInt(Snapshot::Endpoint::kSigBus) ==
              ToInt(proto::Endpoint::SIG_BUS));

// Make sure that Endpoint::SigCause values match.
static_assert(ToInt(Snapshot::Endpoint::kGenericSigCause) ==
              ToInt(proto::Endpoint::GENERIC_SIG_CAUSE));
static_assert(ToInt(Snapshot::Endpoint::kSegvCantExec) ==
              ToInt(proto::Endpoint::SEGV_CANT_EXEC));
static_assert(ToInt(Snapshot::Endpoint::kSegvCantWrite) ==
              ToInt(proto::Endpoint::SEGV_CANT_WRITE));
static_assert(ToInt(Snapshot::Endpoint::kSegvCantRead) ==
              ToInt(proto::Endpoint::SEGV_CANT_READ));
static_assert(ToInt(Snapshot::Endpoint::kSegvOverflow) ==
              ToInt(proto::Endpoint::SEGV_OVERFLOW));
static_assert(ToInt(Snapshot::Endpoint::kSegvGeneralProtection) ==
              ToInt(proto::Endpoint::SEGV_GENERAL_PROTECTION));

// Make sure that PlatformId values match.
static_assert(ToInt(PlatformId::kUndefined) ==
              ToInt(proto::PlatformId::UNDEFINED_PLATFORM_ID));
static_assert(ToInt(PlatformId::kIntelSkylake) ==
              ToInt(proto::PlatformId::INTEL_SKYLAKE));
static_assert(ToInt(PlatformId::kIntelHaswell) ==
              ToInt(proto::PlatformId::INTEL_HASWELL));
static_assert(ToInt(PlatformId::kIntelBroadwell) ==
              ToInt(proto::PlatformId::INTEL_BROADWELL));
static_assert(ToInt(PlatformId::kIntelIvybridge) ==
              ToInt(proto::PlatformId::INTEL_IVYBRIDGE));
static_assert(ToInt(PlatformId::kIntelCascadelake) ==
              ToInt(proto::PlatformId::INTEL_CASCADELAKE));
static_assert(ToInt(PlatformId::kAmdRome) ==
              ToInt(proto::PlatformId::AMD_ROME));
static_assert(ToInt(PlatformId::kIntelIcelake) ==
              ToInt(proto::PlatformId::INTEL_ICELAKE));
static_assert(ToInt(PlatformId::kAmdMilan) ==
              ToInt(proto::PlatformId::AMD_MILAN));
static_assert(ToInt(PlatformId::kIntelSapphireRapids) ==
              ToInt(proto::PlatformId::INTEL_SAPPHIRERAPIDS));
static_assert(ToInt(PlatformId::kAmdGenoa) ==
              ToInt(proto::PlatformId::AMD_GENOA));
static_assert(ToInt(PlatformId::kIntelCoffeelake) ==
              ToInt(proto::PlatformId::INTEL_COFFEELAKE));
static_assert(ToInt(PlatformId::kIntelAlderlake) ==
              ToInt(proto::PlatformId::INTEL_ALDERLAKE));
static_assert(ToInt(PlatformId::kArmNeoverseN1) ==
              ToInt(proto::PlatformId::ARM_NEOVERSE_N1));

// ========================================================================= //

// static
absl::StatusOr<Snapshot::MemoryMapping> SnapshotProto::FromProto(
    const proto::MemoryMapping& proto) {
  PROTO_MUST_HAVE_FIELD(proto, start_address);
  PROTO_MUST_HAVE_FIELD(proto, num_bytes);
  PROTO_MUST_HAVE_FIELD(proto, permissions);
  RETURN_IF_NOT_OK(
      MemoryMapping::CanMakeSized(proto.start_address(), proto.num_bytes()));
  static constexpr int32_t known_bits = proto::MemoryMapping::READABLE |
                                        proto::MemoryMapping::WRITABLE |
                                        proto::MemoryMapping::EXECUTABLE;
  if ((proto.permissions() & ~known_bits) != 0) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Unknown permissions bits: ", absl::Hex(proto.permissions())));
  }

  MemoryPerms perms;
  // static_assert()-s at the top of the file verify that bits used match:
  perms.set_permission_bits(proto.permissions());
  return MemoryMapping::MakeSized(proto.start_address(), proto.num_bytes(),
                                  perms);
}

// static
absl::StatusOr<Snapshot::MemoryBytes> SnapshotProto::FromProto(
    const proto::MemoryBytes& proto) {
  PROTO_MUST_HAVE_FIELD(proto, start_address);
  PROTO_MUST_HAVE_FIELD(proto, byte_values);
  RETURN_IF_NOT_OK(
      MemoryBytes::CanConstruct(proto.start_address(), proto.byte_values()));
  return MemoryBytes(proto.start_address(), proto.byte_values());
}

// static
absl::StatusOr<Snapshot::RegisterState> SnapshotProto::FromProto(
    const proto::RegisterState& proto) {
  PROTO_MUST_HAVE_FIELD(proto, gregs);
  PROTO_MUST_HAVE_FIELD(proto, fpregs);
  return RegisterState(proto.gregs(), proto.fpregs());
}

// static
absl::StatusOr<Snapshot::Endpoint> SnapshotProto::FromProto(
    const proto::Endpoint& proto) {
  switch (proto.event_case()) {
    case proto::Endpoint::kInstructionAddress:
      return Endpoint(proto.instruction_address());
    case proto::Endpoint::kSignal: {
      const auto& p = proto.signal();
      PROTO_MUST_HAVE_FIELD(p, sig_num);
      PROTO_MUST_HAVE_FIELD(p, sig_cause);
      PROTO_MUST_HAVE_FIELD(p, sig_address);
      PROTO_MUST_HAVE_FIELD(p, sig_instruction_address);
      if (p.sig_num() == proto::Endpoint::UNDEFINED_SIG_NUM) {
        return absl::InvalidArgumentError("Undefined sig_num");
      }
      if (p.sig_cause() == proto::Endpoint::UNDEFINED_SIG_CAUSE) {
        return absl::InvalidArgumentError("Undefined sig_cause");
      }
      if ((p.sig_cause() != proto::Endpoint::GENERIC_SIG_CAUSE) !=
          (p.sig_num() == proto::Endpoint::SIG_SEGV)) {
        return absl::InvalidArgumentError(
            absl::StrCat("sig_cause ", p.sig_cause(),
                         " is incompatible with sig_num ", p.sig_num()));
      }
      return Endpoint(static_cast<Endpoint::SigNum>(p.sig_num()),
                      static_cast<Endpoint::SigCause>(p.sig_cause()),
                      p.sig_address(), p.sig_instruction_address());
    }
    default:
      return absl::InvalidArgumentError("no known Endpoint case");
  }
}

// static
absl::StatusOr<Snapshot::EndState> SnapshotProto::FromProto(
    const proto::EndState& proto) {
  PROTO_MUST_HAVE_FIELD(proto, endpoint);
  PROTO_MUST_HAVE_FIELD(proto, registers);
  auto e = FromProto(proto.endpoint());
  RETURN_IF_NOT_OK_PLUS(e.status(), "Bad Endpoint: ");
  auto r = FromProto(proto.registers());
  RETURN_IF_NOT_OK_PLUS(r.status(), "Bad RegisterState: ");
  EndState snap(e.value(), r.value());
  for (const proto::MemoryBytes& p : proto.memory_bytes()) {
    auto b = FromProto(p);
    RETURN_IF_NOT_OK_PLUS(b.status(), "Bad MemoryBytes: ");
    RETURN_IF_NOT_OK_PLUS(snap.can_add_memory_bytes(b.value()),
                          "Can't add MemoryBytes: ");
    snap.add_memory_bytes(std::move(b).value());
  }
  if (proto.has_platforms()) {
    static_assert(ToInt(kMaxPlatformId) < 64);
    for (int p = ToInt(PlatformId::kUndefined); p <= ToInt(kMaxPlatformId);
         ++p) {
      if (proto.platforms() & (1 << p)) {
        snap.add_platform(static_cast<PlatformId>(p));
      }
    }
  }
  return snap;
}

// static
absl::StatusOr<Snapshot> SnapshotProto::FromProto(
    const proto::Snapshot& proto) {
  PROTO_MUST_HAVE_FIELD(proto, architecture);
  PROTO_MUST_HAVE_FIELD(proto, registers);
  const Id& id = proto.has_id() ? proto.id() : Snapshot::UnsetId();
  RETURN_IF_NOT_OK(Snapshot::IsValidId(id));
  if (proto.architecture() == proto::Snapshot::UNDEFINED_ARCH) {
    return absl::InvalidArgumentError("Undefined architecture");
  }
  Snapshot snap(static_cast<Architecture>(proto.architecture()), id);

  for (const proto::MemoryMapping& p : proto.memory_mappings()) {
    auto s = FromProto(p);
    RETURN_IF_NOT_OK_PLUS(s.status(), "Bad MemoryMapping: ");
    RETURN_IF_NOT_OK_PLUS(snap.can_add_memory_mapping(s.value()),
                          "Can't add MemoryMapping: ");
    snap.add_memory_mapping(s.value());
  }
  for (const proto::MemoryMapping& p : proto.negative_memory_mappings()) {
    auto s = FromProto(p);
    RETURN_IF_NOT_OK_PLUS(s.status(), "Bad negative MemoryMapping: ");
    RETURN_IF_NOT_OK_PLUS(snap.can_add_negative_memory_mapping(s.value()),
                          "Can't add negative MemoryMapping: ");
    snap.add_negative_memory_mapping(s.value());
  }
  for (const proto::MemoryBytes& p : proto.memory_bytes()) {
    auto s = FromProto(p);
    RETURN_IF_NOT_OK_PLUS(s.status(), "Bad MemoryBytes: ");
    RETURN_IF_NOT_OK_PLUS(snap.can_add_memory_bytes(s.value()),
                          "Can't add MemoryBytes: ");
    snap.add_memory_bytes(std::move(s).value());
  }
  {
    auto s = FromProto(proto.registers());
    RETURN_IF_NOT_OK_PLUS(s.status(), "Bad RegisterState: ");
    RETURN_IF_NOT_OK_PLUS(snap.can_set_registers(s.value()),
                          "Can't set RegisterState: ");
    snap.set_registers(s.value());
  }
  for (const proto::EndState& p : proto.expected_end_states()) {
    auto s = FromProto(p);
    RETURN_IF_NOT_OK_PLUS(s.status(), "Bad EndState: ");
    RETURN_IF_NOT_OK_PLUS(snap.can_add_expected_end_state(s.value()),
                          "Can't add EndState: ");
    snap.add_expected_end_state(s.value());
  }

  if (proto.has_metadata()) {
    snap.set_metadata(Metadata(proto.metadata()));
  }

  RETURN_IF_NOT_OK_PLUS(snap.IsCompleteSomeState(), "Snapshot is incomplete: ");
  return snap;
}

// static
absl::Status SnapshotProto::IsValid(const proto::Snapshot& proto) {
  return FromProto(proto).status();
}

// ========================================================================= //

// static
void SnapshotProto::ToProto(const MemoryMapping& snap,
                            proto::MemoryMapping* proto) {
  proto->set_start_address(snap.start_address());
  proto->set_num_bytes(snap.num_bytes());
  // static_assert()-s at the top of the file verify that bits used match:
  proto->set_permissions(snap.perms().permission_bits());
}

// static
void SnapshotProto::ToProto(const MemoryBytes& snap,
                            proto::MemoryBytes* proto) {
  proto->set_start_address(snap.start_address());
  proto->set_byte_values(snap.byte_values());
}

// static
void SnapshotProto::ToProto(const RegisterState& snap,
                            proto::RegisterState* proto) {
  proto->set_gregs(snap.gregs());
  proto->set_fpregs(snap.fpregs());
}

// static
void SnapshotProto::ToProto(const Endpoint& snap, proto::Endpoint* proto) {
  switch (snap.type()) {
    case Endpoint::kInstruction:
      proto->set_instruction_address(snap.instruction_address());
      break;
    case Endpoint::kSignal:
      auto p = proto->mutable_signal();
      p->set_sig_num(static_cast<proto::Endpoint::SigNum>(snap.sig_num()));
      p->set_sig_cause(
          static_cast<proto::Endpoint::SigCause>(snap.sig_cause()));
      p->set_sig_address(snap.sig_address());
      p->set_sig_instruction_address(snap.sig_instruction_address());
      break;
  }
}

// static
void SnapshotProto::ToProto(const EndState& snap, proto::EndState* proto) {
  ToProto(snap.endpoint(), proto->mutable_endpoint());
  ToProto(snap.registers(), proto->mutable_registers());
  for (const MemoryBytes& s : snap.memory_bytes()) {
    ToProto(s, proto->add_memory_bytes());
  }
  if (!snap.empty_platforms()) {
    static_assert(ToInt(kMaxPlatformId) < 64);
    int64_t platforms = 0;
    for (int p = ToInt(PlatformId::kUndefined); p <= ToInt(kMaxPlatformId);
         ++p) {
      if (snap.has_platform(static_cast<PlatformId>(p))) {
        platforms |= (1 << p);
      }
    }
    proto->set_platforms(platforms);
  }
}

// static
void SnapshotProto::ToProto(const Snapshot& snap, proto::Snapshot* proto) {
  DCHECK_STATUS(snap.IsCompleteSomeState());
  proto->Clear();
  proto->set_architecture(
      static_cast<proto::Snapshot::Architecture>(snap.architecture()));
  proto->set_id(snap.id());
  for (const MemoryMapping& s : snap.memory_mappings()) {
    ToProto(s, proto->add_memory_mappings());
  }
  for (const MemoryMapping& s : snap.negative_memory_mappings()) {
    ToProto(s, proto->add_negative_memory_mappings());
  }
  for (const MemoryBytes& s : snap.memory_bytes()) {
    ToProto(s, proto->add_memory_bytes());
  }
  ToProto(snap.registers(), proto->mutable_registers());
  for (const EndState& s : snap.expected_end_states()) {
    ToProto(s, proto->add_expected_end_states());
  }
  if (!snap.metadata().empty()) {
    *proto->mutable_metadata() = snap.metadata().value_;
  }
}

}  // namespace silifuzz
