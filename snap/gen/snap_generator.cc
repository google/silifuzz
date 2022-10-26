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

#include "./snap/gen/snap_generator.h"

#include <string.h>
#include <sys/types.h>

#include <cstddef>
#include <optional>
#include <type_traits>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "./common/mapped_memory_map.h"
#include "./common/memory_perms.h"
#include "./common/memory_state.h"
#include "./common/snapshot.h"
#include "./snap/exit_sequence.h"
#include "./snap/gen/repeating_byte_runs.h"
#include "./snap/gen/reserved_memory_mappings.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/platform.h"
#include "./util/ucontext/serialize.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

namespace {

// Returns 'address' as in C++ source code.
std::string AddressString(Snapshot::Address address) {
  return absl::StrFormat("0x%llxULL", address);
}

// Returns 'value' as a uint8_t literal in C++ source code.
std::string UInt8String(uint8_t value) {
  return absl::StrFormat("0x%xU", value);
}

// Returns 'value' as a uint16_t literal in C++ source code.
std::string UInt16String(uint16_t value) {
  return absl::StrFormat("0x%xU", value);
}

// Returns 'value' as a uint32_t literal in C++ source code.
std::string UInt32String(uint32_t value) {
  return absl::StrFormat("0x%xU", value);
}

// Returns 'value' as a uint64_t literal in C++ source code.
std::string UInt64String(uint64_t value) {
  return absl::StrFormat("0x%llxULL", value);
}

std::string UInt128String(__uint128_t value) {
  // There's no such thing as an 128-bit literal, so we need to synthesize it
  // out of two 64-bit literals.
  uint64_t upper = value >> 64;
  uint64_t lower = value;
  if (upper) {
    return absl::StrFormat("(((__uint128_t)0x%llxULL) << 64 | 0x%llxULL)",
                           upper, lower);
  } else {
    return UInt64String(lower);
  }
}

//  Returns string containing C++ code for initilizer of an Snap::Array of given
//  'size' and  whose elements are stored out-of-line in variable
//  'elements_var'.
std::string ArrayString(size_t size, absl::string_view elements_var) {
  return absl::StrFormat("{ .size = %zdULL, .elements = %s }", size,
                         elements_var);
}

// Picks an expected end state compatible with the given options.
absl::StatusOr<const Snapshot::EndState *> PickEndState(
    const Snapshot &snapshot, const SnapGenerator::Options &options) {
  if (options.allow_undefined_end_state) {
    if (snapshot.expected_end_states().size() != 1) {
      return absl::InvalidArgumentError(
          absl::StrCat("want exactly 1 endstate, found ",
                       snapshot.expected_end_states().size()));
    }
    RETURN_IF_NOT_OK(snapshot.IsCompleteSomeState());
    return &snapshot.expected_end_states()[0];
  } else {
    // Must have an expected end state for the requested platform.
    for (const auto &es : snapshot.expected_end_states()) {
      if (es.has_platform(options.platform_id) ||
          options.platform_id == PlatformId::kAny) {
        RETURN_IF_NOT_OK(es.IsComplete());
        return &es;
      }
    }
    return absl::InvalidArgumentError(absl::StrCat(
        "no expected end state for platform ", EnumStr(options.platform_id)));
  }
}

absl::Status CanConvert(const Snapshot &snapshot,
                        const SnapGenerator::Options &opts) {
  absl::StatusOr<const Snapshot::EndState *> end_state_or =
      PickEndState(snapshot, opts);
  RETURN_IF_NOT_OK(end_state_or.status());
  const Snapshot::EndState &end_state = *end_state_or.value();
  // Must end at an instruction, not a signal.
  const Snapshot::Endpoint &endpoint = end_state.endpoint();
  if (endpoint.type() != Snapshot::Endpoint::kInstruction) {
    return absl::InvalidArgumentError("endpoint isn't kInstruction");
  }

  if (OverlapReservedMemoryMappings(snapshot.memory_mappings())) {
    return absl::InvalidArgumentError(
        "memory mappings overlap reserved memory mappings");
  }

  // There should be code space to append an exit sequence.
  const MappedMemoryMap &mapped_memory_map = snapshot.mapped_memory_map();
  const Snapshot::Address ending_rip = endpoint.instruction_address();
  if (!mapped_memory_map.Contains(ending_rip,
                                  ending_rip + kSnapExitSequenceSize)) {
    return absl::InvalidArgumentError(
        "CanConvert: no room for the exit sequence");
  }

  // Skip the rest of checks if this is an undefined state. We don't know the
  // expected values of the registers so inspecting RSP is not possible.
  if (opts.allow_undefined_end_state &&
      end_state.IsComplete(Snapshot::kUndefinedEndState).ok()) {
    return absl::OkStatus();
  }

  // We need 8 bytes of stack to exit (the return address pushed by call)
  // Check that [rsp-8, rsp) is mapped. Also check that RSP=0 is handled.
  Snapshot::Address ending_rsp = snapshot.ExtractRsp(end_state.registers());
  if (ending_rsp < 8 ||
      !mapped_memory_map.Contains(ending_rsp - 8, ending_rsp)) {
    return absl::InvalidArgumentError("need at least 8 bytes on stack");
  }

  return absl::OkStatus();
}

// Helper for Snapify(). This normalizes `memory_byte_list` and then
// breaks list elements into smaller MemoryBytes objects if necessary for
// run-length compression. Optionally apply run-length compression on byte data.
// Returns a status to report any errors.
absl::Status SnapifyMemoryByteList(
    const MappedMemoryMap &memory_map, const SnapGenerator::Options &opts,
    Snapshot::MemoryBytesList *memory_byte_list) {
  // Normalize memory bytes to ensure all bytes in a MemoryBytes have identical
  // permissions
  Snapshot::NormalizeMemoryBytes(memory_map, memory_byte_list);

  // Prepare memory byte list for run-length compression.
  if (opts.compress_repeating_bytes) {
    ASSIGN_OR_RETURN_IF_NOT_OK(Snapshot::MemoryBytesList runs,
                               GetRepeatingByteRuns(*memory_byte_list));
    memory_byte_list->swap(runs);
  }

  return absl::OkStatus();
}

}  // namespace

void SnapGenerator::FileStart() {
  for (const auto &header : system_headers_) {
    PrintLn("#include <", header, ">");
  }
  for (const auto &header : local_headers_) {
    PrintLn("#include \"", header, "\"");
  }
  PrintLn("namespace silifuzz {");
}

void SnapGenerator::FileEnd() { PrintLn("}  // namespace silifuzz"); }

void SnapGenerator::Comment(absl::string_view comment) {
  CHECK(!absl::StrContains(comment, "\n"));
  PrintLn("// ", comment);
}

absl::Status SnapGenerator::GenerateSnap(const VarName &name,
                                         const Snapshot &snapshot,
                                         const Options &opts) {
  const absl::StatusOr<Snapshot> snapified_or = Snapify(snapshot, opts);
  RETURN_IF_NOT_OK(snapified_or.status());
  const Snapshot &snapified = snapified_or.value();
  const Snapshot::EndState &end_state = snapified.expected_end_states()[0];
  const Snapshot::Endpoint &endpoint = end_state.endpoint();
  CHECK(endpoint.type() == Snapshot::Endpoint::kInstruction);

  // Code generation is done bottom-up. First, we generate variable-sized
  // components that cannot be placed inside the fix-sized Snap struct.

  // Generate all out-of-line ByteData.
  const VarNameList memory_byte_values_var_names =
      GenerateMemoryBytesByteData(snapified.memory_bytes(), opts);
  const VarNameList end_state_memory_byte_values_var_names =
      GenerateMemoryBytesByteData(end_state.memory_bytes(), opts);

  // Generate all out-of-line MemoryBytes
  const VarName memory_bytes_var_name = GenerateMemoryBytesList(
      snapified.memory_bytes(), memory_byte_values_var_names,
      snapified.mapped_memory_map(), opts);
  const VarName end_state_memory_bytes_var_name = GenerateMemoryBytesList(
      end_state.memory_bytes(), end_state_memory_byte_values_var_names,
      snapified.mapped_memory_map(), opts);

  // Generate all out-of-line MemoryMappings
  const VarName memory_mappings_var_name =
      GenerateMemoryMappingList(snapified.memory_mappings());

  // Generate code for Snap
  PrintLn("static const Snap ", name, " {");

  PrintLn(".id = \"", snapified.id(), "\",");
  PrintLn(
      ".memory_mappings=",
      ArrayString(snapified.memory_mappings().size(), memory_mappings_var_name),
      ",");
  PrintLn(".memory_bytes=",
          ArrayString(snapified.memory_bytes().size(), memory_bytes_var_name),
          ",");
  Print(".registers = ");
  GenerateRegisters(snapified.registers());
  PrintLn(",");
  PrintLn(".end_state_instruction_address=",
          AddressString(endpoint.instruction_address()), ",");
  Print(".end_state_registers = ");
  GenerateRegisters(end_state.registers());
  PrintLn(",");
  PrintLn(".end_state_memory_bytes=",
          ArrayString(end_state.memory_bytes().size(),
                      end_state_memory_bytes_var_name),
          ",");

  PrintLn("};");
  return absl::OkStatus();
}

void SnapGenerator::GenerateSnapArray(const VarName &name,
                                      const VarNameList &snap_var_name_list) {
  const VarName elements_var_name = absl::StrCat("elements_of_", name);
  Print(absl::StrFormat("static const Snap* const %s[%zd] = {",
                        elements_var_name, snap_var_name_list.size()));
  for (const auto &var_name : snap_var_name_list) {
    Print("&", var_name, ",");
  }
  PrintLn("};");

  PrintLn(
      absl::StrFormat("extern const Snap::Corpus %s = { .size = "
                      "%zd, .elements = %s };",
                      name, snap_var_name_list.size(), elements_var_name));
}

absl::StatusOr<Snapshot> SnapGenerator::Snapify(const Snapshot &snapshot,
                                                const Options &opts) {
  RETURN_IF_NOT_OK(CanConvert(snapshot, opts));
  // Copy Id and Architecture.
  Snapshot snapified(snapshot.architecture(), snapshot.id());
  snapified.set_metadata(snapshot.metadata());

  // Copy memory mappings and optionally force mapping to be writable if
  // requested in options.
  for (const auto &memory_mapping : snapshot.memory_mappings()) {
    RETURN_IF_NOT_OK(Snapshot::MemoryMapping::CanMakeSized(
        memory_mapping.start_address(), memory_mapping.num_bytes()));
    Snapshot::MemoryMapping snapfied_memory_mapping =
        Snapshot::MemoryMapping::MakeSized(memory_mapping.start_address(),
                                           memory_mapping.num_bytes(),
                                           memory_mapping.perms());
    RETURN_IF_NOT_OK(snapified.can_add_memory_mapping(snapfied_memory_mapping));
    snapified.add_memory_mapping(snapfied_memory_mapping);
  }

  // Copy registers. This must be done after setting memory mappings as
  // program counter must point to a valid executable address.
  snapified.set_registers(snapshot.registers());

  // Construct initial memory state of the snapified snaphsot.
  MemoryState memory_state =
      MemoryState::MakeInitial(snapshot, MemoryState::kZeroMappedBytes);

  // Add a snap exit sequence to initial memory bytes at the end point
  // instruction address.
  Snapshot::ByteData snap_exit_byte_data(kSnapExitSequenceSize, 0);
  WriteSnapExitSequence(
      reinterpret_cast<uint8_t *>(snap_exit_byte_data.data()));

  absl::StatusOr<const Snapshot::EndState *> end_state_or =
      PickEndState(snapshot, opts);
  RETURN_IF_NOT_OK(end_state_or.status());
  const Snapshot::EndState &end_state = *end_state_or.value();
  const Snapshot::Endpoint &endpoint = end_state.endpoint();
  RETURN_IF_NOT_OK(Snapshot::MemoryBytes::CanConstruct(
      endpoint.instruction_address(), snap_exit_byte_data));
  Snapshot::MemoryBytes snap_exit_memory_bytes(endpoint.instruction_address(),
                                               snap_exit_byte_data);

  // We need to make sure that this does not overwrite code that a snapshot
  // cares about. In theory, a snapshot can read memory in the region we
  // write the exit sequence so that the snapshot can end differently depending
  // on where the exit sequence is present or not. Right now there is no easy
  // way to detect this. We can run the resultant Snap to filter out these
  // cases.
  //
  // A different but related problem is that some snapshot ends with instruction
  // prefixes, which affect the first instruction of the exit sequence. We tried
  // patching different NOPs in the front of the exit sequence but could not
  // find a NOP instruction variant that is immune to all prefixes. We may look
  // at the byte before the ending instruction address and see if that matches
  // one of the instruction prefixes but doing that may over estimate the
  // issue and filter out more snapshots than necessary.
  if (!memory_state.mapped_memory().Contains(
          snap_exit_memory_bytes.start_address(),
          snap_exit_memory_bytes.limit_address())) {
    return absl::InvalidArgumentError("Snapify: no room for the exit sequence");
  }
  memory_state.SetMemoryBytes(snap_exit_memory_bytes);

  Snapshot::MemoryBytesList initial_memory_bytes_list =
      memory_state.memory_bytes_list(memory_state.written_memory());
  RETURN_IF_NOT_OK(SnapifyMemoryByteList(snapified.mapped_memory_map(), opts,
                                         &initial_memory_bytes_list));
  for (const auto &memory_bytes : initial_memory_bytes_list) {
    RETURN_IF_NOT_OK(snapified.can_add_memory_bytes(memory_bytes));
    snapified.add_memory_bytes(memory_bytes);
  }

  // Add RestoreUContext stack bytes, original end state memory delta, and
  // snap exit stack bytes to construct full end state memory bytes.
  memory_state.SetMemoryBytes(MemoryState::RestoreUContextStackBytes(snapshot));
  memory_state.SetMemoryBytes(end_state.memory_bytes());

  // Additionally check that endpoint is kInstruction because the fixup needs
  // to be applied only for this type of endpoints.
  CHECK(endpoint.type() == Snapshot::Endpoint::kInstruction);
  Snapshot::RegisterState snapified_end_state_regs = end_state.registers();

  // Construct a snapified end state from the original.
  Snapshot::EndState snapified_end_state(endpoint, snapified_end_state_regs);
  snapified_end_state.set_platforms(end_state.platforms());

  if (end_state.IsComplete().ok()) {
    // Apply the memory mappings and the exit sequence fixup only when we have
    // a normal endstate.
    // The snap exit sequence written above consists of a call instruction
    // followed by a 64-bit address. The length of an exit sequence is thus the
    // length of a call instruction plus 8 bytes. When the exit call is
    // executed, it leaves the address after the call instruction on stack.
    constexpr size_t kCallInsnSize = kSnapExitSequenceSize - sizeof(uint64_t);
    Snapshot::Address return_address =
        endpoint.instruction_address() + kCallInsnSize;
    Snapshot::ByteData return_address_byte_data(
        reinterpret_cast<Snapshot::ByteData::value_type *>(&return_address),
        sizeof(return_address));
    // On x86_64, a stack push is done by decrementing the stack point first
    // and then writing to location pointed to by the new stack pointer.
    //
    // before call
    //   RSP-> 20000000: XX XX ....
    //         1ffffff8: XX XX ....
    //
    // after call
    //         20000000: XX XX ....
    //   RSP-> 1ffffff8: <return address>
    //
    const Snapshot::Address end_point_stack_pointer =
        snapshot.ExtractRsp(end_state.registers());
    RETURN_IF_NOT_OK(Snapshot::MemoryBytes::CanConstruct(
        end_point_stack_pointer - sizeof(return_address),
        return_address_byte_data));
    Snapshot::MemoryBytes return_address_memory_bytes(
        end_point_stack_pointer - sizeof(return_address),
        return_address_byte_data);
    memory_state.SetMemoryBytes(return_address_memory_bytes);
    Snapshot::MemoryBytesList end_state_memory_bytes_list =
        memory_state.memory_bytes_list(memory_state.written_memory());
    RETURN_IF_NOT_OK(SnapifyMemoryByteList(snapified.mapped_memory_map(), opts,
                                           &end_state_memory_bytes_list));
    for (const auto &memory_bytes : end_state_memory_bytes_list) {
      // Include only writable memory in the endstate.
      if (snapified.mapped_memory_map()
              .Perms(memory_bytes.start_address(), memory_bytes.limit_address(),
                     MemoryPerms::kOr)
              .Has(MemoryPerms::kWritable)) {
        RETURN_IF_NOT_OK(
            snapified_end_state.can_add_memory_bytes(memory_bytes));
        snapified_end_state.add_memory_bytes(memory_bytes);
      }
    }
  } else {
    // Ensure that an undefined endstate is expected.
    DCHECK(opts.allow_undefined_end_state);
  }
  RETURN_IF_NOT_OK(snapified.can_add_expected_end_state(snapified_end_state));
  snapified.add_expected_end_state(snapified_end_state);

  return snapified;
}

// ========================================================================= //

SnapGenerator::VarName SnapGenerator::LocalVarName(absl::string_view prefix) {
  return absl::StrCat(prefix, "_", local_object_name_counter_++);
}

template <>
void SnapGenerator::GenerateNonZeroValue<uint8_t>(absl::string_view name,
                                                  const uint8_t &value) {
  if (value != 0) {
    Print(".", name, " = ", UInt8String(value), ",");
  }
}

template <>
void SnapGenerator::GenerateNonZeroValue<uint16_t>(absl::string_view name,
                                                   const uint16_t &value) {
  if (value != 0) {
    Print(".", name, " = ", UInt16String(value), ",");
  }
}

template <>
void SnapGenerator::GenerateNonZeroValue(absl::string_view name,
                                         const uint32_t &value) {
  if (value != 0) {
    Print(".", name, " = ", UInt32String(value), ",");
  }
}

template <>
void SnapGenerator::GenerateNonZeroValue(absl::string_view name,
                                         const uint64_t &value) {
  if (value != 0) {
    Print(".", name, " = ", UInt64String(value), ",");
  }
}

SnapGenerator::VarName SnapGenerator::GenerateByteData(
    const Snapshot::ByteData &byte_data, const Options &opts,
    size_t alignment) {
  // If byte data are repeating, return empty name.
  if (opts.compress_repeating_bytes && IsRepeatingByteRun(byte_data)) {
    return VarName();
  }

  // TODO(dougkwan): [impl] We want to use more descriptive names for the
  // file local object. This will require passing the name of parent object
  // to figure out the correct context, for example:
  // code_memory_bytes_2_of_snap_foo.
  VarName var_name = LocalVarName("local_uint8");
  const std::string optional_alignment =
      alignment > 1 ? absl::StrCat(" __attribute__((aligned(", alignment, ")))")
                    : "";
  Print(absl::StrFormat("static const uint8_t %s %s[%zd] = {",
                        optional_alignment, var_name, byte_data.size()));

  // Skip trailing zeros.
  size_t print_size = byte_data.size();
  const uint8_t *data = reinterpret_cast<const uint8_t *>(byte_data.data());
  while (print_size > 0 && data[print_size - 1] == 0) print_size--;

  for (size_t i = 0; i < print_size; ++i) {
    Print(absl::StrFormat("0x%x,", data[i]));
  }
  PrintLn("};");
  return var_name;
}

SnapGenerator::VarNameList SnapGenerator::GenerateMemoryBytesByteData(
    const Snapshot::MemoryBytesList &memory_bytes_list, const Options &opts) {
  VarNameList var_names;
  for (const auto &memory_bytes : memory_bytes_list) {
    var_names.push_back(GenerateByteData(memory_bytes.byte_values(), opts));
  }
  return var_names;
}

SnapGenerator::VarName SnapGenerator::GenerateMemoryBytesList(
    const Snapshot::MemoryBytesList &memory_bytes_list,
    const VarNameList &byte_values_var_names,
    const MappedMemoryMap &mapped_memory_map, const Options &opts) {
  CHECK_EQ(memory_bytes_list.size(), byte_values_var_names.size());
  VarName memory_bytes_list_var_name = LocalVarName("local_memory_bytes");

  PrintLn(absl::StrFormat("static const Snap::MemoryBytes %s[%zd] = {",
                          memory_bytes_list_var_name,
                          memory_bytes_list.size()));
  for (size_t i = 0; i < memory_bytes_list.size(); ++i) {
    const Snapshot::MemoryBytes &memory_bytes = memory_bytes_list[i];
    const Snapshot::Address start = memory_bytes.start_address();
    const Snapshot::Address limit = memory_bytes.limit_address();
    std::optional<MemoryMapping> memory_mapping =
        mapped_memory_map.MappingAt(start);
    CHECK(memory_mapping.has_value());
    // Memory bytes should be contained within this memory mapping.
    CHECK_LE(memory_mapping->start_address(), start);
    CHECK_GE(memory_mapping->limit_address(), limit);
    bool compress_repeating_bytes =
        opts.compress_repeating_bytes &&
        IsRepeatingByteRun(memory_bytes.byte_values());
    PrintLn(absl::StrFormat(
        "{ .start_address = %s, .perms = 0x%x, .repeating = %s,",
        AddressString(start), memory_mapping->perms().ToMProtect(),
        compress_repeating_bytes ? "true" : "false"));
    if (compress_repeating_bytes) {
      CHECK(byte_values_var_names[i].empty());
      Print(absl::StrFormat(".data{.byte_run{.value = 0x%x, .size = %zd}},",
                            memory_bytes.byte_values()[0],
                            memory_bytes.num_bytes()));
    } else {
      CHECK(!byte_values_var_names[i].empty());
      Print(absl::StrFormat(".data{.byte_values = %s},",
                            ArrayString(memory_bytes.byte_values().size(),
                                        byte_values_var_names[i])));
    }
    PrintLn("},");
  }
  PrintLn("};");
  return memory_bytes_list_var_name;
}

SnapGenerator::VarName SnapGenerator::GenerateMemoryMappingList(
    const Snapshot::MemoryMappingList &memory_mapping_list) {
  VarName memory_mapping_list_var_name = LocalVarName("local_memory_mapping");

  PrintLn(absl::StrFormat("static const Snap::MemoryMapping %s[%zd] = {",
                          memory_mapping_list_var_name,
                          memory_mapping_list.size()));
  for (const auto &memory_mapping : memory_mapping_list) {
    Print("{ .start_address=", AddressString(memory_mapping.start_address()),
          ",");
    Print(absl::StrFormat(".num_bytes = %lluULL,", memory_mapping.num_bytes()));
    PrintLn(absl::StrFormat(".perms = 0x%x },",
                            memory_mapping.perms().ToMProtect()));
  }
  PrintLn("};");
  return memory_mapping_list_var_name;
}

void SnapGenerator::GenerateGRegs(const Snapshot::ByteData &gregs_byte_data) {
#ifdef __x86_64__
  GRegSet gregs = {};
  // Only generate initializers for individual registers when the registers byte
  // data are not empty. Otherwise rely on zero-initialization.
  // This function does not check if the empty registers is actually permitted
  // The check is performed by Snapify().

  if (!gregs_byte_data.empty()) {
    CHECK(DeserializeGRegs(gregs_byte_data, &gregs));
  }

#define GEN_GREG(reg) GenerateNonZeroValue(#reg, gregs.reg)

  Print("{");

  GEN_GREG(r8);
  GEN_GREG(r9);
  GEN_GREG(r10);
  GEN_GREG(r11);
  GEN_GREG(r12);
  GEN_GREG(r13);
  GEN_GREG(r14);
  GEN_GREG(r15);
  GEN_GREG(rdi);
  GEN_GREG(rsi);
  GEN_GREG(rbp);
  GEN_GREG(rbx);
  GEN_GREG(rdx);
  GEN_GREG(rax);
  GEN_GREG(rcx);
  GEN_GREG(rsp);
  GEN_GREG(rip);
  GEN_GREG(eflags);

  GEN_GREG(cs);
  GEN_GREG(gs);
  GEN_GREG(fs);
  GEN_GREG(ss);
  GEN_GREG(ds);
  GEN_GREG(es);

  // padding field ignored.

  GEN_GREG(fs_base);
  GEN_GREG(gs_base);

  // sigmask ignored.

  Print("}");

#undef GEN_GREG
#else  // __x86_64__
#error "Unsupported architecture"
#endif  // __x86_64__
}

#ifdef __x86_64__
// x86_64 specific helpers for GenerateFPRegs() below.
// TODO(dougkwan): [test] These helpers need testing. Either refactor
// them into a separate library for easier testing or change to use
// generator specific tests in snap_generator_test_lib.
void SnapGenerator::GenerateX87Stack(const __uint128_t st[8]) {
  Print("{");

  // Find the last non-zero x87 stack entry
  size_t print_size = 8;
  while (print_size > 0 && st[print_size - 1] == 0) {
    print_size--;
  }

  for (size_t i = 0; i < print_size; ++i) {
    Print(UInt128String(st[i]), ",");
  }
  Print("}");
}

void SnapGenerator::GenerateXMMRegs(const __uint128_t xmm[16]) {
  Print("{");

  // Find the last non-zero XMM reg
  size_t print_size = 16;
  while (print_size > 0 && xmm[print_size - 1] == 0) {
    print_size--;
  }

  for (size_t i = 0; i < print_size; ++i) {
    Print(UInt128String(xmm[i]), ",");
  }
  Print("}");
}
#endif  // __x86_64__

void SnapGenerator::GenerateFPRegs(const Snapshot::ByteData &fpregs_byte_data) {
#ifdef __x86_64__
  FPRegSet fpregs = {};
  // Only generate initializers for individual registers when the registers byte
  // data are not empty. Otherwise rely on zero-initialization.
  // This function does not check if the empty registers is actually permitted
  // The check is performed by Snapify().
  if (!fpregs_byte_data.empty()) {
    CHECK(DeserializeFPRegs(fpregs_byte_data, &fpregs));
  }

#define GEN_FPREG(reg) GenerateNonZeroValue(#reg, fpregs.reg)

  Print("{");

  GEN_FPREG(fcw);
  GEN_FPREG(fsw);
  GEN_FPREG(ftw);
  GEN_FPREG(fop);
  GEN_FPREG(rip);
  GEN_FPREG(rdp);
  GEN_FPREG(mxcsr);
  GEN_FPREG(mxcsr_mask);

  // x87 FP stack
  Print(".st = ");
  GenerateX87Stack(fpregs.st);
  PrintLn(",");

  // XMM register.
  Print(".xmm = ");
  GenerateXMMRegs(fpregs.xmm);
  Print(",");

  Print("}");
#undef GEN_FPREG
#else  // __x86_64__
#error "Unsupported architecture"
#endif  // __x86_64__
}

void SnapGenerator::GenerateRegisters(
    const Snapshot::RegisterState &registers) {
  // RegisterState is not a POD class and we need to use a special
  // constructor that converts ConstexprRegisterState in order to
  // make it linker initialized.
  Print("{ .fpregs = ");
  GenerateFPRegs(registers.fpregs());
  Print(", .gregs = ");
  GenerateGRegs(registers.gregs());
  Print("}");
}

}  // namespace silifuzz
