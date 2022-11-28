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
#include "./common/snapshot.h"
#include "./snap/gen/repeating_byte_runs.h"
#include "./snap/snap.h"
#include "./util/checks.h"
#include "./util/ucontext/serialize.h"
#include "./util/ucontext/ucontext.h"

namespace silifuzz {

namespace {

// Returns 'address' as in C++ source code.
std::string AddressString(Snapshot::Address address) {
  return absl::StrFormat("0x%llxULL", address);
}

// Returns 'value' as a uint8_t literal in C++ source code.
std::string UIntString(uint8_t value) {
  return absl::StrFormat("0x%xU", value);
}

// Returns 'value' as a uint16_t literal in C++ source code.
std::string UIntString(uint16_t value) {
  return absl::StrFormat("0x%xU", value);
}

// Returns 'value' as a uint32_t literal in C++ source code.
std::string UIntString(uint32_t value) {
  return absl::StrFormat("0x%xU", value);
}

// Returns 'value' as a uint64_t literal in C++ source code.
std::string UIntString(uint64_t value) {
  return absl::StrFormat("0x%llxULL", value);
}

std::string UIntString(__uint128_t value) {
  // There's no such thing as an 128-bit literal, so we need to synthesize it
  // out of two 64-bit literals.
  uint64_t upper = value >> 64;
  uint64_t lower = value;
  if (upper) {
    return absl::StrFormat("(((__uint128_t)0x%llxULL) << 64 | 0x%llxULL)",
                           upper, lower);
  } else {
    return UIntString(lower);
  }
}

//  Returns string containing C++ code for initilizer of an Snap::Array of given
//  'size' and  whose elements are stored out-of-line in variable
//  'elements_var'.
std::string ArrayString(size_t size, absl::string_view elements_var) {
  return absl::StrFormat("{ .size = %zdULL, .elements = %s }", size,
                         elements_var);
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

absl::Status SnapGenerator::GenerateSnap(const std::string &name,
                                         const Snapshot &snapshot,
                                         const SnapifyOptions &opts) {
  const absl::StatusOr<Snapshot> snapified_or = Snapify(snapshot, opts);
  RETURN_IF_NOT_OK(snapified_or.status());
  const Snapshot &snapified = snapified_or.value();
  const Snapshot::EndState &end_state = snapified.expected_end_states()[0];
  const Snapshot::Endpoint &endpoint = end_state.endpoint();
  CHECK(endpoint.type() == Snapshot::Endpoint::kInstruction);

  // Code generation is done bottom-up. First, we generate variable-sized
  // components that cannot be placed inside the fix-sized Snap struct.

  // Generate all out-of-line ByteData.
  const std::vector<std::string> memory_byte_values_var_names =
      GenerateMemoryBytesByteData(snapified.memory_bytes(), opts);
  const std::vector<std::string> end_state_memory_byte_values_var_names =
      GenerateMemoryBytesByteData(end_state.memory_bytes(), opts);

  // Generate all out-of-line MemoryBytes
  const std::string memory_bytes_var_name = GenerateMemoryBytesList(
      snapified.memory_bytes(), memory_byte_values_var_names,
      snapified.mapped_memory_map(), opts);
  const std::string end_state_memory_bytes_var_name = GenerateMemoryBytesList(
      end_state.memory_bytes(), end_state_memory_byte_values_var_names,
      snapified.mapped_memory_map(), opts);

  // Generate all out-of-line MemoryMappings
  const std::string memory_mappings_var_name =
      GenerateMemoryMappingList(snapified.memory_mappings());

  const std::string registers_name = GenerateRegisters(snapified.registers());

  const std::string end_state_registers_name =
      GenerateRegisters(end_state.registers());

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
  PrintLn(".registers=&", registers_name, ",");
  PrintLn(".end_state_instruction_address=",
          AddressString(endpoint.instruction_address()), ",");
  PrintLn(".end_state_registers=&", end_state_registers_name, ",");
  PrintLn(".end_state_memory_bytes=",
          ArrayString(end_state.memory_bytes().size(),
                      end_state_memory_bytes_var_name),
          ",");

  PrintLn("};");
  return absl::OkStatus();
}

void SnapGenerator::GenerateSnapArray(
    const std::string &name, ArchitectureId architecture_id,
    const std::vector<std::string> &snap_var_name_list) {
  const std::string elements_var_name = absl::StrCat("elements_of_", name);
  Print(absl::StrFormat("static const Snap* const %s[%zd] = {",
                        elements_var_name, snap_var_name_list.size()));
  for (const auto &var_name : snap_var_name_list) {
    Print("&", var_name, ",");
  }
  PrintLn("};");

  PrintLn(absl::StrFormat(
      "extern const SnapCorpus %s = { .magic = 0x%lx, .corpus_type_size = "
      "sizeof(SnapCorpus), .snap_type_size = sizeof(Snap), "
      ".register_state_type_size = sizeof(Snap::RegisterState), "
      ".architecture_id = %d, .padding = {}, .snaps = { .size = %zd, .elements "
      "= %s }};",
      name, kSnapCorpusMagic, architecture_id, snap_var_name_list.size(),
      elements_var_name));
}

// ========================================================================= //

std::string SnapGenerator::LocalVarName(absl::string_view prefix) {
  return absl::StrCat(prefix, "_", local_object_name_counter_++);
}

template <typename T>
void SnapGenerator::GenerateNonZeroValue(absl::string_view name,
                                         const T &value) {
  if (value != 0) {
    Print(".", name, " = ", UIntString(value), ",");
  }
}

std::string SnapGenerator::GenerateByteData(const Snapshot::ByteData &byte_data,
                                            const SnapifyOptions &opts,
                                            size_t alignment) {
  // If byte data are repeating, return empty name.
  if (opts.compress_repeating_bytes && IsRepeatingByteRun(byte_data)) {
    return std::string();
  }

  // TODO(dougkwan): [impl] We want to use more descriptive names for the
  // file local object. This will require passing the name of parent object
  // to figure out the correct context, for example:
  // code_memory_bytes_2_of_snap_foo.
  std::string var_name = LocalVarName("local_uint8");
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

std::vector<std::string> SnapGenerator::GenerateMemoryBytesByteData(
    const Snapshot::MemoryBytesList &memory_bytes_list,
    const SnapifyOptions &opts) {
  std::vector<std::string> var_names;
  for (const auto &memory_bytes : memory_bytes_list) {
    var_names.push_back(GenerateByteData(memory_bytes.byte_values(), opts));
  }
  return var_names;
}

std::string SnapGenerator::GenerateMemoryBytesList(
    const Snapshot::MemoryBytesList &memory_bytes_list,
    const std::vector<std::string> &byte_values_var_names,
    const MappedMemoryMap &mapped_memory_map, const SnapifyOptions &opts) {
  CHECK_EQ(memory_bytes_list.size(), byte_values_var_names.size());
  std::string memory_bytes_list_var_name = LocalVarName("local_memory_bytes");

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
        "{ .start_address = %s, .perms = 0x%x, .flags = %s,",
        AddressString(start), memory_mapping->perms().ToMProtect(),
        compress_repeating_bytes ? "Snap::MemoryBytes::kRepeating" : "0"));
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

std::string SnapGenerator::GenerateMemoryMappingList(
    const Snapshot::MemoryMappingList &memory_mapping_list) {
  std::string memory_mapping_list_var_name =
      LocalVarName("local_memory_mapping");

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
  GRegSet<X86_64> gregs = {};
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
    Print(UIntString(st[i]), ",");
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
    Print(UIntString(xmm[i]), ",");
  }
  Print("}");
}
#endif  // __x86_64__

void SnapGenerator::GenerateFPRegs(const Snapshot::ByteData &fpregs_byte_data) {
#ifdef __x86_64__
  FPRegSet<X86_64> fpregs = {};
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

std::string SnapGenerator::GenerateRegisters(
    const Snapshot::RegisterState &registers) {
  std::string var_name = LocalVarName("local_registers");
  PrintLn("Snap::RegisterState ", var_name, " = {");
  Print("  .fpregs = ");
  GenerateFPRegs(registers.fpregs());
  PrintLn(",");
  Print("  .gregs = ");
  GenerateGRegs(registers.gregs());
  PrintLn(",");
  PrintLn("};");
  return var_name;
}

}  // namespace silifuzz
