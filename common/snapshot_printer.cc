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

#include "./common/snapshot_printer.h"

#include <limits>
#include <optional>

#include "absl/strings/escaping.h"
#include "./common/memory_state.h"
#include "./common/snapshot_util.h"
#include "./util/itoa.h"
#include "./util/logging_util.h"

namespace silifuzz {

template <>
ABSL_CONST_INIT const char* EnumNameMap<SnapshotPrinter::RegsMode>[2] = {
    "all", "non-0"};
template <>
ABSL_CONST_INIT const char* EnumNameMap<SnapshotPrinter::FPRegsMode>[3] = {
    "all", "ctrl", "none"};
template <>
ABSL_CONST_INIT const char* EnumNameMap<SnapshotPrinter::EndRegsMode>[2] = {
    "all", "changed"};
template <>
ABSL_CONST_INIT const char* EnumNameMap<SnapshotPrinter::EndStateMode>[2] = {
    "all", "diffs"};

// ========================================================================= //

SnapshotPrinter::SnapshotPrinter(LinePrinter* printer, const Options& options)
    : options_(options), printer_(printer) {
  DCHECK_GE(options.bytes_limit, -1);
  printer_->Indent(options_.indent);
}

SnapshotPrinter::~SnapshotPrinter() { printer_->Unindent(options_.indent); }

void SnapshotPrinter::Print(const Snapshot& snapshot) {
  Line("Metadata:");
  {
    Indent();
    Line("Id: ", snapshot.id());
    Line("Architecture: ", snapshot.architecture_name());
    PrintCompleteness(snapshot);
    Unindent();
  }

  PrintRegisters(snapshot);
  PrintEndStates(snapshot);
  PrintMemoryMappings(snapshot);
  PrintMemoryBytes(snapshot, snapshot.memory_bytes());
}

void SnapshotPrinter::PrintEndpointsOnly(const Snapshot& snapshot) {
  for (const auto& e : snapshot.expected_end_states()) {
    PrintEndpoint(e.endpoint());
  }
}

void SnapshotPrinter::PrintActualEndState(const Snapshot& snapshot,
                                          const EndState& actual_end_state) {
  int base_end_state_index;
  auto base_end_state = ClosestEndState(actual_end_state, snapshot,
                                        snapshot.expected_end_states().size(),
                                        &base_end_state_index);
  PrintEndState(snapshot, actual_end_state, base_end_state,
                base_end_state_index);
}

// static
void SnapshotPrinter::LogDebugString(const Snapshot& snapshot,
                                     const Options& options) {
  LinePrinter line_printer(LinePrinter::LogInfoPrinter);
  SnapshotPrinter(&line_printer, options).Print(snapshot);
}

// ========================================================================= //

void SnapshotPrinter::PrintByteData(const ByteData& bytes, int64_t limit) {
  static constexpr int kLineSize = 100;
  std::string hex;
  int i = 0;
  for (char byte : bytes) {
    if (limit >= 0 && i >= limit) {
      hex.append("... (data ommited)");
      break;
    }
    hex.append(absl::StrCat(absl::Hex(byte, absl::kZeroPad2)));
    if (hex.size() >= kLineSize) {
      Line(hex);
      hex.clear();
    }
    ++i;
  }
  Line(hex);
}

void SnapshotPrinter::PrintCompleteness(const Snapshot& snapshot) {
  bool incomplete = false;
  std::string completeness;
  auto normal = snapshot.IsComplete(Snapshot::kNormalState);
  auto no_end_state = snapshot.IsComplete(Snapshot::kUndefinedEndState);
  auto making = snapshot.IsComplete(Snapshot::kMakingState);
  if (normal.ok()) {
    completeness = "complete";
  } else if (no_end_state.ok()) {
    completeness = "no end state";
  } else if (making.ok()) {
    completeness = "in the making";
  } else {
    completeness = "INCOMPLETE: ";
    incomplete = true;
  }
  Line("Compleness: ", completeness);
  if (incomplete) {
    Indent();
    Line(normal.ToString());
    Line(no_end_state.ToString());
    Unindent();
  }
}

void SnapshotPrinter::PrintMappedMemoryStats(const Snapshot& snapshot,
                                             absl::string_view stats_name,
                                             MemoryPerms perms,
                                             TextTable* table) {
  int count = 0;
  ByteSize bytes_mapped = 0;
  Snapshot::MemoryBytesSet mapped;
  Address start_address = std::numeric_limits<Address>::max();
  Address limit_address = std::numeric_limits<Address>::min();
  for (const auto& m : snapshot.memory_mappings()) {
    if (m.perms().Has(perms)) {
      count += 1;
      bytes_mapped += m.num_bytes();
      mapped.Add(m.start_address(), m.limit_address());
      // Track overall address range for all memory mappings.
      start_address = std::min(start_address, m.start_address());
      limit_address = std::max(limit_address, m.limit_address());
    }
  }
  if (count == 0) return;
  DCHECK_EQ(bytes_mapped % snapshot.page_size(), 0);
  const int pages_mapped = bytes_mapped / snapshot.page_size();
  mapped.Intersect(snapshot.written_memory_set());
  const ByteSize bytes_written = mapped.byte_size();
  table->AddRowCells(stats_name, count, pages_mapped, bytes_mapped,
                     bytes_written, HexStr(start_address),
                     HexStr(limit_address));
}

void SnapshotPrinter::PrintMemoryMappingsStats(const Snapshot& snapshot) {
  if (!options_.stats) return;
  if (snapshot.memory_mappings().size() <= 1) return;
  if (snapshot.negative_memory_mappings().empty()) {
    Line("Stats:");
  } else {
    Line("Stats (excluding negative mappings):");
  }
  Indent();
  TextTable table;
  table.AddRow({"Perms", "#", "Pages", "Bytes", "written", "[Start addr",
                "Limit addr)"});
  table.SetAligns({'l', 'r', 'r', 'r', 'r', 'l', 'l'});
  table.SetSeparators({" ", " ", " ", " ", " ", " .. "});
  PrintMappedMemoryStats(snapshot, "read", MemoryPerms::R(), &table);
  PrintMappedMemoryStats(snapshot, "write", MemoryPerms::W(), &table);
  PrintMappedMemoryStats(snapshot, "exec", MemoryPerms::X(), &table);
  PrintMappedMemoryStats(snapshot, "any", MemoryPerms::None(), &table);
  table.PrintVia(printer_->AsPrinter());
  Unindent();
}

void SnapshotPrinter::PrintMemoryMappings(const Snapshot& snapshot) {
  bool have_negative = !snapshot.negative_memory_mappings().empty();
  if (have_negative) {
    Line("Memory mappings (", snapshot.memory_mappings().size(), " plus ",
         snapshot.negative_memory_mappings().size(), " negative):");
  } else {
    Line("Memory mappings (", snapshot.memory_mappings().size(), "):");
  }
  Indent();
  PrintMemoryMappingsStats(snapshot);

  std::vector<const MemoryMapping*> mappings;
  for (const auto& m : snapshot.memory_mappings()) mappings.push_back(&m);
  auto less = [](const MemoryMapping* x, const MemoryMapping* y) {
    return x->start_address() < y->start_address();
  };
  std::sort(mappings.begin(), mappings.end(), less);

  TextTable table;
  table.AddRow(
      {"Perms", "Pages", "Bytes", "written", "[Start addr", "Limit addr)"});
  table.SetAligns({'l', 'r', 'r', 'r', 'l', 'l'});
  table.SetSeparators({" ", " ", " ", " ", " .. "});
  for (auto p : mappings) {
    const auto& m = *p;
    DCHECK_EQ(m.num_bytes() % snapshot.page_size(), 0);
    const int pages_mapped = m.num_bytes() / snapshot.page_size();
    Snapshot::MemoryBytesSet mapped;
    mapped.Add(m.start_address(), m.limit_address());
    mapped.Intersect(snapshot.written_memory_set());
    const ByteSize bytes_written = mapped.byte_size();
    table.AddRowCells(
        absl::StrCat(have_negative ? " " : "", m.perms().ToString()),
        pages_mapped, m.num_bytes(), bytes_written, HexStr(m.start_address()),
        HexStr(m.limit_address()));
  }
  // Add negative_memory_mappings() into the same table if any.
  mappings.clear();
  for (const auto& m : snapshot.negative_memory_mappings()) {
    mappings.push_back(&m);
  }
  std::sort(mappings.begin(), mappings.end(), less);
  for (auto p : mappings) {
    const auto& m = *p;
    DCHECK(m.num_bytes() % snapshot.page_size() == 0 ||
           // Special-case when the very last page is negatively mapped:
           m.limit_address() == Snapshot::kMaxAddress);
    const int pages_mapped = m.num_bytes() / snapshot.page_size();
    table.AddRowCells(absl::StrCat("!", m.perms().ToString()), pages_mapped,
                      m.num_bytes(), "n/a", HexStr(m.start_address()),
                      HexStr(m.limit_address()));
  }
  table.PrintVia(printer_->AsPrinter());
  Unindent();
}

SnapshotPrinter::MemoryBytesStats SnapshotPrinter::Stats(
    const Snapshot& snapshot, const MemoryBytesList& memory_bytes) {
  MemoryBytesStats r;
  for (const auto& b : memory_bytes) {
    r.num_bytes += b.num_bytes();
    r.min_perms.Intersect(snapshot.Perms(b.start_address(), b.limit_address(),
                                         MemoryPerms::kAnd));
    r.max_perms.Add(
        snapshot.Perms(b.start_address(), b.limit_address(), MemoryPerms::kOr));
    r.start_address = std::min(r.start_address, b.start_address());
    r.limit_address = std::max(r.limit_address, b.limit_address());
  }
  return r;
}

void SnapshotPrinter::PrintMemoryBytesLine(const Snapshot& snapshot,
                                           const MemoryBytesStats& stats) {
  const auto perms = stats.min_perms == stats.max_perms
                         ? stats.min_perms.ToString()
                         : absl::StrCat(stats.max_perms.ToString(), " -> ",
                                        stats.min_perms.ToString());
  const auto pages = 1.0 * stats.num_bytes / snapshot.page_size();
  if (pages <= 0.1) {
    Line(stats.num_bytes, " bytes in ", perms, ": [",
         HexStr(stats.start_address), " .. ", HexStr(stats.limit_address), ")");
  } else {
    Line(stats.num_bytes, " bytes (", pages, " pages)", " in ", perms, ": [",
         HexStr(stats.start_address), " .. ", HexStr(stats.limit_address), ")");
  }
}

void SnapshotPrinter::PrintMemoryBytesStats(
    const Snapshot& snapshot, const MemoryBytesList& memory_bytes) {
  if (!options_.stats) return;
  if (memory_bytes.size() <= 1) return;
  Line("Stats:");
  Indent();
  PrintMemoryBytesLine(snapshot, Stats(snapshot, memory_bytes));
  Unindent();
}

void SnapshotPrinter::PrintMemoryBytes(const Snapshot& snapshot,
                                       const MemoryBytesList& memory_bytes) {
  Line("Memory bytes (", memory_bytes.size(), "):");
  Indent();
  PrintMemoryBytesStats(snapshot, memory_bytes);

  std::vector<const MemoryBytes*> bytes;
  for (const auto& b : memory_bytes) bytes.push_back(&b);
  std::sort(bytes.begin(), bytes.end(),
            [](const MemoryBytes* x, const MemoryBytes* y) {
              return x->start_address() < y->start_address();
            });

  for (auto p : bytes) {
    const auto& b = *p;
    const auto min_perms =
        snapshot.Perms(b.start_address(), b.limit_address(), MemoryPerms::kAnd);
    const auto max_perms =
        snapshot.Perms(b.start_address(), b.limit_address(), MemoryPerms::kOr);
    PrintMemoryBytesLine(snapshot, {b.num_bytes(), min_perms, max_perms,
                                    b.start_address(), b.limit_address()});
    Indent();
    PrintByteData(b.byte_values(), options_.bytes_limit);
    if (VLOG_IS_ON(1)) {
      // These can be copy-pasted into a textformat proto.Snapshot:
      Indent();
      Line("raw: \"", absl::CEscape(b.byte_values()), "\"");
      Unindent();
    }
    Unindent();
  }
  Unindent();
}

// static
void SnapshotPrinter::RegsLogger(void* this_printer, const char* str1,
                                 const char* str2, const char* str3,
                                 const char* str4) {
  static_cast<SnapshotPrinter*>(this_printer)->Line(str1, str2, str3, str4);
}

void SnapshotPrinter::PrintGRegs(const GRegSet gregs, const GRegSet* base,
                                 absl::string_view comment, bool log_diff) {
  Line("gregs", comment, ":");
  Indent();
  LogGRegs(gregs, &SnapshotPrinter::RegsLogger, this, base, log_diff);
  Unindent();
}

void SnapshotPrinter::PrintFPRegs(const FPRegSet fpregs, const FPRegSet* base,
                                  absl::string_view comment, bool log_diff) {
  if (options_.fp_regs_mode == kNoFPRegs) return;
  Line("fpregs", options_.fp_regs_mode == kCtrlFPRegs ? " (control only)" : "",
       comment, ":");
  Indent();
  LogFPRegs(fpregs, options_.fp_regs_mode == kAllFPRegs,
            &SnapshotPrinter::RegsLogger, this, base, log_diff);
  Unindent();
}

void SnapshotPrinter::PrintRegisterState(
    const Snapshot& snapshot, const RegisterState& register_state,
    const RegisterState* base_register_state, bool log_diff) {
  if (snapshot.architecture() == Snapshot::CurrentArchitecture()) {
    GRegSet gregs, gregs_base;
    FPRegSet fpregs, fpregs_base;
    ConvertRegsFromSnapshot(register_state, &gregs, &fpregs);
    if (base_register_state != nullptr) {
      ConvertRegsFromSnapshot(*base_register_state, &gregs_base, &fpregs_base);
    } else {
      memset(&gregs_base, 0, sizeof(gregs_base));
      memset(&fpregs_base, 0, sizeof(fpregs_base));
    }
    bool use_base = base_register_state == nullptr
                        ? options_.regs_mode == kNonZeroRegs
                        : options_.end_state_regs_mode == kChangedEndRegs;
    auto comment =
        base_register_state == nullptr
            ? (options_.regs_mode == kNonZeroRegs ? " (non-0 only)" : "")
            : (options_.end_state_regs_mode == kChangedEndRegs
                   ? " (modified only)"
                   : "");
    PrintGRegs(gregs, use_base ? &gregs_base : nullptr, comment, log_diff);
    PrintFPRegs(fpregs, use_base ? &fpregs_base : nullptr, comment, log_diff);
    if (VLOG_IS_ON(1)) {
      // These can be copy-pasted into a textformat proto.Snapshot:
      Line("raw gregs:");
      Indent();
      Line("\"", absl::CEscape(register_state.gregs()), "\"");
      Unindent();
      Line("raw fpregs:");
      Indent();
      Line("\"", absl::CEscape(register_state.fpregs()), "\"");
      Unindent();
    }
  } else {
    Line("gregs (", register_state.gregs().size(), " bytes):");
    Indent();
    PrintByteData(register_state.gregs());
    Unindent();
    if (options_.fp_regs_mode != kNoFPRegs) {
      Line("fpregs (", register_state.fpregs().size(), " bytes):");
      Indent();
      PrintByteData(register_state.fpregs());
      Unindent();
    }
  }
}

void SnapshotPrinter::PrintRegisters(const Snapshot& snapshot) {
  Line("Registers:");
  Indent();
  if (snapshot.has_registers() && !snapshot.registers().IsUnset()) {
    PrintRegisterState(snapshot, snapshot.registers());
  } else {
    Line("Has no initial register state");
  }
  Unindent();
}

void SnapshotPrinter::PrintEndStatesStats(const Snapshot& snapshot,
                                          absl::string_view stats_name,
                                          TextTable* table) {
  MemoryBytesStats stats;
  if (stats_name[1] == 'i') {  // min, i.e. intersection of [start, limit)-s
    std::swap(stats.start_address, stats.limit_address);
  }
  for (const auto& e : snapshot.expected_end_states()) {
    auto s = Stats(snapshot, e.memory_bytes());
    if (stats_name[1] == 'i') {  // min
      stats.num_bytes = std::min(stats.num_bytes, s.num_bytes);
      stats.min_perms.Intersect(s.min_perms);
      stats.max_perms.Intersect(s.max_perms);
      stats.start_address = std::max(stats.start_address, s.start_address);
      stats.limit_address = std::min(stats.limit_address, s.limit_address);
    } else if (stats_name[1] == 'a') {  // max
      stats.num_bytes = std::max(stats.num_bytes, s.num_bytes);
      stats.min_perms.Add(s.min_perms);
      stats.max_perms.Add(s.max_perms);
      stats.start_address = std::min(stats.start_address, s.start_address);
      stats.limit_address = std::max(stats.limit_address, s.limit_address);
    } else {  // avg
      stats.num_bytes += s.num_bytes;
      // avg does not make sense for perms and not much for address range.
    }
  }
  if (stats_name[1] == 'v') {  // avg
    auto num_bytes =
        1.0 * stats.num_bytes / snapshot.expected_end_states().size();
    table->AddRowCells(stats_name, num_bytes, num_bytes / snapshot.page_size(),
                       "", "", "", "");
  } else {
    const auto pages = 1.0 * stats.num_bytes / snapshot.page_size();
    table->AddRowCells(stats_name, stats.num_bytes, pages,
                       stats.max_perms.ToString(), stats.min_perms.ToString(),
                       HexStr(stats.start_address),
                       HexStr(stats.limit_address));
  }
}

void SnapshotPrinter::PrintEndStatesStats(const Snapshot& snapshot) {
  if (!options_.stats) return;
  if (snapshot.expected_end_states().size() <= 1) return;
  Line("Stats:");
  Indent();
  TextTable table;
  table.AddRow(
      {"", "Bytes", "Pages", "Max", "Min", "[Start addr", "Limit addr)"});
  table.SetAligns({'l', 'r', 'r', 'l', 'l', 'l', 'l'});
  table.SetSeparators({" ", " ", " ", " -> ", " ", " .. "});
  PrintEndStatesStats(snapshot, "min", &table);
  PrintEndStatesStats(snapshot, "max", &table);
  PrintEndStatesStats(snapshot, "avg", &table);
  table.PrintVia(printer_->AsPrinter());
  Unindent();
}

void SnapshotPrinter::PrintEndpoint(const Endpoint& endpoint,
                                    const Endpoint* base_endpoint,
                                    int base_end_state_index) {
  DCHECK_EQ(base_endpoint == nullptr, base_end_state_index == -1);
  // Note that `endpoint` might not be from Snapshot::expected_end_states().
  if (base_endpoint && endpoint == *base_endpoint) {
    Line("Same endpoint as in expected end_state ", base_end_state_index);
  } else {
    if (base_endpoint && base_endpoint->type() != endpoint.type()) {
      base_endpoint = nullptr;
    }
    if (base_endpoint) {
      Line("Endpoint (diff vs expected end_state ", base_end_state_index, "):");
    } else {
      Line("Endpoint:");
    }
    Indent();
    switch (endpoint.type()) {
      case Endpoint::kInstruction:
        // Only one endpoint member, we know it differs.
        Line("Instruction address: ", HexStr(endpoint.instruction_address()));
        break;
      case Endpoint::kSignal:
        if (!(base_endpoint &&
              base_endpoint->sig_num() == endpoint.sig_num())) {
          Line("Signal: ", EnumStr(endpoint.sig_num()));
        }
        Indent();
        if (endpoint.sig_cause() != Endpoint::kGenericSigCause &&
            !(base_endpoint &&
              base_endpoint->sig_cause() == endpoint.sig_cause())) {
          Line("because: ", EnumStr(endpoint.sig_cause()));
        }
        if (!(base_endpoint &&
              base_endpoint->sig_address() == endpoint.sig_address())) {
          Line("with sig_address = ", HexStr(endpoint.sig_address()));
        }
        if (!(base_endpoint && base_endpoint->sig_instruction_address() ==
                                   endpoint.sig_instruction_address())) {
          Line("at instruction address = ",
               HexStr(endpoint.sig_instruction_address()));
        }
        Unindent();
        break;
    }
    Unindent();
  }
}

// static
int SnapshotPrinter::NumBytes(const MemoryBytesList& memory_bytes) {
  int r = 0;
  for (const auto& b : memory_bytes) {
    r += b.num_bytes();
  }
  return r;
}

// static
int SnapshotPrinter::DiffSize(const Snapshot& snapshot,
                              int base_end_state_index,
                              const EndState& end_state) {
  const auto& base_end_state =
      snapshot.expected_end_states()[base_end_state_index];
  auto memory_state =
      MemoryState::MakeEnd(snapshot, MemoryState::kWithRealExecutionFixups,
                           base_end_state_index, MemoryState::kZeroMappedBytes);
  // We write register bytes into memory_state on the otherwise unused
  // first page in the address space to reuse MemoryState::DeltaMemoryBytes()
  // for them.
  Address gregs_addr = 0;
  Address fpregs_addr = gregs_addr + base_end_state.registers().gregs().size();
  auto mapping = MemoryMapping::MakeSized(gregs_addr, snapshot.page_size(),
                                          MemoryPerms::All());
  memory_state.AddNewMemoryMapping(mapping);
  memory_state.SetMemoryBytes(
      MemoryBytes(gregs_addr, base_end_state.registers().gregs()));
  memory_state.SetMemoryBytes(
      MemoryBytes(fpregs_addr, base_end_state.registers().fpregs()));
  // We evaluate the size of the difference as a weighted sum of differences
  // in the components. Weights have been chosen using common-sense; can be
  // tuned to yield more desirable/revealing base end-states or to minimize
  // the total output of SnapshotPrinter.
  // EndState::platforms() has 0 weight on purpose.
  return 100 * (base_end_state.endpoint() == end_state.endpoint() ? 0 : 1) +
         4 * NumBytes(memory_state.DeltaMemoryBytes(
                 MemoryBytes(gregs_addr, end_state.registers().gregs()))) +
         2 * NumBytes(memory_state.DeltaMemoryBytes(
                 MemoryBytes(fpregs_addr, end_state.registers().fpregs()))) +
         1 * NumBytes(memory_state.DeltaMemoryBytes(end_state.memory_bytes()));
}

// static
const Snapshot::EndState* SnapshotPrinter::ClosestEndState(
    const EndState& end_state, const Snapshot& snapshot,
    int end_state_index_limit, int* end_state_index) {
  if (end_state_index_limit == 0) {
    *end_state_index = -1;
    return nullptr;  // nothing to diff with
  } else if (!snapshot.expected_end_states()[0].IsComplete().ok()) {
    // registers and memory_bytes are empty in *all* expected_end_states()
    // due to how Snapshot::IsComplete() works, so no point to diff with them.
    *end_state_index = -1;
    return nullptr;
  } else if (end_state_index_limit == 1) {  // the only choice
    *end_state_index = 0;
    return &snapshot.expected_end_states()[0];
  } else {
    int index = 0;
    // If we start worrying about performance here, we should try to
    // reuse the MemoryState across the DiffSize() calls.
    int diff_size = DiffSize(snapshot, 0, end_state);
    for (int i = 1; i < end_state_index_limit; ++i) {
      int d = DiffSize(snapshot, i, end_state);
      if (d < diff_size) {
        diff_size = d;
        index = i;
      }
    }
    *end_state_index = index;
    return &snapshot.expected_end_states()[index];
  }
}

void SnapshotPrinter::PrintEndState(const Snapshot& snapshot,
                                    const EndState& end_state,
                                    const EndState* base_end_state,
                                    int base_end_state_index) {
  DCHECK_EQ(base_end_state == nullptr, base_end_state_index == -1);
  PrintEndpoint(end_state.endpoint(),
                base_end_state ? &base_end_state->endpoint() : nullptr,
                base_end_state_index);
  if (!end_state.empty_platforms()) {
    if (base_end_state) {
      Line("Platforms (diff vs expected end_state ", base_end_state_index,
           "):");
    } else {
      Line("Platforms:");
    }
    Indent();
    for (int p = ToInt(PlatformId::kUndefined); p <= ToInt(kMaxPlatformId);
         ++p) {
      auto x = static_cast<PlatformId>(p);
      if (base_end_state) {
        if (end_state.has_platform(x) != base_end_state->has_platform(x)) {
          Line(end_state.has_platform(x) ? "+" : "-", EnumStr(x));
        }
      } else {
        if (end_state.has_platform(x)) Line(EnumStr(x));
      }
    }
    Unindent();
  }
  if (!end_state.registers().IsUnset()) {
    if (base_end_state) {
      Line("Registers (diff vs expected end_state ", base_end_state_index,
           "):");
      Indent();
      PrintRegisterState(snapshot, end_state.registers(),
                         &base_end_state->registers(), true);
    } else {
      Line("Registers (diff vs snapshot's initial values):");
      Indent();
      PrintRegisterState(snapshot, end_state.registers(), &snapshot.registers(),
                         false);
    }
    Unindent();
  }
  if (!end_state.memory_bytes().empty()) {
    if (base_end_state) {
      Line("Memory (diff vs expected end_state ", base_end_state_index, "):");
      auto memory_state = MemoryState::MakeEnd(
          snapshot, MemoryState::kWithRealExecutionFixups, base_end_state_index,
          MemoryState::kZeroMappedBytes);
      Indent();
      PrintMemoryBytes(snapshot,
                       memory_state.DeltaMemoryBytes(end_state.memory_bytes()));
      Unindent();
    } else {
      Line("Memory (diff vs snapshot's initial state):");
      Indent();
      PrintMemoryBytes(snapshot, end_state.memory_bytes());
      Unindent();
    }
  }
}

void SnapshotPrinter::PrintEndStates(const Snapshot& snapshot) {
  Line("End states (", snapshot.expected_end_states().size(), "):");
  Indent();
  PrintEndStatesStats(snapshot);
  int i = 0;
  for (const auto& e : snapshot.expected_end_states()) {
    if (snapshot.expected_end_states().size() > 1) {
      Line("#", i, ":");
      Indent();
      if (options_.end_state_mode == kAllEndStates) {
        PrintEndState(snapshot, e);
      } else {
        int base_end_state_index;
        auto base_end_state =
            ClosestEndState(e, snapshot, i, &base_end_state_index);
        PrintEndState(snapshot, e, base_end_state, base_end_state_index);
      }
      Unindent();
      ++i;
    } else {
      PrintEndState(snapshot, e);
    }
  }
  Unindent();
}

}  // namespace silifuzz
