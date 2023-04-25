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

#ifndef THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_PRINTER_H_
#define THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_PRINTER_H_

#include <stdint.h>

#include <optional>
#include <utility>

#include "absl/strings/string_view.h"
#include "./common/snapshot.h"
#include "./common/snapshot_types.h"
#include "./util/itoa.h"
#include "./util/line_printer.h"
#include "./util/text_table.h"
#include "./util/ucontext/ucontext_types.h"

namespace silifuzz {

// SnapshotPrinter lets one print the state of a Snapshot.
//
// This is more informative and usable for human consumption than
// converting corresponding proto::Snapshot to text.
//
// This is conceptually a beefed-up Snapshot::DebugString().
// (We do not provide SnapshotPrinter's logic via that interface simply
// to avoid merging these two libs into one).
//
// This class is thread-compatible.
class SnapshotPrinter : private SnapshotTypeNames {
 public:
  // Printing option modes controlling how register data is presented.
  enum RegsMode { kAllRegs, kNonZeroRegs };
  enum FPRegsMode { kAllFPRegs, kCtrlFPRegs, kNoFPRegs };
  enum EndRegsMode { kAllEndRegs, kChangedEndRegs };
  // ... and how end-states are presented.
  enum EndStateMode { kAllEndStates, kEndStateDiffs };

  // Printing options.
  struct Options {
    int indent = 0;  // initial/overall value for all the lines
    RegsMode regs_mode = kNonZeroRegs;
    FPRegsMode fp_regs_mode = kCtrlFPRegs;
    EndRegsMode end_state_regs_mode = kChangedEndRegs;
    EndStateMode end_state_mode = kEndStateDiffs;
    int64_t bytes_limit = 150;  // max # of ByteData bytes to print
    bool stats = false;       // whether to print summary stats
  };
  static Options DefaultOptions() { return Options(); }

  // We will print into *printer according to `options`.
  explicit SnapshotPrinter(LinePrinter* printer,
                           const Options& options = DefaultOptions());

  ~SnapshotPrinter();

  // Not copyable or movable (no need).
  SnapshotPrinter(const SnapshotPrinter&) = delete;
  SnapshotPrinter& operator=(const SnapshotPrinter&) = delete;

  // Prints `snapshot` per c-tor args.
  void Print(const Snapshot& snapshot);

  // Prints info about all endpoints.
  void PrintEndpointsOnly(const Snapshot& snapshot);

  // Prints info about actual_end_state of executing `snapshot`,
  // as compared to snapshot.expected_end_states().
  void PrintActualEndState(const Snapshot& snapshot,
                           const EndState& actual_end_state);

  // A better version of LOG_INFO(snapshot.DebugString()):
  // logs on multiple lines avoiding any chopping.
  static void LogDebugString(const Snapshot& snapshot,
                             const Options& options = DefaultOptions());

 private:
  // Convenience forwarders to printer_.
  template <typename... Ts>
  void Line(Ts&&... args) {
    printer_->Line(std::forward<Ts>(args)...);
  }
  void Indent() { printer_->Indent(); }
  void Unindent() { printer_->Unindent(); }

  // Prints byte data as hex (also splitting into not too long lines)
  // and printing up to `limit` bytes (-1 is no-limit).
  void PrintByteData(const ByteData& bytes, int64_t limit = -1);

  // Prints info about snapshot.IsComplete() outcomes.
  void PrintCompleteness(const Snapshot& snapshot);

  // Prints into *table a line about stats_name stats for
  // snapshot.memory_mappings() that have `perms`.
  void PrintMappedMemoryStats(const Snapshot& snapshot,
                              absl::string_view stats_name, MemoryPerms perms,
                              TextTable* table);

  // Prints various stats about snapshot.memory_mappings().
  void PrintMemoryMappingsStats(const Snapshot& snapshot);

  // Prints info about snapshot.memory_mappings() and
  // snapshot.negative_memory_mappings().
  void PrintMemoryMappings(const Snapshot& snapshot);

  // Summary stats about one or several MemoryBytes.
  struct MemoryBytesStats {
    ByteSize num_bytes = 0;
    MemoryPerms min_perms = MemoryPerms::All();   // intersection of perms
    MemoryPerms max_perms = MemoryPerms::None();  // union of perms
    Address start_address = Snapshot::kMaxAddress;
    Address limit_address = Snapshot::kMinAddress;
  };

  // Produces stats for memory_bytes in `snapshot`.
  MemoryBytesStats Stats(const Snapshot& snapshot,
                         const MemoryBytesList& memory_bytes);

  // Prints a line about MemoryBytesStats in `snapshot`.
  void PrintMemoryBytesLine(const Snapshot& snapshot,
                            const MemoryBytesStats& stats);

  // Prints various stats about memory_bytes in `snapshot`.
  void PrintMemoryBytesStats(const Snapshot& snapshot,
                             const MemoryBytesList& memory_bytes);

  // Prints info about memory_bytes in `snapshot`.
  void PrintMemoryBytes(const Snapshot& snapshot,
                        const MemoryBytesList& memory_bytes);

  // Prints executable memory bytes in `snapshot` as instructions.
  void PrintExecutableMemoryBytes(const Snapshot& snapshot,
                                  const MemoryBytesList& memory_bytes);

  // Helper forwarding "lambda" for LogGRegs() and LogFPRegs() functions.
  // this_printer will be a SnapshotPrinter*.
  static void RegsLogger(void* this_printer, const char* str1, const char* str2,
                         const char* str3, const char* str4);

  // Prints register values. `base` if given will suppress printing
  // of the registers that have the same value in it. `comment` provides an
  // optional note about how registers are printed.
  // When `log_diff` is true logs both the actual and the expected values.
  template <typename Arch>
  void PrintGRegs(const GRegSet<Arch>& gregs, const GRegSet<Arch>* base,
                  absl::string_view comment, bool log_diff);
  template <typename Arch>
  void PrintFPRegs(const FPRegSet<Arch>& fpregs, const FPRegSet<Arch>* base,
                   absl::string_view comment, bool log_diff);

  // Prints register_state from `snapshot` relative to base_register_state,
  // that is provided iff register_state is end-state registers.
  // `log_diff` is passed to PrintGRegs/PrintFPRegs.
  void PrintRegisterState(const Snapshot& snapshot,
                          const RegisterState& register_state,
                          const RegisterState* base_register_state = nullptr,
                          bool log_diff = false);
  template <typename Arch>
  void PrintRegisterStateImpl(
      const RegisterState& register_state,
      const RegisterState* base_register_state = nullptr,
      bool log_diff = false);

  // Prints snapshot.registers().
  void PrintRegisters(const Snapshot& snapshot);

  // Prints into *table a line about stats_name (one of min,max,avg) stats for
  // snapshot.expected_end_states().
  // For perms and Address ranges produced,
  // min mean intersection, max means union, and avg does not make sense.
  void PrintEndStatesStats(const Snapshot& snapshot,
                           absl::string_view stats_name, TextTable* table);

  // Prints various stats about snapshot.expected_end_states().
  void PrintEndStatesStats(const Snapshot& snapshot);

  // Prints info about `endpoint`.
  // base_endpoint if given provides the endpoint of snapshot's end_state
  // to diff against (base_end_state_index is its index then).
  void PrintEndpoint(const Endpoint& endpoint,
                     const Endpoint* base_endpoint = nullptr,
                     int base_end_state_index = -1);

  // Returns the count of bytes in memory_bytes.
  static int NumBytes(const MemoryBytesList& memory_bytes);

  // Returns the magnitude of the diference from
  // snapshot.expected_end_states()[base_end_state_index] to end_state.
  static int DiffSize(const Snapshot& snapshot, int base_end_state_index,
                      const EndState& end_state);

  // Return the closest to end_state EndState if any among
  // snapshot.expected_end_states() up to but excluding end_state_index_limit
  // to diff in printing. Sets *end_state_index to match the return
  // value if non-null.
  static const EndState* ClosestEndState(const EndState& end_state,
                                         const Snapshot& snapshot,
                                         int end_state_index_limit,
                                         int* end_state_index);

  // Prints info about end_state in `snapshot`.
  // base_end_state if given provides the snapshot's end_state to diff against
  // (base_end_state_index is its index then);
  // otherwise will diff against snapshot's initial state.
  void PrintEndState(const Snapshot& snapshot, const EndState& end_state,
                     const EndState* base_end_state = nullptr,
                     int base_end_state_index = -1);

  // Prints info about snapshot.expected_end_states().
  void PrintEndStates(const Snapshot& snapshot);

  // ----------------------------------------------------------------------- //

  // C-tor args.
  const Options options_;
  LinePrinter* const printer_;
};

// ========================================================================= //

template <>
extern const char* EnumNameMap<SnapshotPrinter::RegsMode>[2];
template <>
extern const char* EnumNameMap<SnapshotPrinter::FPRegsMode>[3];
template <>
extern const char* EnumNameMap<SnapshotPrinter::EndRegsMode>[2];
template <>
extern const char* EnumNameMap<SnapshotPrinter::EndStateMode>[2];

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_COMMON_SNAPSHOT_PRINTER_H_
