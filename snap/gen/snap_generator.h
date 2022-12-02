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

#ifndef THIRD_PARTY_SILIFUZZ_SNAP_GEN_SNAP_GENERATOR_H_
#define THIRD_PARTY_SILIFUZZ_SNAP_GEN_SNAP_GENERATOR_H_

#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./common/mapped_memory_map.h"
#include "./common/snapshot.h"
#include "./util/platform.h"

namespace silifuzz {

// Per-snap generation options.
struct SnapifyOptions {
  // If true, allows the only expected endstate of the _input_ snapshot(s) to
  // be Snapshot::State::kUndefinedEndState.
  bool allow_undefined_end_state = false;

  // Use the end state for this platform.
  PlatformId platform_id = PlatformId::kAny;

  // Use run-length compression for memory byte data.
  bool compress_repeating_bytes = true;

  // Returns Options for running snapshots produced by V2-style Maker.
  static constexpr SnapifyOptions V2InputRunOpts() {
    return SnapifyOptions{.allow_undefined_end_state = false};
  }

  // Returns Options for making V2-style snapshots.
  static constexpr SnapifyOptions V2InputMakeOpts() {
    return SnapifyOptions{.allow_undefined_end_state = true};
  }

  static constexpr SnapifyOptions Default() { return V2InputRunOpts(); }
};

// Tests if snapshot can be converted to Snap.
absl::Status CanSnapify(const Snapshot &snapshot,
                        const SnapifyOptions &opts = SnapifyOptions::Default());

// Convert 'snapshot' into a form that GenerateSnap() can convert into a
// Snap that produces the same result as the 'snapshot'. The conversion
// includes adding an exit sequence at the end state instruction
// address and including all writable mapping memory bytes in the end
// state.
absl::StatusOr<Snapshot> Snapify(
    const Snapshot &snapshot,
    const SnapifyOptions &opts = SnapifyOptions::Default());

// SnapGenerator takes a silifuzz::Snapshot and generates a Snap representation
// of it as C++ source code. The generated C++ source code is not formatted
// properly for human readabily but the generator may do rudimentary formatting
// that still helps readability. Generated code is expected to be further
// processed by tools like clang-format for proper formatting.
//
// Example usage:
//
//    ostream os;
//    ...
//    SnapshotGenerator gen(os);
//    gen.FileStart();
//    ...
//    Snapshot snapshot = ...
//    gen.GenerateSnap("kExampleSnap", snapshot);
//    gen.GenerateSnapArray("kDefaultSnapCorpus", {"kExampleSnap"});
//    ....
//    gen.FileEnd();
//
// This class is thread-compatible.
template <typename Arch>
class SnapGenerator {
 public:
  // Construct a SnapGenerator. Generated C++ code is sent to 'output_stream'.
  SnapGenerator(std::ostream &output_stream) : output_stream_(output_stream) {
    IncludeSystemHeader("cstdint");
    IncludeLocalHeader("./snap/snap.h");
  }

  ~SnapGenerator() { output_stream_.flush(); }

  // Class has I/O state and is not copyable.
  SnapGenerator(const SnapGenerator &) = delete;
  SnapGenerator &operator=(const SnapGenerator &) = delete;

  // Add a required system header for the generated code.  This must be called
  // before FileStart(). The headers are included in the order call to
  // IncludeHeader(). The header third_party/silifuzz/runner/snap.h is
  // automatically added by the constructor.
  void IncludeSystemHeader(absl::string_view header) {
    system_headers_.push_back(std::string(header));
  }

  // Like above but for local header.
  void IncludeLocalHeader(absl::string_view header) {
    local_headers_.push_back(std::string(header));
  }

  // Generate file prologue and epilogue.
  void FileStart();
  void FileEnd();

  // Generates a line comment (just like this one).
  void Comment(absl::string_view comment);

  // Generates C++ source code to define a Snap variable called
  // `name` using a normalized version of `snapshot`.
  absl::Status GenerateSnap(
      const std::string &name, const Snapshot &snapshot,
      const SnapifyOptions &opts = SnapifyOptions::Default());

  // Generate C++ source code to define a SnapCorpus variable
  // called 'name' using a list containing variable names of previously
  // generated Snaps.
  void GenerateSnapArray(const std::string &name,
                         const std::vector<std::string> &snap_var_name_list);

 private:
  // Returns a unique name for a file local object, with an optional prefix.
  std::string LocalVarName(absl::string_view prefix = "local_object");

  // Prints variable number of arguments to the generator's output stream.
  // REQUIRED: number of arguments and their types must be acceptable by
  // absl::StrCat().
  template <typename... Ts>
  void Print(const Ts &...args) {
    output_stream_ << absl::StrCat(args...);
  }

  // Like Print() above but also ends the current line.
  template <typename... Ts>
  void PrintLn(const Ts &...args) {
    output_stream_ << absl::StrCat(args...) << std::endl;
  }

  // Generates code to initialize a field called 'name' with a T type
  // 'value' if 'value' is not zero.
  template <typename T>
  void GenerateNonZeroValue(absl::string_view name, const T &value);

  // Generates code to assign a variable of type Snap::Array<uint8_t> containing
  // data from 'byte_data' using `opts`.  Optionally aligns the uint8_t data to
  // the given alignment. Returns variable name. If run-lengh compression is
  // applied to the byte data, an empty var name is returned.  Caller must Check
  // that run-length encoding is not applied to byte data before using the
  // returned var name.
  //
  // Byte data are by default aligned to 8-byte boundaries. Copying memory and
  // comparing memory are less efficienct with narrower alignments than this.
  std::string GenerateByteData(const Snapshot::ByteData &byte_data,
                               const SnapifyOptions &opts,
                               size_t alignment = sizeof(uint64_t));

  // Generates code for ByteData inside a list of Snapshot::MemoryBytes using
  // `opts`. For each MemoryBytes, an uint8_t array is generated for its
  // ByteData and the array is assigned to a new variable. Returns a list of
  // such variable names, one for each MemoryBytes and in the same order as
  // 'memory_bytes_list'.
  std::vector<std::string> GenerateMemoryBytesByteData(
      const Snapshot::MemoryBytesList &memory_bytes_list,
      const SnapifyOptions &opts);

  // Generates code to assign a variable with an array of Snap::MemoryByte
  // for 'memory_bytes_list' using `opts`. 'byte_values_var_names' is a list of
  // variable names of arrays generated by GenerateMemoryBytesByteData().
  // 'mapped_memory_map' describes the memory mappings used by memory bytes.
  // Returns variable name of the Snap::MemoryByte array.
  std::string GenerateMemoryBytesList(
      const Snapshot::MemoryBytesList &memory_bytes_list,
      const std::vector<std::string> &byte_values_var_names,
      const MappedMemoryMap &mapped_memory_map, const SnapifyOptions &opts);

  // Generates code to assign a variable with an array of Snap::MemoryMapping
  // for 'memory_mapping_list'. Returns variable name of the Snap::MemoryMapping
  // array.
  std::string GenerateMemoryMappingList(
      const Snapshot::MemoryMappingList &memory_mapping_list);

  // Generates a GRegSet expression correspoding to the 'gregs_byte_data', which
  // is in the same format as returned by Snapshot::ReigsterState::gregs().
  void GenerateGRegs(const Snapshot::ByteData &gregs_byte_data);

  // Generate an array of scalar values.
  template <typename T>
  void GenerateArray(const T *data, size_t size);

  // Generates a FPRegSet expression correspoding to the 'fpregs_byte_data',
  // which is in the same format as returned by
  // Snapshot::ReigsterState::fpregs().
  void GenerateFPRegs(const Snapshot::ByteData &fpregs_byte_data);

  // Generates code for the contents of 'registers'.
  std::string GenerateRegisters(const Snapshot::RegisterState &registers);

  // Output stream for the generator.
  std::ostream &output_stream_;

  // Counter for temporary name generator.
  size_t local_object_name_counter_ = 0;

  // System headers used by generated code.
  std::vector<std::string> system_headers_;

  // Local headers used by generated code.  Included after system headers.
  std::vector<std::string> local_headers_;
};

}  // namespace silifuzz

#endif  // THIRD_PARTY_SILIFUZZ_SNAP_GEN_SNAP_GENERATOR_H_
