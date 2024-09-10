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

#include "./snap/snap_corpus_util.h"

#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <memory>
#include <utility>

#include "./snap/snap.h"
#include "./snap/snap_relocator.h"
#include "./util/arch.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/misc_util.h"
#include "./util/mmapped_memory_ptr.h"

namespace silifuzz {

template <typename Arch>
MmappedMemoryPtr<const SnapCorpus<Arch>> LoadCorpusFromFile(
    const char* filename, bool preload, bool verify, int* corpus_fd) {
  // MAP_POPULATE interferes with memory sharing. Using it causes read
  // only portion of a corpus to be copied in each runner.
  constexpr char kProcPrefix[] = "/proc/";
  constexpr char kDevShmPrefix[] = "/dev/shm/";
  if (strncmp(filename, kProcPrefix, strlen(kProcPrefix)) == 0 ||
      strncmp(filename, kDevShmPrefix, strlen(kDevShmPrefix)) == 0) {
    preload = false;
  }

  VLOG_INFO(1, "Loading corpus from ", filename);
  int fd = open(filename, O_RDONLY);
  if (fd == -1) {
    LOG_FATAL("Failed to open corpus file ", filename, ": ", ErrnoStr(errno));
  }
  // Use lseek() instead of stat() to find file size as stat() is not
  // present in nolibc.
  off_t file_size = lseek(fd, 0, SEEK_END);
  CHECK_NE(file_size, -1);
  VLOG_INFO(1, "Corpus size (bytes) ", IntStr(file_size));
  void* relocatable = mmap(nullptr, file_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | (preload ? MAP_POPULATE : 0), fd, 0);
  CHECK_NE(relocatable, MAP_FAILED);
  VLOG_INFO(1, "Mapped corpus at ", HexStr(AsInt(relocatable)));
  auto mapped = MakeMmappedMemoryPtr<char>(reinterpret_cast<char*>(relocatable),
                                           file_size);

  SnapRelocatorError error;
  MmappedMemoryPtr<const SnapCorpus<Arch>> corpus =
      SnapRelocator<Arch>::RelocateCorpus(std::move(mapped), verify, &error);
  if (error != SnapRelocatorError::kOk) {
    LOG_FATAL("Failed to relocate corpus code=", IntStr(ToInt(error)));
  }
  VLOG_INFO(1, "Corpus size (snapshots) ", IntStr(corpus->snaps.size));

  // Return the fd if it was requested.
  if (corpus_fd != nullptr) {
    *corpus_fd = fd;
  } else {
    CHECK_EQ(close(fd), 0);
  }
  return corpus;
}

template MmappedMemoryPtr<const SnapCorpus<X86_64>> LoadCorpusFromFile<X86_64>(
    const char* filename, bool preload, bool verify, int* corpus_fd);

template MmappedMemoryPtr<const SnapCorpus<AArch64>>
LoadCorpusFromFile<AArch64>(const char* filename, bool preload, bool verify,
                            int* corpus_fd);

ArchitectureId CorpusFileArchitecture(const char* filename) {
  ArchitectureId arch = ArchitectureId::kUndefined;
  int fd = open(filename, O_RDONLY);
  if (fd == -1) {
    LOG_FATAL("Failed to open corpus file ", filename, ": ", ErrnoStr(errno));
  }

  SnapCorpusHeader header;
  int bytes_read = read(fd, &header, sizeof(header));
  if (bytes_read == sizeof(header)) {
    if (header.magic == kSnapCorpusMagic) {
      arch = static_cast<ArchitectureId>(header.architecture_id);
    }
  }
  close(fd);
  return arch;
}

}  // namespace silifuzz
