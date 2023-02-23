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

#include <memory>
#include <utility>

#include "./snap/snap_relocator.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/misc_util.h"

namespace silifuzz {

MmappedMemoryPtr<const SnapCorpus> LoadCorpusFromFile(const char* filename,
                                                      bool preload,
                                                      int* corpus_fd) {
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
  CHECK_NE(fd, -1);
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
  SnapRelocator::Error error;
  MmappedMemoryPtr<const SnapCorpus> corpus =
      SnapRelocator::RelocateCorpus(std::move(mapped), &error);
  CHECK(error == SnapRelocator::Error::kOk);
  VLOG_INFO(1, "Corpus size (snapshots) ", IntStr(corpus->snaps.size));

  // Return the fd if it was requested.
  if (corpus_fd != nullptr) {
    *corpus_fd = fd;
  } else {
    CHECK_EQ(close(fd), 0);
  }
  return corpus;
}

}  // namespace silifuzz
