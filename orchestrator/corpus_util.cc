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

#include "./orchestrator/corpus_util.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <thread>  // NOLINT
#include <utility>
#include <vector>

#include "absl/cleanup/cleanup.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/cord.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "third_party/liblzma/lzma.h"
#include "./snap/snap.h"
#include "./snap/snap_checksum.h"
#include "./util/byte_io.h"
#include "./util/checks.h"
#include "./util/itoa.h"
#include "./util/owned_file_descriptor.h"
#include "./util/path_util.h"
#include "./util/span_util.h"

namespace silifuzz {

namespace {

// Writes data in `cord` to file with descriptor `fd` and returns status.
absl::Status WriteCord(const absl::Cord& cord, int fd) {
  for (const auto& chunk : cord.Chunks()) {
    if (Write(fd, chunk.data(), chunk.size()) != chunk.size()) {
      // Write() handles EINTR, so it is an error if it cannot complete.
      return absl::ErrnoToStatus(errno, "write()");
    }
  }
  return absl::OkStatus();
}

// Returns contents for file with descriptor `fd` as a Cord or a status.
// This reads starting from the current file offset.
absl::StatusOr<absl::Cord> ReadCord(int fd) {
  constexpr size_t kChunkSize = 1 << 20;  // 1MB
  std::string buffer(kChunkSize, 0);
  ssize_t bytes_read;
  absl::Cord cord;
  while ((bytes_read = Read(fd, buffer.data(), buffer.size())) > 0) {
    cord.Append(absl::string_view(buffer.data(), bytes_read));
  }
  if (bytes_read < 0) {
    // If Read() returns a negative number, there is an error.
    return absl::ErrnoToStatus(errno, "read()");
  }
  return cord;
}

// Returns the size of the file (in bytes) at `path` or an error status.
absl::StatusOr<off_t> GetFileSize(const std::string& path) {
  struct stat st;
  if (stat(path.c_str(), &st) != 0) {
    return absl::ErrnoToStatus(errno, absl::StrCat("stat() on ", path));
  }
  return st.st_size;
}

}  // namespace

absl::StatusOr<absl::Cord> ReadXzipFile(const std::string& path) {
  lzma_stream decompressed_stream = LZMA_STREAM_INIT;
  lzma_ret ret = lzma_stream_decoder(
      &decompressed_stream, lzma_easy_decoder_memusage(9 /* level */), 0);
  if (ret != LZMA_OK) {
    return absl::InternalError(
        absl::StrCat("Failed to initialize decoder, return code =", ret));
  }

  constexpr size_t kInputChunkSize = 1 << 20;
  std::vector<uint8_t> input_buffer(kInputChunkSize);

  constexpr size_t kOutputChunkSize = 1 << 20;
  std::vector<uint8_t> output_buffer(kOutputChunkSize);
  decompressed_stream.avail_out = output_buffer.size();
  decompressed_stream.next_out = output_buffer.data();

  const int input_fd = open(path.c_str(), O_RDONLY);
  absl::Cleanup clean_up([&decompressed_stream, input_fd]() {
    lzma_end(&decompressed_stream);
    if (input_fd >= 0) {
      close(input_fd);
    }
  });

  if (input_fd < 0) {
    return absl::InternalError(
        absl::StrCat("Failed to open compressed file ", path));
  }

  absl::Cord decompressed_data;
  bool input_eof_seen = false;
  do {
    // Refill input buffer if empty.
    if (decompressed_stream.avail_in == 0 && !input_eof_seen) {
      const ssize_t bytes_read =
          Read(input_fd, input_buffer.data(), input_buffer.size());
      if (bytes_read > 0) {
        decompressed_stream.avail_in = bytes_read;
        decompressed_stream.next_in = input_buffer.data();
      } else {
        if (bytes_read == 0) {
          input_eof_seen = true;
        } else {
          return absl::InternalError(
              absl::StrCat("Failed to read compressed file ", path));
        }
      }
    }

    ret = lzma_code(&decompressed_stream,
                    input_eof_seen ? LZMA_FINISH : LZMA_RUN);

    // Append data to cord if output buffer is full or if decompressed stream
    // ends.
    if (decompressed_stream.avail_out == 0 || ret == LZMA_STREAM_END) {
      absl::string_view chunk(
          reinterpret_cast<char*>(output_buffer.data()),
          output_buffer.size() - decompressed_stream.avail_out);
      decompressed_data.Append(chunk);
      decompressed_stream.avail_out = output_buffer.size();
      decompressed_stream.next_out = output_buffer.data();
    }
  } while (ret == LZMA_OK);

  if (ret != LZMA_STREAM_END) {
    return absl::InternalError(absl::StrCat("Failed to decompress data ", path,
                                            ", lzma code = ", ret));
  }

  off_t consumed_size = lseek(input_fd, 0, SEEK_CUR);
  if (consumed_size == (off_t)-1) {
    return absl::InternalError(
        absl::StrCat("Could not determine current position in ", path));
  }
  off_t total_size = lseek(input_fd, 0, SEEK_END);
  if (total_size == (off_t)-1) {
    return absl::InternalError(
        absl::StrCat("Could not determine size of ", path));
  }

  // Decompressor may not have consumed every byte we read.
  consumed_size -= decompressed_stream.avail_in;

  // If decompression did not consume the entire file, the file is likely
  // corrupt in some way that the decompressor did not notice.
  if (consumed_size != total_size) {
    return absl::InternalError(
        absl::StrCat("Decompression did not consume every byte of ", path,
                     ", remaining bytes = ", total_size - consumed_size));
  }

  // Data looks OK.
  return decompressed_data;
}

absl::StatusOr<OwnedFileDescriptor> WriteSharedMemoryFile(
    const absl::Cord& contents, absl::string_view name) {
  int memfd = memfd_create(std::string(name).c_str(),
                           O_RDWR | MFD_ALLOW_SEALING | MFD_CLOEXEC);
  if (memfd == -1) {
    return absl::ErrnoToStatus(errno, "memfd_create()");
  }
  OwnedFileDescriptor owned_fd(memfd);
  int fd = owned_fd.borrow();
  RETURN_IF_NOT_OK(WriteCord(contents, fd));

  // Seal file after write to prevent modification of its contents and seals.
  // There appears to be a kernel bug that happens with large enough number of
  // concurrent threads calling fcntl(2). The bug manifests as fcntl returning
  // errno=EBUSY when passed F_SEAL_WRITE.
  if (fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW) != 0) {
    return absl::ErrnoToStatus(errno,
                               absl::StrCat("fcntl(F_ADD_SEALS): ", name));
  }

  // Move file descriptor to beginning of file.
  if (lseek(fd, 0, SEEK_SET) != 0) {
    return absl::ErrnoToStatus(errno, "lseek()");
  }

  return owned_fd;
}

std::string FilePathForFD(const OwnedFileDescriptor& fd) {
  return absl::StrCat("/proc/", getpid(), "/fd/", fd.borrow());
}

constexpr const absl::string_view kXzExtension = ".xz";

absl::StatusOr<InMemoryShard> LoadCorpus(const std::string& path) {
  std::string name = absl::StrCat(Basename(path));

  absl::Cord contents;
  if (absl::EndsWith(path, kXzExtension)) {
    // Clip .xz the extension from the file name.
    name = name.substr(0, name.size() - kXzExtension.size());
    ASSIGN_OR_RETURN_IF_NOT_OK(contents, ReadXzipFile(path));
  } else {
    // Assume this is an uncompressed corpus.
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) {
      return absl::ErrnoToStatus(errno, absl::StrCat("open(): ", path));
    }
    absl::Cleanup file_closer = absl::MakeCleanup([fd] { close(fd); });
    ASSIGN_OR_RETURN_IF_NOT_OK(contents, ReadCord(fd));
  }

  // Will be truncated if the contents are too short.
  std::string header_bytes(contents.Subcord(0, sizeof(SnapCorpusHeader)));

  // Calculate checksum.
  CorpusChecksumCalculator checksum;
  for (absl::string_view chunk : contents.Chunks()) {
    checksum.AddData(chunk);
  }

  // Set linked name in /proc/self/fd/ for ease of debugging.
  ASSIGN_OR_RETURN_IF_NOT_OK(OwnedFileDescriptor owned_fd,
                             WriteSharedMemoryFile(contents, name));

  std::string file_path = FilePathForFD(owned_fd);

  return InMemoryShard{
      .file_descriptor = std::move(owned_fd),
      .file_path = std::move(file_path),
      .name = std::move(name),
      .header_bytes = std::move(header_bytes),
      .file_size = contents.size(),
      .checksum = checksum.Checksum(),
  };
}

absl::StatusOr<uint64_t> EstimateLargestCorpusSizeMB(
    const std::vector<std::string>& corpus_paths) {
  CHECK(!corpus_paths.empty());
  int largest_path_idx = 0;
  ASSIGN_OR_RETURN_IF_NOT_OK(off_t largest_size, GetFileSize(corpus_paths[0]));
  for (int i = 1; i < corpus_paths.size(); ++i) {
    ASSIGN_OR_RETURN_IF_NOT_OK(off_t size, GetFileSize(corpus_paths[i]));
    if (size > largest_size) {
      largest_path_idx = i;
      largest_size = size;
    }
  }
  ASSIGN_OR_RETURN_IF_NOT_OK(InMemoryShard shard,
                             LoadCorpus(corpus_paths[largest_path_idx]));
  // Round up to 1 meg.
  return static_cast<uint64_t>(
      std::ceil(static_cast<double>(shard.file_size) / (1024 * 1024)));
}

absl::StatusOr<InMemoryCorpora> LoadCorpora(
    const std::vector<std::string>& corpus_paths) {
  // Cannot use construct owner_fds(size, init_value) because element type is
  // not copyable.
  std::vector<absl::StatusOr<InMemoryShard>> shards(corpus_paths.size());
  std::generate(shards.begin(), shards.end(),
                []() { return absl::UnknownError("LoadCorpora"); });
  size_t num_threads = std::min<size_t>(std::thread::hardware_concurrency(),
                                        corpus_paths.size());
  CHECK_GT(num_threads, 0);

  // Thread function to load a portion of corpus_paths and store
  // results in the corresponding portion of owned_fds.
  auto load_corpus_span =
      [](absl::Span<const std::string> corpus_paths,
         absl::Span<absl::StatusOr<InMemoryShard>> results) {
        CHECK_EQ(corpus_paths.size(), results.size());
        for (size_t i = 0; i < corpus_paths.size(); ++i) {
          results[i] = LoadCorpus(corpus_paths[i]);
        }
      };

  // Distribute corpus paths evenly over corpus loader threads.
  std::vector<std::thread> loader_threads;
  auto corpus_path_spans = PartitionEvenly(corpus_paths, num_threads);
  auto shard_spans = PartitionEvenly(shards, num_threads);
  loader_threads.reserve(num_threads);
  for (size_t i = 0; i < num_threads; ++i) {
    loader_threads.emplace_back(load_corpus_span, corpus_path_spans[i],
                                shard_spans[i]);
  }

  for (auto& thread : loader_threads) {
    CHECK(thread.joinable());
    thread.join();
  }

  InMemoryCorpora result;
  result.shards.reserve(shards.size());
  for (size_t i = 0; i < corpus_paths.size(); ++i) {
    RETURN_IF_NOT_OK(shards[i].status());
    VLOG_INFO(1, "Loaded corpus ", shards[i]->name, " as ",
              shards[i]->file_path);
    result.shards.push_back(std::move(*shards[i]));
  }
  return result;
}

absl::Status ValidateShard(const InMemoryShard& shard) {
  if (shard.file_size < sizeof(SnapCorpusHeader)) {
    return absl::OutOfRangeError(absl::StrCat(
        "Shard ", shard.name, " is too small to be a valid corpus"));
  }
  if (shard.header_bytes.size() != sizeof(SnapCorpusHeader)) {
    return absl::InternalError(
        absl::StrCat("Shard ", shard.name,
                     " - failed to capture the corpus header, somehow"));
  }
  const SnapCorpusHeader& header =
      *reinterpret_cast<const SnapCorpusHeader*>(shard.header_bytes.data());
  // Likely not a corpus file if the magic is wrong.
  if (header.magic != kSnapCorpusMagic) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Shard ", shard.name, " has bad magic: ", HexStr(header.magic)));
  }
  // Likely a version mismatch if the header size is wrong.
  if (header.header_size != sizeof(SnapCorpusHeader)) {
    return absl::InvalidArgumentError(absl::StrCat(
        "Shard ", shard.name, " header size should be ",
        sizeof(SnapCorpusHeader), " but it is ", header.header_size));
  }
  // Likely file corruption if the size is wrong.
  if (header.num_bytes != shard.file_size) {
    return absl::InvalidArgumentError(
        absl::StrCat("Shard ", shard.name, " should be ", header.num_bytes,
                     " bytes but is ", shard.file_size, " bytes"));
  }
  // Likely file corruption if the checksum is wrong.
  if (header.checksum != shard.checksum) {
    return absl::DataLossError(absl::StrCat(
        "Shard ", shard.name, " should have checksum ", HexStr(header.checksum),
        " but it is ", HexStr(shard.checksum)));
  }
  return absl::OkStatus();
}

absl::Status ValidateCorpus(const InMemoryCorpora& corpora) {
  size_t error_count = 0;
  size_t shard_count = 0;
  for (const InMemoryShard& shard : corpora.shards) {
    absl::Status s = ValidateShard(shard);
    if (!s.ok()) {
      LOG_ERROR(s.message());
      ++error_count;
    }
    ++shard_count;
  }
  if (error_count) {
    return absl::InternalError(absl::StrCat("Failed to validate ", error_count,
                                            "/", shard_count,
                                            " corpus shards"));
  }
  return absl::OkStatus();
}

}  // namespace silifuzz
