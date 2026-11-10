/** Copyright 2020 Alibaba Group Holding Limited.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * 	http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "neug/transaction/wal/local_wal_parser.h"

#include <fcntl.h>
#ifndef _WIN32
#include <sys/mman.h>
#include <unistd.h>
#else
#include <io.h>
#endif
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <ostream>

#include <glog/logging.h>

#include "neug/transaction/wal/wal.h"
#include "neug/utils/crc32c.h"
#include "neug/utils/exception/exception.h"
#include "neug/utils/io/file/file_utils.h"

namespace neug {

LocalWalParser::LocalWalParser(const std::string& wal_uri) {
  LocalWalParser::open(wal_uri);
}

void LocalWalParser::open(const std::string& wal_uri) {
  close();
  auto wal_dir = get_wal_uri_path(wal_uri);
  if (!std::filesystem::exists(wal_dir)) {
    std::filesystem::create_directory(wal_dir);
  }

  std::vector<std::string> paths;
  for (const auto& entry : std::filesystem::directory_iterator(wal_dir)) {
    paths.push_back(entry.path().string());
  }
  for (auto path : paths) {
    size_t file_size = std::filesystem::file_size(path);
    if (file_size == 0) {
      continue;
    }
#ifdef _WIN32
    // WAL is a binary format: keep the descriptor untranslated so any CRT
    // reads preserve CRLF and CTRL+Z rather than treating them as text/EOF.
    int fd = _open(path.c_str(), O_RDONLY | _O_BINARY, 0);
#else
    int fd = ::open(path.c_str(), O_RDONLY);
#endif
    if (fd == -1) {
      close();
      THROW_IO_EXCEPTION("Failed to open wal file: " + path + ": " +
                         strerror(errno));
    }
    void* mmapped_buffer =
        ::mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mmapped_buffer == MAP_FAILED) {
#ifdef _WIN32
      _close(fd);
#else
      ::close(fd);
#endif
      close();
      THROW_IO_EXCEPTION("Failed to mmap wal file: " + path + ": " +
                         strerror(errno));
    }

    fds_.push_back(fd);
    paths_.push_back(path);
    mmapped_ptrs_.push_back(mmapped_buffer);
    mmapped_size_.push_back(file_size);
  }

  insert_wal_list_.resize(4096);
  for (size_t i = 0; i < mmapped_ptrs_.size(); ++i) {
    char* const begin = static_cast<char*>(mmapped_ptrs_[i]);
    char* const end = begin + mmapped_size_[i];
    uint32_t first_word = 0;
    if (mmapped_size_[i] >= sizeof(first_word)) {
      std::memcpy(&first_word, begin, sizeof(first_word));
    }
    if (first_word == kWalFrameMagic) {
      parseFramedFile(begin, end, paths_[i]);
    } else {
      parseLegacyFile(begin, end, paths_[i]);
    }
  }

  if (!update_wal_list_.empty()) {
    std::sort(update_wal_list_.begin(), update_wal_list_.end(),
              [](const UpdateWalUnit& lhs, const UpdateWalUnit& rhs) {
                return lhs.timestamp < rhs.timestamp;
              });
  }
}

void LocalWalParser::close() {
  insert_wal_list_.clear();
  size_t ptr_num = mmapped_ptrs_.size();
  for (size_t i = 0; i < ptr_num; ++i) {
    munmap(mmapped_ptrs_[i], mmapped_size_[i]);
  }
  for (auto fd : fds_) {
#ifdef _WIN32
    _close(fd);
#else
    ::close(fd);
#endif
  }
  fds_.clear();
  paths_.clear();
  mmapped_ptrs_.clear();
  mmapped_size_.clear();
  update_wal_list_.clear();
  last_ts_ = 0;
}

bool LocalWalParser::registerRecord(const WalHeader& header, char* payload,
                                    size_t payload_length,
                                    const std::string& path) {
  const uint32_t ts = header.timestamp;
  if (header.type) {
    UpdateWalUnit unit;
    unit.timestamp = ts;
    unit.ptr = payload;
    unit.size = payload_length;
    update_wal_list_.push_back(unit);
  } else {
    if (ts >= insert_wal_list_.size()) {
      insert_wal_list_.resize(static_cast<size_t>(ts) + 1);
    }
    insert_wal_list_[ts].ptr = payload;
    insert_wal_list_[ts].size = payload_length;
  }
  last_ts_ = std::max(ts, last_ts_);
  return true;
}

void LocalWalParser::parseFramedFile(char* begin, char* end,
                                     const std::string& path) {
  char* ptr = begin;
  size_t records = 0;
  while (static_cast<size_t>(end - ptr) >= sizeof(WalFrameHeader)) {
    WalFrameHeader frame;
    std::memcpy(&frame, ptr, sizeof(frame));
    if (frame.magic == 0) {
      break;  // clean end of log (zeroed terminator / preallocated space)
    }
    const size_t offset = static_cast<size_t>(ptr - begin);
    if (frame.magic != kWalFrameMagic) {
      LOG(WARNING) << "WAL " << path << ": bad frame magic at offset " << offset
                   << " after " << records
                   << " records; treating the rest as a torn tail";
      break;
    }
    char* payload = ptr + sizeof(WalFrameHeader);
    const size_t remaining = static_cast<size_t>(end - payload);
    if (frame.payload_length < sizeof(WalHeader) ||
        frame.payload_length > remaining) {
      LOG(WARNING) << "WAL " << path << ": record at offset " << offset
                   << " has invalid length " << frame.payload_length
                   << "; treating the rest as a torn tail";
      break;
    }
    const uint32_t crc = Crc32c::Extend(
        Crc32c::Compute(&frame.payload_length, sizeof(frame.payload_length)),
        payload, frame.payload_length);
    if (crc != frame.crc32c) {
      LOG(WARNING) << "WAL " << path << ": checksum mismatch at offset "
                   << offset << " after " << records
                   << " records; discarding the uncommitted tail";
      break;
    }
    WalHeader header;
    std::memcpy(&header, payload, sizeof(header));
    const size_t body_length = frame.payload_length - sizeof(WalHeader);
    if (header.timestamp == 0 || header.length != body_length) {
      LOG(ERROR) << "WAL " << path << ": inconsistent record header at offset "
                 << offset << "; stopping replay of this file";
      break;
    }
    if (!registerRecord(header, payload + sizeof(WalHeader), body_length,
                        path)) {
      break;
    }
    ++records;
    ptr = payload + frame.payload_length;
  }
}

void LocalWalParser::parseLegacyFile(char* begin, char* end,
                                     const std::string& path) {
  // Pre-checksum format: [WalHeader][body]... terminated by a zero header.
  // It cannot detect torn records, but every access is bounds-checked so a
  // damaged file stops replay instead of reading past the mapping.
  char* ptr = begin;
  while (static_cast<size_t>(end - ptr) >= sizeof(WalHeader)) {
    WalHeader header;
    std::memcpy(&header, ptr, sizeof(header));
    if (header.timestamp == 0) {
      break;
    }
    char* body = ptr + sizeof(WalHeader);
    const size_t length = header.length;
    if (length > static_cast<size_t>(end - body)) {
      LOG(WARNING) << "WAL " << path << ": legacy record at offset "
                   << (ptr - begin) << " runs past end of file; stopping";
      break;
    }
    if (!registerRecord(header, body, length, path)) {
      break;
    }
    ptr = body + length;
  }
}

uint32_t LocalWalParser::last_ts() const { return last_ts_; }

const WalContentUnit& LocalWalParser::get_insert_wal(uint32_t ts) const {
  static const WalContentUnit kEmpty{};
  return ts < insert_wal_list_.size() ? insert_wal_list_[ts] : kEmpty;
}

const std::vector<UpdateWalUnit>& LocalWalParser::get_update_wals() const {
  return update_wal_list_;
}

const bool LocalWalParser::registered_ = WalParserFactory::RegisterWalParser(
    "file", static_cast<WalParserFactory::wal_parser_initializer_t>(
                &LocalWalParser::Make));

}  // namespace neug
