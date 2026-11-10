/** Copyright 2020 Alibaba Group Holding Limited.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#pragma once

#include <cstring>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <vector>

#include "neug/utils/property/types.h"

namespace neug {

class OutArchive {
 public:
  OutArchive() : begin_(NULL), end_(NULL) {}
  explicit OutArchive(size_t size)
      : buffer_(size), begin_(buffer_.data()), end_(begin_ + size) {}
  OutArchive(OutArchive&& oa) {
    buffer_ = std::move(oa.buffer_);
    begin_ = oa.begin_;
    end_ = oa.end_;

    oa.begin_ = NULL;
    oa.end_ = NULL;
  }

  ~OutArchive() {}

  OutArchive& operator=(OutArchive&& oa) {
    buffer_ = std::move(oa.buffer_);
    begin_ = oa.begin_;
    end_ = oa.end_;

    oa.begin_ = NULL;
    oa.end_ = NULL;
    return *this;
  }

  inline void Clear() {
    buffer_.clear();
    begin_ = NULL;
    end_ = NULL;
  }

  inline void Allocate(size_t size) {
    buffer_.resize(size);
    begin_ = buffer_.data();
    end_ = begin_ + static_cast<ptrdiff_t>(size);
  }

  inline void Rewind() { begin_ = buffer_.data(); }

  inline void SetSlice(char* buffer, size_t size) {
    buffer_.clear();
    begin_ = buffer;
    end_ = begin_ + size;
  }

  inline void SetSlice(const char* buffer, size_t size) {
    SetSlice(const_cast<char*>(buffer), size);
  }

  inline char* GetBuffer() { return begin_; }

  inline const char* GetBuffer() const { return begin_; }

  inline size_t GetSize() const { return end_ - begin_; }

  inline bool Empty() const { return begin_ == end_; }

  /// Bytes left to read.
  inline size_t Remaining() const { return static_cast<size_t>(end_ - begin_); }

  /// Fail with std::out_of_range when fewer than `size` bytes remain.
  /// Serialized data (WAL records, checkpoints, wire payloads) may be
  /// truncated or corrupted; an unchecked cursor would read past the buffer
  /// and turn a recoverable error into a crash.
  inline void Require(size_t size) const {
    if (size > Remaining()) {
      throw std::out_of_range(
          "OutArchive: truncated or corrupted input (need " +
          std::to_string(size) + " bytes, " + std::to_string(Remaining()) +
          " remaining)");
    }
  }

  inline void* GetBytes(size_t size) {
    Require(size);
    char* ret = begin_;
    begin_ += size;
    return ret;
  }

  template <typename T>
  inline void Peek(T& value) {
    char* old_begin = begin_;
    *this >> value;
    begin_ = old_begin;
  }

 private:
  std::vector<char> buffer_;
  char* begin_;
  char* end_;
};

template <typename T,
          typename std::enable_if<std::is_pod<T>::value, T>::type* = nullptr>
inline OutArchive& operator>>(OutArchive& out_archive, T& u) {
  u = *reinterpret_cast<T*>(out_archive.GetBytes(sizeof(T)));
  return out_archive;
}

inline OutArchive& operator>>(OutArchive& out_archive, EmptyType&) {
  return out_archive;
}

inline OutArchive& operator>>(OutArchive& out_archive, std::string& s) {
  size_t size;
  out_archive >> size;
  // Bounds-check before allocating so a corrupted length cannot request an
  // arbitrarily large buffer.
  const char* data = static_cast<const char*>(out_archive.GetBytes(size));
  s.assign(data, size);
  return out_archive;
}

inline OutArchive& operator>>(OutArchive& out_archive, std::string_view& s) {
  size_t size;
  out_archive >> size;
  const char* data = reinterpret_cast<const char*>(out_archive.GetBytes(size));
  s = std::string_view(data, size);
  return out_archive;
}

template <typename T,
          typename std::enable_if<std::is_pod<T>::value, T>::type* = nullptr>
inline OutArchive& operator>>(OutArchive& out_archive, std::vector<T>& vec) {
  size_t size;
  out_archive >> size;
  if (size > out_archive.Remaining() / sizeof(T)) {
    out_archive.Require(static_cast<size_t>(-1));  // throws: corrupt count
  }
  vec.resize(size);
  if (size > 0) {
    if constexpr (std::is_same_v<T, bool>) {
      // Special handling for vector<bool>
      for (size_t i = 0; i < size; ++i) {
        bool val = *reinterpret_cast<bool*>(out_archive.GetBytes(sizeof(bool)));
        vec[i] = val;
      }
      return out_archive;
    } else {
      memcpy(&vec[0], out_archive.GetBytes(sizeof(T) * size), sizeof(T) * size);
    }
  }
  return out_archive;
}

template <typename T,
          typename std::enable_if<!std::is_pod<T>::value, T>::type* = nullptr>
inline OutArchive& operator>>(OutArchive& out_archive, std::vector<T>& vec) {
  size_t size;
  out_archive >> size;
  // Every element consumes at least one byte, so a count larger than the
  // remaining input is necessarily corrupt.
  if (size > out_archive.Remaining()) {
    out_archive.Require(size);
  }
  vec.resize(size);
  for (size_t i = 0; i < size; ++i) {
    out_archive >> vec[i];
  }
  return out_archive;
}

template <typename... Args>
inline OutArchive& operator>>(OutArchive& out_archive,
                              std::tuple<Args...>& tup) {
  std::apply([&out_archive](Args&... args) { (out_archive >> ... >> args); },
             tup);
  return out_archive;
}

}  // namespace neug
