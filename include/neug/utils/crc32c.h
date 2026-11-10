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

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace neug {

namespace crc32c_detail {

constexpr std::array<uint32_t, 256> MakeTable() {
  std::array<uint32_t, 256> table{};
  for (uint32_t i = 0; i < 256; ++i) {
    uint32_t c = i;
    for (int k = 0; k < 8; ++k) {
      c = (c & 1u) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1);
    }
    table[i] = c;
  }
  return table;
}

inline constexpr std::array<uint32_t, 256> kTable = MakeTable();

}  // namespace crc32c_detail

/// Portable table-driven CRC-32C (Castagnoli, reflected polynomial
/// 0x82F63B78). Used to detect torn or corrupted WAL records on recovery.
class Crc32c {
 public:
  static uint32_t Extend(uint32_t crc, const void* data, size_t length) {
    const auto* p = static_cast<const unsigned char*>(data);
    crc = ~crc;
    for (size_t i = 0; i < length; ++i) {
      crc = crc32c_detail::kTable[(crc ^ p[i]) & 0xFFu] ^ (crc >> 8);
    }
    return ~crc;
  }

  static uint32_t Compute(const void* data, size_t length) {
    return Extend(0, data, length);
  }
};

}  // namespace neug
