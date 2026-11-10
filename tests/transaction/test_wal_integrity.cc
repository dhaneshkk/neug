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

// Fault-injection tests for WAL record integrity: checksummed framing,
// torn-tail handling, bounds-checked legacy parsing and archive decoding.

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "neug/transaction/wal/local_wal_parser.h"
#include "neug/transaction/wal/local_wal_writer.h"
#include "neug/transaction/wal/wal.h"
#include "neug/utils/crc32c.h"
#include "neug/utils/serialization/out_archive.h"

namespace {

std::vector<char> MakeRecord(uint32_t ts, uint32_t type,
                             const std::string& body) {
  neug::WalHeader header{};
  header.timestamp = ts;
  header.type = type;
  header.length = static_cast<uint32_t>(body.size());
  std::vector<char> record(sizeof(header) + body.size());
  std::memcpy(record.data(), &header, sizeof(header));
  std::memcpy(record.data() + sizeof(header), body.data(), body.size());
  return record;
}

class WalIntegrityTest : public ::testing::Test {
 protected:
  void SetUp() override {
    dir_ = std::filesystem::temp_directory_path() /
           ("neug_wal_integrity_" +
            std::to_string(
                std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(dir_);
  }
  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove_all(dir_, ec);
  }

  std::filesystem::path OnlyWalFile() const {
    std::filesystem::path found;
    for (const auto& e : std::filesystem::directory_iterator(dir_)) {
      found = e.path();
    }
    return found;
  }

  void WriteRecords(const std::vector<std::vector<char>>& records) {
    neug::LocalWalWriter writer(dir_.string(), 0);
    writer.open(dir_.string());
    for (const auto& r : records) {
      ASSERT_TRUE(writer.append(r.data(), r.size()));
    }
    writer.close();
  }

  // Overwrite `bytes` at `offset` in the single WAL file.
  void Patch(size_t offset, const std::string& bytes) {
    std::fstream f(OnlyWalFile(),
                   std::ios::binary | std::ios::in | std::ios::out);
    ASSERT_TRUE(f);
    f.seekp(static_cast<std::streamoff>(offset));
    f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  }

  std::filesystem::path dir_;
};

TEST(Crc32cTest, KnownVector) {
  // RFC 3720 / iSCSI test vector: CRC-32C("123456789") = 0xE3069283.
  const std::string data = "123456789";
  EXPECT_EQ(neug::Crc32c::Compute(data.data(), data.size()), 0xE3069283u);
}

TEST(WalHeaderTest, PortableLayout) {
  EXPECT_EQ(sizeof(neug::WalHeader), 8u);
  neug::WalHeader h{};
  h.timestamp = 7;
  h.type = 1;
  h.length = 0x7FFFFFFFu;
  EXPECT_EQ(h.length, 0x7FFFFFFFu);  // unsigned: never negative
  uint32_t word = 0;
  std::memcpy(&word, reinterpret_cast<const char*>(&h) + 4, 4);
  // bit 0 = type, bits 1..31 = length (the historic GCC/Clang layout).
  EXPECT_EQ(word & 1u, 1u);
  EXPECT_EQ(word >> 1, 0x7FFFFFFFu);
}

TEST_F(WalIntegrityTest, FramedRoundTrip) {
  WriteRecords({MakeRecord(1, 0, "alpha"), MakeRecord(2, 1, "beta-update"),
                MakeRecord(3, 0, "gamma")});
  neug::LocalWalParser parser(dir_.string());
  EXPECT_EQ(parser.last_ts(), 3u);
  const auto& a = parser.get_insert_wal(1);
  EXPECT_EQ(std::string(a.ptr, a.size), "alpha");
  const auto& c = parser.get_insert_wal(3);
  EXPECT_EQ(std::string(c.ptr, c.size), "gamma");
  ASSERT_EQ(parser.get_update_wals().size(), 1u);
  EXPECT_EQ(std::string(parser.get_update_wals()[0].ptr,
                        parser.get_update_wals()[0].size),
            "beta-update");
}

TEST_F(WalIntegrityTest, TornTailIsDiscardedNotReplayed) {
  const auto r1 = MakeRecord(1, 0, "committed");
  const auto r2 = MakeRecord(2, 0, "torn-record-body");
  WriteRecords({r1, r2});
  // Simulate a crash where record 2's frame reached disk but its body did not:
  // corrupt one body byte so the checksum no longer matches.
  const size_t frame = sizeof(neug::WalFrameHeader);
  const size_t r2_body = frame + r1.size() + frame + sizeof(neug::WalHeader);
  Patch(r2_body + 3, "\xFF");

  neug::LocalWalParser parser(dir_.string());
  EXPECT_EQ(parser.last_ts(), 1u);
  const auto& first = parser.get_insert_wal(1);
  EXPECT_EQ(std::string(first.ptr, first.size), "committed");
  EXPECT_EQ(parser.get_insert_wal(2).ptr, nullptr);
}

TEST_F(WalIntegrityTest, CorruptLengthDoesNotReadPastMapping) {
  WriteRecords({MakeRecord(1, 0, "ok"), MakeRecord(2, 0, "victim")});
  const size_t frame = sizeof(neug::WalFrameHeader);
  const size_t r2_frame = frame + sizeof(neug::WalHeader) + 2;
  // payload_length field of the second frame -> enormous
  Patch(r2_frame + 4, std::string("\xF0\xFF\xFF\x7F", 4));
  neug::LocalWalParser parser(dir_.string());
  EXPECT_EQ(parser.last_ts(), 1u);
}

TEST_F(WalIntegrityTest, WriterRejectsMismatchedHeaderLength) {
  auto record = MakeRecord(1, 0, "payload");
  neug::WalHeader bad{};
  bad.timestamp = 1;
  bad.length = 1000;  // does not match the actual body size
  std::memcpy(record.data(), &bad, sizeof(bad));
  neug::LocalWalWriter writer(dir_.string(), 0);
  writer.open(dir_.string());
  EXPECT_FALSE(writer.append(record.data(), record.size()));
  // Rejected before any file was created, so the transaction can abort.
  EXPECT_TRUE(std::filesystem::is_empty(dir_));
  writer.close();
}

TEST_F(WalIntegrityTest, LegacyUnframedFilesStillReplay) {
  std::vector<char> buf;
  for (auto& r : {MakeRecord(1, 0, "legacy-1"), MakeRecord(2, 0, "legacy-2")}) {
    buf.insert(buf.end(), r.begin(), r.end());
  }
  buf.resize(buf.size() + sizeof(neug::WalHeader), 0);  // terminator
  std::ofstream(dir_ / "thread_0_0.wal", std::ios::binary)
      .write(buf.data(), static_cast<std::streamsize>(buf.size()));
  neug::LocalWalParser parser(dir_.string());
  EXPECT_EQ(parser.last_ts(), 2u);
  const auto& u = parser.get_insert_wal(2);
  EXPECT_EQ(std::string(u.ptr, u.size), "legacy-2");
}

TEST_F(WalIntegrityTest, LegacyTruncatedRecordStopsSafely) {
  auto r = MakeRecord(1, 0, "0123456789");
  // Cut the file in the middle of the body (no terminator, no padding).
  std::ofstream(dir_ / "thread_0_0.wal", std::ios::binary)
      .write(r.data(), static_cast<std::streamsize>(r.size() - 4));
  neug::LocalWalParser parser(dir_.string());
  EXPECT_EQ(parser.last_ts(), 0u);
}

TEST_F(WalIntegrityTest, OutOfRangeTimestampLookupIsEmpty) {
  WriteRecords({MakeRecord(1, 0, "x")});
  neug::LocalWalParser parser(dir_.string());
  EXPECT_EQ(parser.get_insert_wal(1u << 30).ptr, nullptr);
}

TEST(OutArchiveBoundsTest, TruncatedInputThrows) {
  // A string whose declared length exceeds the remaining bytes.
  std::vector<char> buf(sizeof(size_t) + 3);
  const size_t declared = 1ull << 40;
  std::memcpy(buf.data(), &declared, sizeof(declared));
  neug::OutArchive arc;
  arc.SetSlice(buf.data(), buf.size());
  std::string s;
  EXPECT_THROW(arc >> s, std::out_of_range);

  neug::OutArchive arc2;
  arc2.SetSlice(buf.data(), 2);
  uint64_t v = 0;
  EXPECT_THROW(arc2 >> v, std::out_of_range);

  neug::OutArchive arc3;
  arc3.SetSlice(buf.data(), buf.size());
  std::vector<uint32_t> vec;
  EXPECT_THROW(arc3 >> vec, std::out_of_range);
}

}  // namespace
