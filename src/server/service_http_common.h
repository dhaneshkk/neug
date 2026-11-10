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

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

#include "neug/main/query_request.h"
#include "neug/main/query_result.h"
#include "neug/server/tp_operations.h"
#include "neug/utils/result.h"

namespace neug {
namespace service_http {

// HTTP status mapping shared by the BRPC and cpp-httplib transports. The
// values are standard HTTP codes; brpc's HTTP_STATUS_* constants expand to
// exactly these numbers, so both transports answer with identical statuses.
inline int32_t status_code_to_http_code(StatusCode code) {
  switch (code) {
  case StatusCode::OK:
    return 200;
  case StatusCode::ERR_PERMISSION:
    return 403;
  case StatusCode::ERR_DATABASE_LOCKED:
    return 503;
  case StatusCode::ERR_NOT_SUPPORTED:
    return 501;
  case StatusCode::ERR_NOT_IMPLEMENTED:
    return 501;
  case StatusCode::ERR_QUERY_SYNTAX:
    return 400;
  case StatusCode::ERR_NOT_INITIALIZED:
    return 500;
  case StatusCode::ERR_QUERY_EXECUTION:
    return 500;
  case StatusCode::ERR_INTERNAL_ERROR:
    return 500;
  case StatusCode::ERR_NOT_FOUND:
    return 404;
  case StatusCode::ERR_NO_CHECKPOINT:
    return 404;
  case StatusCode::ERR_INVALID_ARGUMENT:
    return 400;
  case StatusCode::ERR_COMPILATION:
    return 500;
  case StatusCode::ERR_SERVICE_UNAVAILABLE:
    return 503;
  case StatusCode::ERR_TX_STATE_CONFLICT:
    return 409;
  case StatusCode::ERR_TX_TIMEOUT:
  case StatusCode::ERR_TX_NOT_FOUND:
    return 410;
  default:
    return 500;
  }
}

// ---------------------------------------------------------------------------
// Request admission checks shared by the BRPC and cpp-httplib transports.
//
// The service accepts arbitrary Cypher (including INSTALL/LOAD/COPY), so a
// request must not be forgeable by a web page the operator happens to visit:
//  * Browsers attach an Origin header to every cross-origin (and every POST)
//    request. Requests carrying an Origin are rejected unless that origin is
//    listed in NEUG_HTTP_ALLOWED_ORIGINS (comma-separated). Native clients
//    (Python/Node/Java SDKs, curl) send no Origin and are unaffected. This
//    also blocks DNS-rebinding POSTs, which carry the attacker's origin.
//  * "Simple" CORS content types (text/plain, form encodings) that a page can
//    send without a preflight are refused with 415 on POST bodies.
//  * If NEUG_HTTP_AUTH_TOKEN is set, every request must present
//    "Authorization: Bearer <token>".
// ---------------------------------------------------------------------------

struct HttpRequestHeaders {
  std::string_view method;
  const std::string* origin = nullptr;
  const std::string* content_type = nullptr;
  const std::string* authorization = nullptr;
  bool has_body = false;
};

struct HttpRejection {
  int http_code;
  std::string message;
};

inline std::string AsciiLowerTrim(std::string_view in) {
  size_t b = 0, e = in.size();
  while (b < e && std::isspace(static_cast<unsigned char>(in[b]))) {
    ++b;
  }
  while (e > b && std::isspace(static_cast<unsigned char>(in[e - 1]))) {
    --e;
  }
  std::string out(in.substr(b, e - b));
  std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  return out;
}

inline std::vector<std::string> SplitEnvList(const char* env_name) {
  std::vector<std::string> items;
  const char* raw = std::getenv(env_name);
  if (raw == nullptr) {
    return items;
  }
  std::stringstream ss(raw);
  std::string item;
  while (std::getline(ss, item, ',')) {
    auto norm = AsciiLowerTrim(item);
    while (!norm.empty() && norm.back() == '/') {
      norm.pop_back();
    }
    if (!norm.empty()) {
      items.push_back(std::move(norm));
    }
  }
  return items;
}

inline bool ConstantTimeEquals(std::string_view a, std::string_view b) {
  unsigned char diff = static_cast<unsigned char>(a.size() != b.size());
  const size_t n = std::max(a.size(), b.size());
  for (size_t i = 0; i < n; ++i) {
    const unsigned char ca =
        i < a.size() ? static_cast<unsigned char>(a[i]) : 0;
    const unsigned char cb =
        i < b.size() ? static_cast<unsigned char>(b[i]) : 0;
    diff |= static_cast<unsigned char>(ca ^ cb);
  }
  return diff == 0;
}

inline std::optional<HttpRejection> CheckRequestAdmission(
    const HttpRequestHeaders& req) {
  // Configuration is read per request so tests and operators can change it
  // without restarting; the cost is negligible next to query execution.
  if (const char* token = std::getenv("NEUG_HTTP_AUTH_TOKEN");
      token != nullptr && *token != '\0') {
    const std::string expected = std::string("Bearer ") + token;
    if (req.authorization == nullptr ||
        !ConstantTimeEquals(*req.authorization, expected)) {
      return HttpRejection{401, "Missing or invalid bearer token."};
    }
  }
  if (req.origin != nullptr && !req.origin->empty()) {
    auto origin = AsciiLowerTrim(*req.origin);
    while (!origin.empty() && origin.back() == '/') {
      origin.pop_back();
    }
    const auto allowed = SplitEnvList("NEUG_HTTP_ALLOWED_ORIGINS");
    if (std::find(allowed.begin(), allowed.end(), origin) == allowed.end()) {
      return HttpRejection{403, "Cross-origin request rejected (origin '" +
                                    *req.origin +
                                    "' is not in NEUG_HTTP_ALLOWED_ORIGINS)."};
    }
  }
  if (req.method == "POST" && req.has_body && req.content_type != nullptr) {
    auto media = AsciiLowerTrim(std::string_view(*req.content_type)
                                    .substr(0, req.content_type->find(';')));
    if (media == "text/plain" || media == "application/x-www-form-urlencoded" ||
        media == "multipart/form-data") {
      return HttpRejection{415, "Unsupported Content-Type '" +
                                    *req.content_type +
                                    "'; send application/json."};
    }
  }
  return std::nullopt;
}

inline size_t MaxRequestBodyBytes() {
  constexpr size_t kDefault = size_t{256} << 20;  // 256 MiB
  const char* raw = std::getenv("NEUG_HTTP_MAX_BODY_BYTES");
  if (raw == nullptr || *raw == '\0') {
    return kDefault;
  }
  char* end = nullptr;
  const unsigned long long v = std::strtoull(raw, &end, 10);
  return (end != raw && v > 0) ? static_cast<size_t>(v) : kDefault;
}

inline result<std::string_view> TransactionIdFromPath(
    std::string_view transaction_id) {
  if (transaction_id.empty() || transaction_id.find('/') != std::string::npos) {
    RETURN_ERROR(Status(StatusCode::ERR_INVALID_ARGUMENT,
                        "A transaction ID is required in the request path."));
  }
  return transaction_id;
}

inline std::string FormatExpiresAt(
    std::chrono::system_clock::time_point expires_at) {
  const auto epoch_milliseconds =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          expires_at.time_since_epoch());
  const auto epoch_seconds =
      std::chrono::duration_cast<std::chrono::seconds>(epoch_milliseconds);
  const auto milliseconds = epoch_milliseconds - epoch_seconds;
  const auto time = static_cast<std::time_t>(epoch_seconds.count());
  std::tm utc_time{};
#ifdef _WIN32
  gmtime_s(&utc_time, &time);
#else
  gmtime_r(&time, &utc_time);
#endif
  char buffer[32];
  std::snprintf(buffer, sizeof(buffer), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
                utc_time.tm_year + 1900, utc_time.tm_mon + 1, utc_time.tm_mday,
                utc_time.tm_hour, utc_time.tm_min, utc_time.tm_sec,
                static_cast<int>(milliseconds.count()));
  return buffer;
}

inline std::string SerializeBeginResponse(
    const ServiceTransactionInfo& transaction, TransactionMode mode) {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
  writer.StartObject();
  writer.Key("transaction_id");
  writer.String(
      transaction.transaction_id.data(),
      static_cast<rapidjson::SizeType>(transaction.transaction_id.size()));
  writer.Key("mode");
  writer.String(mode == TransactionMode::kReadOnly ? "read_only"
                                                   : "read_write");
  writer.Key("expires_at");
  if (transaction.expires_at) {
    const auto expires_at = FormatExpiresAt(*transaction.expires_at);
    writer.String(expires_at.data(),
                  static_cast<rapidjson::SizeType>(expires_at.size()));
  } else {
    writer.Null();
  }
  writer.EndObject();
  return std::string(buffer.GetString(), buffer.GetSize());
}

inline result<TransactionMode> ParseTransactionMode(const std::string& body) {
  rapidjson::Document document;
  document.Parse(body.data(), body.size());
  if (document.HasParseError() || !document.IsObject() ||
      !document.HasMember("mode") || !document["mode"].IsString()) {
    RETURN_ERROR(Status(StatusCode::ERR_INVALID_ARGUMENT,
                        "Transaction begin requires a JSON mode."));
  }
  const std::string_view mode(document["mode"].GetString(),
                              document["mode"].GetStringLength());
  if (mode == "read_only") {
    return TransactionMode::kReadOnly;
  }
  if (mode == "read_write") {
    return TransactionMode::kReadWrite;
  }
  RETURN_ERROR(Status(StatusCode::ERR_INVALID_ARGUMENT,
                      "Transaction mode must be read_only or read_write."));
}

inline Status RequireEmptyBody(const std::string& body) {
  if (!body.empty()) {
    return Status(StatusCode::ERR_INVALID_ARGUMENT,
                  "This transaction operation does not accept a request body.");
  }
  return Status::OK();
}

inline result<std::string> SerializeQueryResult(
    result<QueryResult>&& query_result) {
  if (!query_result) {
    RETURN_ERROR(query_result.error());
  }
  try {
    return query_result.value().Serialize();
  } catch (const std::exception& e) {
    RETURN_ERROR(Status::RuntimeError(e.what()));
  }
}

template <typename Execute>
result<std::string> ParseAndExecuteQuery(const std::string& request,
                                         Execute&& execute) {
  auto parsed = RequestParser::ParseFromString(request);
  if (!parsed) {
    RETURN_ERROR(parsed.error());
  }
  return SerializeQueryResult(execute(parsed.value()));
}

}  // namespace service_http
}  // namespace neug
