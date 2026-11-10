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

// Unit tests for the transport-independent HTTP admission checks that stop
// browser-forged (CSRF / DNS-rebinding) requests and enforce bearer auth.

#include <gtest/gtest.h>

#include <cstdlib>
#include <string>

#include "service_http_common.h"

namespace {

using neug::service_http::CheckRequestAdmission;
using neug::service_http::HttpRequestHeaders;

void SetEnv(const char* name, const char* value) {
#ifdef _WIN32
  _putenv_s(name, value ? value : "");
#else
  if (value) {
    setenv(name, value, 1);
  } else {
    unsetenv(name);
  }
#endif
}

class HttpAdmissionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SetEnv("NEUG_HTTP_AUTH_TOKEN", nullptr);
    SetEnv("NEUG_HTTP_ALLOWED_ORIGINS", nullptr);
  }
  void TearDown() override { SetUp(); }

  HttpRequestHeaders Post(const std::string* content_type = nullptr) {
    HttpRequestHeaders h;
    h.method = "POST";
    h.has_body = true;
    h.content_type = content_type;
    return h;
  }
};

TEST_F(HttpAdmissionTest, NativeClientWithoutOriginIsAdmitted) {
  EXPECT_FALSE(CheckRequestAdmission(Post()).has_value());
  const std::string json = "application/json; charset=utf-8";
  EXPECT_FALSE(CheckRequestAdmission(Post(&json)).has_value());
}

TEST_F(HttpAdmissionTest, BrowserOriginIsRejectedUnlessAllowed) {
  auto req = Post();
  const std::string origin = "https://evil.example";
  req.origin = &origin;
  auto rejected = CheckRequestAdmission(req);
  ASSERT_TRUE(rejected.has_value());
  EXPECT_EQ(rejected->http_code, 403);

  SetEnv("NEUG_HTTP_ALLOWED_ORIGINS",
         "https://console.example, https://EVIL.example/");
  EXPECT_FALSE(CheckRequestAdmission(req).has_value());
}

TEST_F(HttpAdmissionTest, SimpleCorsContentTypesAreRejected) {
  for (const char* ct : {"text/plain", "Text/Plain;charset=UTF-8",
                         "application/x-www-form-urlencoded",
                         "multipart/form-data; boundary=x"}) {
    SCOPED_TRACE(ct);
    const std::string content_type = ct;
    auto rejected = CheckRequestAdmission(Post(&content_type));
    ASSERT_TRUE(rejected.has_value());
    EXPECT_EQ(rejected->http_code, 415);
  }
}

TEST_F(HttpAdmissionTest, BearerTokenIsEnforcedWhenConfigured) {
  SetEnv("NEUG_HTTP_AUTH_TOKEN", "s3cret");
  auto req = Post();
  auto missing = CheckRequestAdmission(req);
  ASSERT_TRUE(missing.has_value());
  EXPECT_EQ(missing->http_code, 401);

  const std::string wrong = "Bearer nope";
  req.authorization = &wrong;
  ASSERT_TRUE(CheckRequestAdmission(req).has_value());

  const std::string right = "Bearer s3cret";
  req.authorization = &right;
  EXPECT_FALSE(CheckRequestAdmission(req).has_value());
}

TEST(HttpStatusMappingTest, PermissionAndLockAreNotInternalErrors) {
  EXPECT_EQ(neug::service_http::status_code_to_http_code(
                neug::StatusCode::ERR_PERMISSION),
            403);
  EXPECT_EQ(neug::service_http::status_code_to_http_code(
                neug::StatusCode::ERR_DATABASE_LOCKED),
            503);
}

}  // namespace
