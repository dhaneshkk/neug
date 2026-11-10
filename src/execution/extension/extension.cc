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

#ifndef NEUG_LITE
#error "NEUG_LITE must be defined by the build system"
#endif

#if !NEUG_LITE
#ifdef _WIN32
// Include Winsock before any header that might include windows.h.
#include <winsock2.h>
#endif

#ifndef _WIN32
#include <dlfcn.h>
#else
#include <windows.h>
#include <cstdio>
#include <string>
// Windows shims for POSIX dlopen/dlsym/dlclose/dlerror.
#define RTLD_NOW 0
#define RTLD_LOCAL 0
// dlerror() must mirror the POSIX contract: return nullptr unless the last
// dlopen/dlsym/dlclose failed, and return - then clear - the failure reason
// otherwise. Reading GetLastError() unconditionally reports stale codes left
// by unrelated APIs during DLL load (e.g. glog's environment lookups during
// static init leave error 203), which turns successful dlsym calls into
// spurious loader failures. The loader runs on a single thread, so a
// thread-local state slot faithfully models the per-thread POSIX state.
static thread_local DWORD dl_last_error = 0;
static thread_local bool dl_error_pending = false;

static inline void dl_record_failure(DWORD error) {
  dl_last_error = error;
  dl_error_pending = true;
}

static inline char* dlerror() {
  static thread_local char buf[256];
  if (!dl_error_pending) {
    return nullptr;
  }
  dl_error_pending = false;
  snprintf(buf, sizeof(buf), "Windows error code: %lu",
           static_cast<unsigned long>(dl_last_error));
  return buf;
}

// UTF-8 safe: LoadLibraryA interprets paths in the active ANSI code page, so
// non-ASCII install paths would fail. Convert to a wide string and use
// LoadLibraryW instead (mirrors the compiler-side loader).
static inline void* dlopen(const char* path, int) {
  if (path == nullptr) {
    dl_record_failure(ERROR_INVALID_PARAMETER);
    return nullptr;
  }
  int wlen = MultiByteToWideChar(CP_UTF8, 0, path, -1, nullptr, 0);
  if (wlen <= 0) {
    dl_record_failure(GetLastError());
    return nullptr;
  }
  std::wstring wpath(static_cast<size_t>(wlen), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath.data(), wlen);
  void* handle = LoadLibraryW(wpath.c_str());
  if (handle == nullptr) {
    dl_record_failure(GetLastError());
  }
  return handle;
}

static inline void* dlsym(void* handle, const char* name) {
  void* sym = reinterpret_cast<void*>(
      GetProcAddress(static_cast<HMODULE>(handle), name));
  if (sym == nullptr) {
    dl_record_failure(GetLastError());
  }
  return sym;
}

static inline int dlclose(void* handle) {
  BOOL freed = FreeLibrary(static_cast<HMODULE>(handle));
  if (!freed) {
    dl_record_failure(GetLastError());
  }
  return freed ? 0 : 1;
}
#endif

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#ifndef _WIN32
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/x509_vfy.h>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
#endif
#include "httplib.h"
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

#include "neug/compiler/common/string_format.h"
#include "neug/compiler/common/windows_utils.h"
#endif  // !NEUG_LITE

#include <glog/logging.h>

#include "neug/compiler/extension/extension_manager.h"
#include "neug/config.h"
#include "neug/execution/extension/extension.h"

namespace neug {

Status ExtensionManager::InstallExtension(const std::string& name,
                                          const std::string& repository) {
  std::lock_guard<std::mutex> lock(mutex_);
  return extension::install_extension(NormalizeExtensionName(name), repository);
}

Status ExtensionManager::UninstallExtension(const std::string& name) {
  std::lock_guard<std::mutex> lock(mutex_);
  return extension::uninstall_extension(NormalizeExtensionName(name));
}

#if !NEUG_LITE

namespace extension {

#ifdef _WIN32
// Read an environment variable from the live Win32 environment block.
//
// Node.js assigns process.env.* at runtime through SetEnvironmentVariableW,
// which updates the process environment block but NOT the MSVC CRT's _environ
// snapshot captured at startup. std::getenv (and _wgetenv) read that snapshot,
// so they miss values lib/binding.js sets just before loading the native addon
// -- notably NEUG_EXTENSION_HOME_PYENV, leaving the extension home to fall
// back to /tmp. GetEnvironmentVariableW reads the live block and observes
// those runtime assignments. See #1160.
static std::string getEnvVarFromWin32(const char* name) {
  std::wstring wname = common::WindowsUtils::utf8ToUnicode(name);
  DWORD len = GetEnvironmentVariableW(wname.c_str(), nullptr, 0);
  if (len == 0) {
    return std::string();  // not set
  }
  std::wstring buf(len, L'\0');
  DWORD got = GetEnvironmentVariableW(wname.c_str(), &buf[0], len);
  if (got == 0 || got >= len) {
    return std::string();
  }
  buf.resize(got);
  return common::WindowsUtils::unicodeToUTF8(buf.c_str());
}
#endif

// Extension names become directory names and file names, so only accept a
// conservative identifier alphabet. This rejects "..", path separators, NUL,
// drive prefixes and anything else that could escape the extension root.
static bool isValidExtensionName(const std::string& name) {
  if (name.empty() || name.size() > 64) {
    return false;
  }
  for (unsigned char c : name) {
    const bool ok =
        (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
    if (!ok) {
      return false;
    }
  }
  return true;
}

static Status validateExtensionName(const std::string& name) {
  if (!isValidExtensionName(name)) {
    return Status(StatusCode::ERR_INVALID_ARGUMENT,
                  "Invalid extension name '" + name +
                      "': names must be 1-64 characters of [a-z0-9_]");
  }
  return Status::OK();
}

static bool envFlagEnabled(const char* name) {
  const char* value = std::getenv(name);
  return value != nullptr &&
         (std::string(value) == "1" || std::string(value) == "true" ||
          std::string(value) == "TRUE");
}

// Per-user default extension home. The previous fallback was the
// world-writable /tmp, which let any local user plant a library that a later
// LOAD (or auto_load_extension) would execute in the database process.
static std::string getDefaultExtensionBase() {
#ifdef _WIN32
  std::string base = getEnvVarFromWin32("LOCALAPPDATA");
  if (!base.empty()) {
    return base + "\\neug";
  }
  return std::string();
#else
  const char* xdg = std::getenv("XDG_DATA_HOME");
  if (xdg && *xdg && xdg[0] == '/') {
    return std::string(xdg) + "/neug";
  }
  const char* home = std::getenv("HOME");
  if (home && *home) {
    return std::string(home) + "/.neug";
  }
  if (const passwd* pw = ::getpwuid(::geteuid()); pw && pw->pw_dir) {
    return std::string(pw->pw_dir) + "/.neug";
  }
  return std::string();
#endif
}

static std::string getExtensionRootDir() {
  std::string base;
#ifdef _WIN32
  base = getEnvVarFromWin32("NEUG_EXTENSION_HOME_PYENV");
#else
  const char* pyenv = std::getenv("NEUG_EXTENSION_HOME_PYENV");
  if (pyenv && *pyenv) {
    base = pyenv;
  }
#endif
#if defined(NEUG_EXTENSION_HOME_MACRO)
  if (base.empty()) {
    base = NEUG_EXTENSION_HOME_MACRO;
  }
#endif
  if (base.empty()) {
    base = getDefaultExtensionBase();
  }
  if (base.empty()) {
    THROW_IO_EXCEPTION(
        "Cannot determine a per-user extension directory; set "
        "NEUG_EXTENSION_HOME_PYENV");
  }
  return base + "/extension";
}

static std::string getUserExtensionDir(const std::string& extension_name) {
  return getExtensionRootDir() + "/" + extension_name;
}

// True when `path` resolves to a location strictly inside `root`.
static bool isPathWithinRoot(const std::filesystem::path& root,
                             const std::filesystem::path& path) {
  std::error_code ec;
  const auto canonical_root = std::filesystem::weakly_canonical(root, ec);
  if (ec) {
    return false;
  }
  const auto canonical_path = std::filesystem::weakly_canonical(path, ec);
  if (ec) {
    return false;
  }
  const auto rel = canonical_path.lexically_relative(canonical_root);
  if (rel.empty() || rel == ".") {
    return false;
  }
  const auto first = *rel.begin();
  return first != ".." && !rel.is_absolute();
}

// Refuse to dlopen code that another local user could have written. The file,
// its directory and the extension root must be owned by the current user (or
// root) and must not be group/world-writable.
// NEUG_EXTENSION_ALLOW_INSECURE_PERMS=1 opts out for shared environments that
// rely on group-writable installs.
static Status checkTrustedExtensionPath(const std::filesystem::path& root,
                                        const std::filesystem::path& library) {
#ifdef _WIN32
  (void) root;
  (void) library;
  return Status::OK();
#else
  if (envFlagEnabled("NEUG_EXTENSION_ALLOW_INSECURE_PERMS")) {
    return Status::OK();
  }
  const uid_t me = ::geteuid();
  for (const auto& p : {library, library.parent_path(), root}) {
    struct stat st {};
    if (::stat(p.c_str(), &st) != 0) {
      return Status(StatusCode::ERR_IO_ERROR,
                    "Cannot stat extension path: " + p.string());
    }
    if (st.st_uid != me && st.st_uid != 0) {
      return Status(StatusCode::ERR_PERMISSION,
                    "Refusing to load extension: " + p.string() +
                        " is owned by another user");
    }
    if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
      return Status(StatusCode::ERR_PERMISSION,
                    "Refusing to load extension: " + p.string() +
                        " is group- or world-writable (set "
                        "NEUG_EXTENSION_ALLOW_INSECURE_PERMS=1 to override)");
    }
  }
  return Status::OK();
#endif
}

// Only the official repository is trusted by default. Additional HTTPS
// repositories must be listed (comma-separated URL prefixes) in
// NEUG_EXTENSION_REPO_ALLOWLIST by whoever controls the server process, so a
// query alone can no longer make the database download and run foreign code.
static Status checkRepositoryAllowed(const std::string& repo) {
  if (repo == neug::extension::ExtensionUtils::OFFICIAL_EXTENSION_REPO) {
    return Status::OK();
  }
  if (repo.rfind("https://", 0) != 0) {
    return Status(StatusCode::ERR_PERMISSION,
                  "Extension repository must use https://: " + repo);
  }
  if (repo.find('{') != std::string::npos ||
      repo.find('}') != std::string::npos) {
    return Status(StatusCode::ERR_INVALID_ARGUMENT,
                  "Extension repository URL must not contain braces: " + repo);
  }
  const char* allow = std::getenv("NEUG_EXTENSION_REPO_ALLOWLIST");
  if (allow != nullptr) {
    std::stringstream ss(allow);
    std::string prefix;
    while (std::getline(ss, prefix, ',')) {
      prefix.erase(0, prefix.find_first_not_of(" \t"));
      prefix.erase(prefix.find_last_not_of(" \t") + 1);
      if (!prefix.empty() && repo.rfind(prefix, 0) == 0) {
        return Status::OK();
      }
    }
  }
  return Status(StatusCode::ERR_PERMISSION,
                "Extension repository is not allowed: " + repo +
                    ". Add its URL prefix to NEUG_EXTENSION_REPO_ALLOWLIST on "
                    "the database host to permit it.");
}

// Promote libneug.so to RTLD_GLOBAL so that extensions loaded via dlopen
// can resolve neug symbols.  When the host process (e.g. Python) loads
// libneug.so with RTLD_LOCAL, the symbols stay in a local scope and are
// invisible to subsequently dlopen'd extensions even though they list
// libneug.so in DT_NEEDED.  Re-opening with RTLD_NOLOAD | RTLD_GLOBAL
// promotes the already-loaded instance without reloading it.
static void ensureNeugSymbolsGlobal() {
#ifndef _WIN32
  static bool promoted = false;
  if (promoted)
    return;
  Dl_info info;
  if (dladdr(reinterpret_cast<void*>(&ensureNeugSymbolsGlobal), &info) &&
      info.dli_fname) {
    dlopen(info.dli_fname, RTLD_NOW | RTLD_NOLOAD | RTLD_GLOBAL);
  }
  promoted = true;
#else
  // On Windows, symbols are exported via NEUG_API macros, so no promotion is
  // needed.
#endif
}

static Status downloadExtensionFile(const ExtensionRepoInfo& repoInfo,
                                    const std::string& localFilePath);
static Status verifyExtensionChecksum(const ExtensionRepoInfo& libRepoInfo,
                                      const std::string& localLibPath);

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
// Try to find and set CA certificate paths automatically
static void trySetCaCertPaths(httplib::SSLClient& cli) {
  // First check environment variables
  const char* ssl_cert_file = std::getenv("SSL_CERT_FILE");
  const char* ssl_cert_dir = std::getenv("SSL_CERT_DIR");

  if (ssl_cert_file || ssl_cert_dir) {
    cli.set_ca_cert_path(ssl_cert_file ? ssl_cert_file : "",
                         ssl_cert_dir ? ssl_cert_dir : "");
    LOG(INFO) << "[Admin] Using CA certificate paths from environment: "
              << "SSL_CERT_FILE=" << (ssl_cert_file ? ssl_cert_file : "not set")
              << ", SSL_CERT_DIR=" << (ssl_cert_dir ? ssl_cert_dir : "not set");
    return;
  }

  // Combined CA certificate file paths for both macOS and Linux
  // Try all possible paths regardless of platform
  // Linux paths are tried first, then macOS paths
  const char* common_ca_files[] = {
      // Linux paths (tried first)
      "/etc/ssl/certs/ca-certificates.crt",        // Debian/Ubuntu
      "/etc/ssl/certs/ca-bundle.crt",              // Some distributions
      "/etc/pki/tls/certs/ca-bundle.crt",          // RedHat/CentOS
      "/usr/local/ssl/certs/ca-certificates.crt",  // Some custom installations
      "/etc/ssl/ca-bundle.pem",                    // Alternative location
      "/etc/ssl/certs/ca-bundle.pem",              // Alternative bundle format
      "/usr/share/ssl/certs/ca-bundle.crt",        // Some installations
      "/usr/share/ca-certificates/ca-certificates.crt",  // Alternative location
      "/etc/ca-certificates/extracted/ca-bundle.trust.crt",  // Debian extracted
      // macOS paths
      "/etc/ssl/cert.pem",                   // macOS system
      "/private/etc/ssl/cert.pem",           // macOS alternative
      "/usr/local/etc/openssl/cert.pem",     // Homebrew OpenSSL (Intel Mac)
      "/opt/homebrew/etc/openssl/cert.pem",  // Homebrew OpenSSL (Apple Silicon)
      "/System/Library/OpenSSL/certs/cert.pem",  // System OpenSSL (older macOS)
      "/usr/local/etc/ca-certificates/cert.pem",  // Alternative location
      nullptr};

  // Combined CA certificate directory paths for both macOS and Linux
  // Linux paths are tried first, then macOS paths
  const char* common_ca_dirs[] = {
      // Linux paths (tried first)
      "/etc/ssl/certs",              // Most Linux distributions
      "/etc/pki/tls/certs",          // RedHat/CentOS
      "/usr/local/ssl/certs",        // Some custom installations
      "/usr/share/ssl/certs",        // Alternative location
      "/usr/share/ca-certificates",  // Debian/Ubuntu
      "/etc/ca-certificates/extracted/tls-ca-bundle.pem",  // Debian extracted
      "/etc/ssl",  // Standard SSL directory
      // macOS paths
      "/usr/local/etc/openssl/certs",     // Homebrew OpenSSL (Intel Mac)
      "/opt/homebrew/etc/openssl/certs",  // Homebrew OpenSSL (Apple Silicon)
      "/System/Library/OpenSSL/certs",    // System OpenSSL (older macOS)
      "/private/etc/ssl/certs",           // macOS alternative
      "/private/etc/ssl",                 // macOS alternative
      nullptr};

  // Try to find a valid CA certificate file
  for (int i = 0; common_ca_files[i] != nullptr; i++) {
    if (std::filesystem::exists(common_ca_files[i])) {
      cli.set_ca_cert_path(common_ca_files[i], "");
      LOG(INFO) << "[Admin] Auto-detected CA certificate file: "
                << common_ca_files[i];
      return;
    }
  }

  // Try to find a valid CA certificate directory
  for (int i = 0; common_ca_dirs[i] != nullptr; i++) {
    if (std::filesystem::exists(common_ca_dirs[i]) &&
        std::filesystem::is_directory(common_ca_dirs[i])) {
      cli.set_ca_cert_path("", common_ca_dirs[i]);
      LOG(INFO) << "[Admin] Auto-detected CA certificate directory: "
                << common_ca_dirs[i];
      return;
    }
  }

  // If nothing found, rely on OpenSSL defaults
  // On macOS, httplib may use Keychain if
  // CPPHTTPLIB_USE_CERTS_FROM_MACOSX_KEYCHAIN is defined
  LOG(WARNING)
      << "[Admin] No CA certificate paths found, using OpenSSL defaults";
#ifdef __APPLE__
  LOG(WARNING) << "[Admin] On macOS, consider defining "
                  "CPPHTTPLIB_USE_CERTS_FROM_MACOSX_KEYCHAIN "
               << "to use Keychain certificates, or set "
                  "SSL_CERT_FILE/SSL_CERT_DIR environment variables";
#endif
}
#endif

Status install_extension(const std::string& extension_name,
                         const std::string& repository) {
  LOG(INFO) << "[Admin] INSTALL extension: " << extension_name;
  RETURN_IF_NOT_OK(validateExtensionName(extension_name));
  const std::string& requested_repo =
      repository.empty()
          ? std::string(
                neug::extension::ExtensionUtils::OFFICIAL_EXTENSION_REPO)
          : repository;
  RETURN_IF_NOT_OK(checkRepositoryAllowed(requested_repo));
  std::string extDir = getUserExtensionDir(extension_name);

  std::error_code ec;
  std::filesystem::create_directories(extDir, ec);
  if (ec) {
    return Status(StatusCode::ERR_IO_ERROR,
                  "Failed to create extension directory: " + extDir +
                      " ec=" + ec.message());
  }
#ifndef _WIN32
  // Keep the per-user extension tree private to its owner.
  ::chmod(getExtensionRootDir().c_str(), 0700);
  ::chmod(extDir.c_str(), 0700);
#endif

  auto fileName =
      neug::extension::ExtensionUtils::getExtensionFileName(extension_name);
  auto localLibPath = extDir + "/" + fileName;

  auto repoInfo = neug::extension::ExtensionUtils::getExtensionLibRepoInfo(
      extension_name, requested_repo);

  LOG(INFO) << "[Admin] Download URL host=" << repoInfo.hostURL
            << " path=" << repoInfo.hostPath << " full=" << repoInfo.repoURL;

  if (std::filesystem::exists(localLibPath)) {
    auto verifySt = verifyExtensionChecksum(repoInfo, localLibPath);
    // existing extension lib in local path is not consistent with the remote
    // repo, remove it
    if (!verifySt.ok()) {
      std::error_code ec;
      if (!std::filesystem::remove(localLibPath, ec)) {
        LOG(ERROR) << "[Admin] Cannot delete existing extension file (no "
                      "permission or error): " +
                          localLibPath + " ec=" + ec.message() +
                          ". Please delete it manually.";
        return Status(
            StatusCode::ERR_IO_ERROR,
            "Cannot delete existing extension file (no permission or error): " +
                localLibPath + " ec=" + ec.message() +
                ". Please delete it manually.");
      }
      LOG(INFO) << "[Admin] Removed existing extension file: " << localLibPath;
    }
  }

  if (!std::filesystem::exists(localLibPath)) {
    // Download to a private temporary name and publish it with an atomic
    // rename only after the checksum matches, so a concurrent LOAD (or a
    // crash) can never observe an unverified or partially written library.
#ifndef _WIN32
    const std::string tmpPath =
        localLibPath + ".download." + std::to_string(::getpid());
#else
    const std::string tmpPath = localLibPath + ".download";
#endif
    std::error_code rm_ec;
    std::filesystem::remove(tmpPath, rm_ec);
    auto st = downloadExtensionFile(repoInfo, tmpPath);
    if (!st.ok()) {
      std::filesystem::remove(tmpPath, rm_ec);
      return Status(StatusCode::ERR_IO_ERROR,
                    "Failed to download extension " + extension_name +
                        " to local lib path " + localLibPath + " : " +
                        st.error_message());
    }
    auto verifySt = verifyExtensionChecksum(repoInfo, tmpPath);
    if (!verifySt.ok()) {
      std::filesystem::remove(tmpPath, rm_ec);
      return Status(
          StatusCode::ERR_IO_ERROR,
          "Extension integrity check failed: " + verifySt.error_message());
    }
#ifndef _WIN32
    ::chmod(tmpPath.c_str(), 0600);
#endif
    std::error_code mv_ec;
    std::filesystem::rename(tmpPath, localLibPath, mv_ec);
    if (mv_ec) {
      std::filesystem::remove(tmpPath, rm_ec);
      return Status(StatusCode::ERR_IO_ERROR, "Failed to publish extension " +
                                                  localLibPath + ": " +
                                                  mv_ec.message());
    }
    LOG(INFO) << "[Admin] Extension " << extension_name
              << " downloaded, verified and installed to " << localLibPath;
  }

  return Status::OK();
}

static Status downloadExtensionFile(const ExtensionRepoInfo& repoInfo,
                                    const std::string& localFilePath) {
#ifndef CPPHTTPLIB_OPENSSL_SUPPORT
  return Status(
      StatusCode::ERR_IO_ERROR,
      "HTTPS not supported (rebuild with CPPHTTPLIB_OPENSSL_SUPPORT)");
#else
  httplib::SSLClient cli(repoInfo.hostURL.c_str());
  cli.set_connection_timeout(10, 0);
  cli.set_read_timeout(60, 0);

  // Try to automatically detect and set CA certificate paths
  trySetCaCertPaths(cli);

  httplib::Headers headers = {
      {"User-Agent", common::stringFormat("gs/v{}", getVersion())}};

  auto res = cli.Get(repoInfo.hostPath.c_str(), headers);
  if (!res) {
    std::string error_detail = httplib::to_string(res.error());
    LOG(ERROR) << "[Admin] Download failed, res.error()=" << error_detail;

    // If SSL verification failed, get detailed error information
    if (res.error() == httplib::Error::SSLServerVerification) {
      long verify_result = cli.get_openssl_verify_result();
      if (verify_result != 0) {
        const char* verify_error_str =
            X509_verify_cert_error_string(verify_result);
        LOG(ERROR) << "[Admin] SSL verification failed: " << "error_code="
                   << verify_result << ", error_description=\""
                   << (verify_error_str ? verify_error_str : "unknown")
                   << "\", host=" << repoInfo.hostURL;

        // Log CA certificate paths for debugging
        const char* ssl_cert_file = std::getenv("SSL_CERT_FILE");
        const char* ssl_cert_dir = std::getenv("SSL_CERT_DIR");
        LOG(ERROR) << "[Admin] CA certificate paths: " << "SSL_CERT_FILE="
                   << (ssl_cert_file ? ssl_cert_file
                                     : "not set (using default)")
                   << ", SSL_CERT_DIR="
                   << (ssl_cert_dir ? ssl_cert_dir : "not set (using default)");

        error_detail += " (SSL verify error: " + std::to_string(verify_result);
        if (verify_error_str) {
          error_detail += " - " + std::string(verify_error_str);
        }
        error_detail += ")";
      }
    }

    return Status(StatusCode::ERR_IO_ERROR,
                  "Failed to download: " + repoInfo.repoURL +
                      " (network error: " + error_detail + ")");
  } else if (res->status != 200) {
    return Status(StatusCode::ERR_IO_ERROR,
                  "Failed to download: " + repoInfo.repoURL + " (HTTP " +
                      std::to_string(res->status) + ")");
  }

  std::ofstream ofs(localFilePath, std::ios::binary);
  if (!ofs) {
    return Status(StatusCode::ERR_IO_ERROR,
                  "Cannot open local file: " + localFilePath);
  }
  ofs.write(res->body.data(), static_cast<std::streamsize>(res->body.size()));
  if (!ofs) {
    return Status(StatusCode::ERR_IO_ERROR,
                  "Failed writing file: " + localFilePath);
  }
  return Status::OK();
#endif
}

static result<std::string> computeFileSHA256(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  if (!file.is_open()) {
    RETURN_ERROR(Status(StatusCode::ERR_IO_ERROR, "Cannot open file: " + path));
  }

  EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
  if (mdctx == nullptr) {
    RETURN_ERROR(
        Status(StatusCode::ERR_INTERNAL_ERROR, "Failed to create EVP_MD_CTX"));
  }

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(mdctx);
    RETURN_ERROR(Status(StatusCode::ERR_INTERNAL_ERROR,
                        "Failed to initialize SHA256 digest"));
  }

  constexpr size_t kBufferSize = 8192;
  char buffer[kBufferSize];
  while (file.read(buffer, kBufferSize) || file.gcount() > 0) {
    if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
      EVP_MD_CTX_free(mdctx);
      RETURN_ERROR(Status(StatusCode::ERR_INTERNAL_ERROR,
                          "Failed to update SHA256 digest"));
    }
  }

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len = 0;
  if (EVP_DigestFinal_ex(mdctx, hash, &hash_len) != 1) {
    EVP_MD_CTX_free(mdctx);
    RETURN_ERROR(Status(StatusCode::ERR_INTERNAL_ERROR,
                        "Failed to finalize SHA256 digest"));
  }

  EVP_MD_CTX_free(mdctx);

  std::ostringstream ss;
  for (unsigned int i = 0; i < hash_len; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<int>(hash[i]);
  }

  return ss.str();
}

static Status verifyExtensionChecksum(const ExtensionRepoInfo& libRepoInfo,
                                      const std::string& localLibPath) {
  std::string checksumURL = libRepoInfo.repoURL + ".sha256";
  std::string checksumPath = libRepoInfo.hostPath + ".sha256";
  std::string checksumHost = libRepoInfo.hostURL;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  httplib::SSLClient cli(checksumHost.c_str());
  cli.set_connection_timeout(5, 0);
  cli.set_read_timeout(10, 0);

  // Try to automatically detect and set CA certificate paths
  trySetCaCertPaths(cli);

  httplib::Headers headers = {
      {"User-Agent", common::stringFormat("gs/v{}", getVersion())}};

  auto res = cli.Get(checksumPath.c_str(), headers);
  if (!res) {
    std::string error_detail = httplib::to_string(res.error());
    LOG(ERROR) << "[Admin] Download failed, res.error()=" << error_detail;

    // If SSL verification failed, get detailed error information
    if (res.error() == httplib::Error::SSLServerVerification) {
      long verify_result = cli.get_openssl_verify_result();
      if (verify_result != 0) {
        const char* verify_error_str =
            X509_verify_cert_error_string(verify_result);
        LOG(ERROR) << "[Admin] SSL verification failed: " << "error_code="
                   << verify_result << ", error_description=\""
                   << (verify_error_str ? verify_error_str : "unknown")
                   << "\", host=" << checksumHost;

        // Log CA certificate paths for debugging
        const char* ssl_cert_file = std::getenv("SSL_CERT_FILE");
        const char* ssl_cert_dir = std::getenv("SSL_CERT_DIR");
        LOG(ERROR) << "[Admin] CA certificate paths: " << "SSL_CERT_FILE="
                   << (ssl_cert_file ? ssl_cert_file
                                     : "not set (using default)")
                   << ", SSL_CERT_DIR="
                   << (ssl_cert_dir ? ssl_cert_dir : "not set (using default)");

        error_detail += " (SSL verify error: " + std::to_string(verify_result);
        if (verify_error_str) {
          error_detail += " - " + std::string(verify_error_str);
        }
        error_detail += ")";
      }
    }

    return Status(StatusCode::ERR_IO_ERROR,
                  "Failed to download checksum: " + checksumURL +
                      " (network error: " + error_detail + ")");
  } else if (res->status != 200) {
    return Status(StatusCode::ERR_IO_ERROR,
                  "Failed to download checksum: " + checksumURL + " (HTTP " +
                      std::to_string(res->status) + ")");
  }

  std::string expectedChecksum = res->body;

  auto spacePos = expectedChecksum.find(' ');
  if (spacePos != std::string::npos) {
    expectedChecksum = expectedChecksum.substr(0, spacePos);
  }

  expectedChecksum.erase(
      std::remove(expectedChecksum.begin(), expectedChecksum.end(), '\n'),
      expectedChecksum.end());
  expectedChecksum.erase(
      std::remove(expectedChecksum.begin(), expectedChecksum.end(), '\r'),
      expectedChecksum.end());

  auto computedResult = computeFileSHA256(localLibPath);
  if (!computedResult) {
    return computedResult.error();
  }

  std::string computedChecksum = computedResult.value();

  std::transform(expectedChecksum.begin(), expectedChecksum.end(),
                 expectedChecksum.begin(), ::tolower);
  std::transform(computedChecksum.begin(), computedChecksum.end(),
                 computedChecksum.begin(), ::tolower);

  if (expectedChecksum != computedChecksum) {
    return Status(StatusCode::ERR_IO_ERROR,
                  "Checksum verification failed for " + localLibPath +
                      ". Expected: " + expectedChecksum +
                      ", Got: " + computedChecksum);
  }

  LOG(INFO) << "[Admin] Checksum verification passed for " << localLibPath;
  return Status::OK();
#else
  return Status(StatusCode::ERR_IO_ERROR,
                "Checksum verification requires OpenSSL support");
#endif
}

Status uninstall_extension(const std::string& extension_name) {
  LOG(INFO) << "[Admin] UNINSTALL extension: " << extension_name;
  RETURN_IF_NOT_OK(validateExtensionName(extension_name));
  std::string extDir = getUserExtensionDir(extension_name);
  if (!isPathWithinRoot(getExtensionRootDir(), extDir)) {
    return Status(StatusCode::ERR_INVALID_ARGUMENT,
                  "Extension path escapes the extension root: " + extDir);
  }
  std::error_code ec;
  if (!std::filesystem::exists(extDir)) {
    return Status(StatusCode::ERR_IO_ERROR,
                  "Cannot uninstall extension: " + extension_name +
                      " since it has not been installed.");
  }
  if (!std::filesystem::remove_all(extDir, ec)) {
    return Status(StatusCode::ERR_IO_ERROR,
                  "An error occurred while uninstalling extension: " +
                      extension_name + ". Error: " + ec.message());
  }
  LOG(INFO) << "[Admin] Extension: " << extension_name
            << " has been uninstalled";
  return Status::OK();
}

}  // namespace extension

void ExtensionManager::Open(const NeugDBConfig& config) {
  if (!config.auto_load_extension) {
    return;
  }
  try {
    const auto root = std::filesystem::path(extension::getExtensionRootDir());
    std::error_code ec;
    const bool exists = std::filesystem::exists(root, ec);
    if (!exists && !ec) {
      LOG(ERROR) << "[AutoLoadExtension] stage=discover root=" << root
                 << " error=Extension directory does not exist"
                 << "; continuing database open";
      return;
    }
    std::filesystem::directory_iterator it(root, ec), end;
    std::vector<std::string> names;
    while (!ec && it != end) {
      const auto path = it->path();
      try {
        std::error_code entry_error;
        const bool is_directory = it->is_directory(entry_error);
        if (entry_error) {
          LOG(ERROR) << "[AutoLoadExtension] stage=discover path=" << path
                     << " error=" << entry_error.message()
                     << "; continuing database open";
        } else if (is_directory) {
          const auto name = path.filename().string();
          const auto canonical_name = NormalizeExtensionName(name);
          const auto library =
              path / extension::ExtensionUtils::getExtensionFileName(name);
          std::string error;
          if (name != canonical_name) {
            error = "Extension directory name must be lowercase";
          } else if (!extension::isValidExtensionName(name)) {
            error = "Extension directory name must match [a-z0-9_]{1,64}";
          } else {
            const auto status = std::filesystem::status(library, entry_error);
            if (status.type() == std::filesystem::file_type::not_found) {
              error = "Extension library file does not exist";
            } else if (entry_error) {
              error = entry_error.message();
            } else if (!std::filesystem::is_regular_file(status)) {
              error = "Extension library path is not a regular file";
            }
          }
          if (!error.empty()) {
            LOG(ERROR) << "[AutoLoadExtension] stage=discover extension="
                       << name << " path=" << library << " error=" << error
                       << "; continuing database open";
          } else {
            names.push_back(canonical_name);
          }
        }
      } catch (const std::exception& e) {
        LOG(ERROR) << "[AutoLoadExtension] stage=discover path=" << path
                   << " error=" << e.what() << "; continuing database open";
      } catch (...) {
        LOG(ERROR) << "[AutoLoadExtension] stage=discover path=" << path
                   << " error=Unknown exception; continuing database open";
      }
      it.increment(ec);
    }
    if (ec) {
      LOG(ERROR) << "[AutoLoadExtension] stage=discover root=" << root
                 << " error=" << ec.message() << "; continuing database open";
    }
    std::sort(names.begin(), names.end());
    names.erase(std::unique(names.begin(), names.end()), names.end());
    for (const auto& name : names) {
      try {
        auto loaded = LoadExtension(name);
        if (!loaded) {
          LOG(ERROR) << "[AutoLoadExtension] stage=load extension=" << name
                     << " root=" << root
                     << " error=" << loaded.error().ToString()
                     << "; continuing database open";
        }
      } catch (const std::exception& e) {
        LOG(ERROR) << "[AutoLoadExtension] stage=load extension=" << name
                   << " root=" << root << " error=" << e.what()
                   << "; continuing database open";
      } catch (...) {
        LOG(ERROR) << "[AutoLoadExtension] stage=load extension=" << name
                   << " root=" << root
                   << " error=Unknown exception; continuing database open";
      }
    }
  } catch (const std::exception& e) {
    LOG(ERROR) << "[AutoLoadExtension] stage=discover error=" << e.what()
               << "; continuing database open";
  } catch (...) {
    LOG(ERROR) << "[AutoLoadExtension] stage=discover error=Unknown exception"
               << "; continuing database open";
  }
}

result<ExtensionManager::LoadResult> ExtensionManager::LoadExtension(
    const std::string& extension_name) {
  const auto canonical_name = NormalizeExtensionName(extension_name);
  if (auto valid = extension::validateExtensionName(canonical_name);
      !valid.ok()) {
    RETURN_ERROR(valid);
  }
  std::lock_guard<std::mutex> lock(mutex_);
  if (loaded_extensions_.contains(canonical_name)) {
    LOG(WARNING) << "[Admin] Extension " << canonical_name
                 << " is already loaded; skipping library initialization";
    return LoadResult{canonical_name, false};
  }

  LOG(INFO) << "[Admin] LOAD extension: " << canonical_name;
  extension::ensureNeugSymbolsGlobal();
  auto fileName =
      neug::extension::ExtensionUtils::getExtensionFileName(canonical_name);

  std::string userExtDir = extension::getUserExtensionDir(canonical_name);
  std::string userLibPath = userExtDir + "/" + fileName;
  if (std::filesystem::exists(userLibPath)) {
    const auto root = extension::getExtensionRootDir();
    if (!extension::isPathWithinRoot(root, userLibPath)) {
      RETURN_ERROR(
          Status(StatusCode::ERR_INVALID_ARGUMENT,
                 "Extension path escapes the extension root: " + userLibPath));
    }
    if (auto trusted = extension::checkTrustedExtensionPath(root, userLibPath);
        !trusted.ok()) {
      RETURN_ERROR(trusted);
    }
    LOG(INFO) << "[Admin] Loading extension from user install: " << userLibPath;
    // Keep extension dependencies in their own scope to avoid symbol
    // conflicts with other loaded libraries.
    // neug symbols are still resolvable because ensureNeugSymbolsGlobal()
    // has already promoted libneug.so to RTLD_GLOBAL.
    void* handle = dlopen(userLibPath.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
      RETURN_ERROR(Status(StatusCode::ERR_IO_ERROR,
                          "Failed to load extension library: " + userLibPath +
                              ". Error: " + std::string(dlerror())));
    }
    dlerror();
    auto init_func = reinterpret_cast<InitFunc>(dlsym(handle, "Init"));
    const char* dlsym_error = dlerror();
    if (dlsym_error) {
      dlclose(handle);
      RETURN_ERROR(Status(
          StatusCode::ERR_IO_ERROR,
          "Failed to find 'Init' function in extension: " + canonical_name +
              ". Error: " + std::string(dlsym_error)));
    }
    try {
      (*init_func)();
    } catch (const std::exception& e) {
      dlclose(handle);
      RETURN_ERROR(Status(StatusCode::ERR_IO_ERROR,
                          "Extension initialization failed: " + canonical_name +
                              ". Error: " + e.what()));
    } catch (...) {
      dlclose(handle);
      RETURN_ERROR(
          Status(StatusCode::ERR_IO_ERROR,
                 "Extension initialization failed with unknown error: " +
                     canonical_name));
    }
    loaded_extensions_.emplace(canonical_name,
                               LoadedExtension{userLibPath, handle, init_func});
    LOG(INFO) << "[Admin] Extension " << canonical_name
              << " loaded and initialized successfully";
    return LoadResult{canonical_name, true};
  }

  // Not found
  LOG(ERROR) << "[Admin] Extension " << userLibPath
             << " not found in user install or wheel package";
  RETURN_ERROR(Status(StatusCode::ERR_IO_ERROR,
                      "Extension " + userLibPath +
                          " not found in user install or wheel package"));
}

#else

// Lite builds retain the existing unsupported LOAD behavior.
void ExtensionManager::Open(const NeugDBConfig& config) {
  if (config.auto_load_extension) {
    LOG(ERROR) << "[AutoLoadExtension] stage=load error=LOAD is unavailable in "
                  "lite mode"
               << "; continuing database open";
  }
}

namespace extension {

Status install_extension(const std::string&, const std::string&) {
  return Status(StatusCode::ERR_NOT_SUPPORTED,
                "INSTALL is unavailable in lite mode.");
}

Status uninstall_extension(const std::string&) {
  return Status(StatusCode::ERR_NOT_SUPPORTED,
                "UNINSTALL is unavailable in lite mode.");
}

}  // namespace extension

result<ExtensionManager::LoadResult> ExtensionManager::LoadExtension(
    const std::string&) {
  RETURN_ERROR(Status(StatusCode::ERR_NOT_SUPPORTED,
                      "LOAD is unavailable in lite mode."));
}

#endif  // !NEUG_LITE

}  // namespace neug
