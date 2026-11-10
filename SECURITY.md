# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |

Security updates are applied only to the latest release.

## Reporting a Vulnerability

If you have discovered a security vulnerability in this project, please report it privately. **Do not disclose it as a public issue.** This gives us time to work with you to fix the issue before public exposure, reducing the chance that the exploit will be used before a patch is released.

Please report security vulnerabilities via one of the following methods:

1. **GitHub Security Advisory**: [Create a private security advisory](https://github.com/alibaba/neug/security/advisories/new)
2. **Email**: Contact the GraphScope team at graphscope@alibaba-inc.com

Please include the following information in your report:

- Description of the vulnerability
- Steps to reproduce the issue
- Potential impact
- Suggested fix (if any)

## Response Timeline

- **Initial Response**: We aim to acknowledge receipt of your report within 24 hours.
- **Investigation**: We will investigate and validate the issue within 2 days.
- **Resolution**: We target to provide a fix within 90 days, depending on complexity.

## Disclosure Policy

We follow a coordinated disclosure process:

1. Reporter submits vulnerability privately
2. We confirm and investigate the issue
3. We develop and test a fix
4. We release the fix and publish a security advisory
5. Reporter may then disclose publicly (after fix is released)

## Security Best Practices

When using NeuG in production:

- Keep NeuG updated to the latest version
- Use appropriate access controls for database files
- Validate and sanitize all user inputs before query execution
- Follow the principle of least privilege for service deployments

### Service-mode hardening controls

The HTTP service executes arbitrary Cypher, including `INSTALL`, `LOAD`,
`UNINSTALL` and file-reading `COPY`/`LOAD FROM`. Treat network access to the
service port as database-administrator access, and use these controls:

| Environment variable | Effect |
| --- | --- |
| `NEUG_HTTP_AUTH_TOKEN` | When set, every request must send `Authorization: Bearer <token>`. The Python `Session` picks it up automatically (or pass `auth_token=`). |
| `NEUG_HTTP_ALLOWED_ORIGINS` | Comma-separated browser origins allowed to call the service. Requests that carry any other `Origin` header are rejected with 403, which blocks CSRF and DNS-rebinding requests from web pages. Native clients send no `Origin` and are unaffected. |
| `NEUG_HTTP_MAX_BODY_BYTES` | Maximum request body size (default 256 MiB, cpp-httplib transport). |
| `NEUG_EXTENSION_REPO_ALLOWLIST` | Comma-separated HTTPS URL prefixes accepted by `INSTALL ... FROM`. Only the official repository is trusted by default. |
| `NEUG_EXTENSION_ALLOW_INSECURE_PERMS` | Set to `1` to load extensions from directories that are group/world-writable or owned by another user (refused by default). |

POST bodies sent with `text/plain`, `application/x-www-form-urlencoded` or
`multipart/form-data` are rejected with 415, since browsers can send those
types cross-origin without a CORS preflight.

Extension names must match `[a-z0-9_]{1,64}`. When neither
`NEUG_EXTENSION_HOME_PYENV` nor a build-time home is configured, extensions
live in a per-user directory (`$XDG_DATA_HOME/neug/extension` or
`~/.neug/extension`, mode 0700) instead of `/tmp`.

WAL records are framed with a CRC-32C checksum. On recovery, replay stops at
the first torn or corrupted record, so a crash between a write and its fsync
can no longer replay a half-written transaction. WAL files written before
this change are still read, with bounds checks.

## Acknowledgments

We appreciate the security research community's efforts in responsibly disclosing vulnerabilities. Contributors who report valid security issues will be acknowledged in release notes (unless they prefer to remain anonymous).
