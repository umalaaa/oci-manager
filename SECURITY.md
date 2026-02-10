# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in **oci-manager**, please **do not** open a public issue.

Instead, please report it privately via one of:

1. **GitHub Private Vulnerability Reporting** — use the "Security" tab → "Report a vulnerability"
2. **Email** — send details to the repository maintainer (see profile)

We will acknowledge your report within **48 hours** and work on a fix promptly.

## Security Considerations

### Credential Safety
- **NEVER** commit your real `config` file or `.pem` private keys.
- The repo ships with `config.example` — copy it to `config` and fill in your values.
- The real `config` file is in `.gitignore` and should never appear in the repository.

### Admin Key
- The `admin_key` in the config gates access to the Web UI and all API endpoints.
- Use a strong, randomly generated key (32+ characters recommended).
- You can also pass the key via the `OCI_ADMIN_KEY` environment variable.

### Network Exposure
- By default, the web server binds to `127.0.0.1` (localhost only).
- To bind to all interfaces, you must explicitly pass `--allow-remote`.
- **For production / remote access**, place the web UI behind a reverse proxy (e.g., Caddy, nginx) with TLS.

### Cookie-Based Auth
- The Web UI stores the admin key in a **plaintext cookie** (no hashing).
- This is acceptable for local/dev use, but for production, use HTTPS to protect the cookie in transit.
