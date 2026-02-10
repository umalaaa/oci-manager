# OCI Manager

A fast, single-binary CLI + Web UI for managing Oracle Cloud Infrastructure (OCI) Compute instances — built in Rust.

## Features

- **Create / Terminate / Reboot** instances via CLI or Web UI
- **Multi-profile** — manage multiple OCI tenancies from one config file
- **Flex shapes** — configure OCPUs and Memory for `VM.Standard.A1.Flex`, `E4.Flex`, etc.
- **Presets** — save reusable instance configurations (shape, OS, resources) in config
- **Auto-selection** — automatically picks availability domain, image, and shape when not specified
- **Task queue** — Web UI queues create requests with automatic retry; tasks can be stopped
- **Cron mode** — headless `cron` subcommand for system schedulers
- **Web-only mode** — start the Web UI without any OCI profiles configured
- **Web UI** with admin key authentication, profile selector, English/Chinese support
- **Cross-platform** — Linux (x64/ARM64), macOS (x64/ARM64), Windows (x64)

---

## Installation

### Linux One-Click Install

```bash
curl -sSf https://raw.githubusercontent.com/umalaaa/oci-manager/main/install.sh | bash
```

This downloads the latest binary and sets up a **systemd** service on port `9927`.

After installation:

1. Edit your config file (the script tells you where: `~/.oci-manager/config` or `/etc/oci-manager/config`)
2. Place your OCI API `.pem` key in the same directory
3. Start the service:
   - **Non-root**: `systemctl --user enable --now oci-manager`
   - **Root**: `sudo systemctl enable --now oci-manager`
4. Open `http://your-server-ip:9927` in your browser

### Uninstall

```bash
curl -sSf https://raw.githubusercontent.com/umalaaa/oci-manager/main/uninstall.sh | bash
```

### Build from Source

Requires [Rust toolchain](https://rustup.rs/).

```bash
cargo build --release
# Binary: target/release/oci-manager (or oci-manager.exe on Windows)
```

---

## Configuration

The config file uses INI format. Location priority:

| Priority | Path |
|----------|------|
| 1 | `--config <path>` (CLI flag) |
| 2 | `./config` (current directory) |
| 3 | `~/.oci/config` (home directory) |

```bash
cp config.example ~/.oci/config   # then edit with your real values
```

> ⚠️ **NEVER commit your real `config` file or `.pem` keys to git!**

### Full Example

```ini
# ── Web UI Settings ────────────────────────
[global:web]
enable_admin=true
admin_key=change-me-to-a-strong-random-key
port=9927
# ssh_public_key=ssh-ed25519 AAAA...         # (optional) global default SSH key

# ── Default OCI Profile (required fields) ──
[DEFAULT]
user=ocid1.user.oc1..aaaaaaaaexample
fingerprint=aa:bb:cc:dd:ee:ff:00:11:22:33
tenancy=ocid1.tenancy.oc1..aaaaaaaaexample
region=us-phoenix-1
key_file=/path/to/oci_api_key.pem

# ── Optional defaults (uncomment as needed) ─
# compartment=ocid1.compartment.oc1..example
# subnet=ocid1.subnet.oc1..example
# shape=VM.Standard.E4.Flex
# availability_domain=Uocm:PHX-AD-1
# ssh_public_key=/path/to/id_rsa.pub
# display_name_prefix=auto
# boot_volume_size_gbs=50
# ocpus=1
# memory_in_gbs=6

# ── Additional Profile (you can add as many as needed) ──
# [SECONDARY]
# user=ocid1.user.oc1..example2
# fingerprint=bb:cc:dd:ee:ff:00:11:22:33:44
# tenancy=ocid1.tenancy.oc1..example2
# region=eu-frankfurt-1
# key_file=/path/to/key2.pem

# ── Presets ────────────────────────────────
[preset:ARM-1cpu-6gb-Ubuntu]
shape=VM.Standard.A1.Flex
ocpus=1
memory_in_gbs=6
image_os=Canonical Ubuntu
image_version=22.04
display_name_prefix=arm-ubuntu
```

### `[global:web]` — Web UI Settings

Web server settings go here. This section is **not** an OCI profile — no credentials needed.

| Field | Required | Description |
|-------|----------|-------------|
| `enable_admin` | ✅ | Set `true` to enable the web UI |
| `admin_key` | ✅ | Authentication key for login |
| `port` | | Web UI port (default: `8080`) |
| `ssh_public_key` | | Global default SSH key for all profiles |

> **Tip:** These settings can also be placed at the **top level** of the config (before any `[section]`).

**Web-only mode:** If you only include `[global:web]` without any OCI profile, the web server will still start. OCI operations will fail until a profile is added.

### `[DEFAULT]` / `[NAME]` — OCI Profiles

OCI credentials. `[DEFAULT]` is used when no `--profile` is specified.

| Field | Required | Description |
|-------|----------|-------------|
| `user` | ✅ | User OCID |
| `fingerprint` | ✅ | API key fingerprint |
| `tenancy` | ✅ | Tenancy OCID |
| `region` | ✅ | OCI region (e.g. `us-phoenix-1`) |
| `key_file` | ✅ | Path to private key `.pem` |
| `compartment` | | Default compartment OCID |
| `subnet` | | Default subnet OCID |
| `shape` | | Default shape |
| `availability_domain` | | Default AD |
| `ssh_public_key` | | SSH public key (path or inline) |
| `display_name_prefix` | | Prefix for auto-generated names |
| `boot_volume_size_gbs` | | Boot volume size in GB |
| `ocpus` | | Default OCPUs (Flex shapes) |
| `memory_in_gbs` | | Default memory in GB (Flex shapes) |

Add more profiles with named sections (e.g. `[SECONDARY]`). Switch with `--profile SECONDARY` or the Web UI dropdown.

### `[preset:NAME]` — Reusable Configurations

Define reusable instance configurations. All fields are optional and override profile defaults when selected.

```ini
[preset:ARM-4cpu-24gb-OracleLinux]
shape=VM.Standard.A1.Flex
ocpus=4
memory_in_gbs=24
image_os=Oracle Linux
image_version=8
display_name_prefix=arm-ol
```

---

## Usage

### CLI

```bash
# List instances
oci-manager instance list --compartment <ocid>

# Create instance (uses config defaults + auto-selection)
oci-manager instance create

# Create with specific options
oci-manager instance create \
  --shape VM.Standard.A1.Flex \
  --ocpus 2 --memory-gbs 12 \
  --image-os "Canonical Ubuntu" --image-version 22.04

# Create with retry (keeps trying every 3 minutes)
oci-manager instance create \
  --shape VM.Standard.A1.Flex --ocpus 4 --memory-gbs 24 \
  --retry --retry-seconds 180

# Terminate / Reboot
oci-manager instance terminate --instance <ocid>
oci-manager instance reboot --instance <ocid>
oci-manager instance reboot --instance <ocid> --hard

# Check availability domains and shapes
oci-manager availability --compartment <ocid>
```

### Web UI

```bash
oci-manager serve                                        # localhost:8080
oci-manager serve --port 9090                            # custom port
oci-manager serve --host 0.0.0.0 --port 8080 --allow-remote  # remote access
```

Open the URL in your browser, enter your `admin_key`, and you can:
- Select profiles and presets
- Create instances with full form validation
- Queue tasks with automatic retry (and stop them)
- View, reboot, and terminate running instances

### Cron Mode

Runs a single create attempt (or retry loop) and exits. Perfect for system schedulers:

```bash
# Using a preset
oci-manager cron --preset ARM-1cpu-6gb-Ubuntu

# With retry (max 10 attempts, 3 min interval)
oci-manager cron --preset ARM-4cpu-24gb-OracleLinux \
  --retry --retry-seconds 180 --retry-max 10

# Override preset values
oci-manager cron --preset ARM-1cpu-6gb-Ubuntu --ocpus 2 --memory-gbs 12

# Full manual specification
oci-manager cron \
  --shape VM.Standard.A1.Flex --ocpus 1 --memory-gbs 6 \
  --image-os "Canonical Ubuntu" --image-version 22.04 \
  --retry
```

**Linux cron** (try every 5 minutes):
```cron
*/5 * * * * /usr/local/bin/oci-manager cron --preset ARM-1cpu-6gb-Ubuntu >> /var/log/oci-cron.log 2>&1
```

**Windows Task Scheduler**: Run `oci-manager.exe cron --preset ARM-1cpu-6gb-Ubuntu --retry` on your desired schedule.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OCI_ADMIN_KEY` | Admin key for web UI (fallback if not in config) |
| `RUST_LOG` | Log level (`info`, `debug`, `trace`) |

---

## Security

| Item | Protection |
|------|------------|
| OCI credentials | `.gitignore` blocks `config`, `*.pem`, `*.key` |
| Admin key | Set via config or `OCI_ADMIN_KEY` env var, never hardcoded |
| Web UI binding | Defaults to `127.0.0.1`; requires `--allow-remote` for non-loopback |
| Authentication | All API endpoints require `admin_key` (header, bearer, or cookie) |
| SSH keys (Web UI) | Inline-only validation prevents file path traversal |

**Recommendations:**
- Use a **strong, random `admin_key`** (32+ characters)
- For remote access, place behind a **reverse proxy with TLS** (Caddy, nginx)
- Set `RUST_LOG=info` in production
- Rotate API keys periodically

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## Development

```bash
cargo test                                    # Run tests
cargo fmt                                     # Format code
cargo clippy --all-targets -- -D warnings     # Lint
```

### Project Structure

```
oci-manager/
├── src/
│   ├── main.rs      # Entry point, CLI dispatch, cron handler
│   ├── cli.rs       # Clap CLI argument definitions
│   ├── config.rs    # INI config parsing, profiles, presets
│   ├── logic.rs     # Instance creation logic, SSH key handling
│   ├── models.rs    # OCI API response models (serde)
│   ├── oci.rs       # OCI REST client with request signing
│   └── web.rs       # Axum web server, API handlers, task queue
├── static/
│   ├── index.html   # Admin dashboard (SPA)
│   └── login.html   # Login page
├── config.example   # Example config (tracked in git)
├── Cargo.toml       # Rust dependencies
└── .github/
    └── workflows/
        └── ci.yml   # CI: lint, test, audit, cross-platform builds
```

---

## CI / CD

GitHub Actions runs on every push and PR:

| Job | Description |
|-----|-------------|
| **Lint** | `cargo fmt --check` + `cargo clippy` |
| **Test** | `cargo test` on Linux, macOS, Windows |
| **Audit** | `cargo audit` for dependency vulnerabilities |
| **Build** | Release binaries for 5 targets |
| **Release** | Auto-creates GitHub Release on `v*` tag push |

### Build Targets

| Target | OS | Arch |
|--------|----|------|
| `x86_64-unknown-linux-musl` | Linux | x64 (Static) |
| `aarch64-unknown-linux-musl` | Linux | ARM64 (Static) |
| `x86_64-apple-darwin` | macOS | x64 |
| `aarch64-apple-darwin` | macOS | ARM64 |
| `x86_64-pc-windows-msvc` | Windows | x64 |

### Creating a Release

```bash
git tag v0.2.0
git push origin v0.2.0
```

---

## License

MIT
