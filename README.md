# OCI Manager

A fast, single-binary CLI + Web UI for managing Oracle Cloud Infrastructure (OCI) Compute instances — built in Rust.

## Features

- **Multi-profile support** — manage multiple OCI tenancies from a single config file
- **Create / Terminate / Reboot** instances via CLI or Web UI
- **Flex shapes** — configure OCPUs and Memory for `VM.Standard.A1.Flex`, `E4.Flex`, etc.
- **Presets** — save reusable instance configurations (shape, OS, resources) in config
- **Auto-selection** — automatically picks availability domain, image, and shape when not specified
- **Task queue** — Web UI queues create requests with automatic retry; tasks can be stopped
- **Cron mode** — headless `cron` subcommand for scheduling via system cron / Windows Task Scheduler
- **Web UI** with admin key authentication and profile selector
- **Internationalization** — Web UI supports English and Chinese (EN/ZH)
- **Cross-platform** — builds for Linux (x64/ARM64), macOS (x64/ARM64), and Windows (x64)

---

## Quick Start

### 1. Prerequisites

- [Rust toolchain](https://rustup.rs/) (cargo + rustc)
- An OCI API signing key (`.pem` file) — [How to generate](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/apisigningkey.htm)
- Network access to OCI API endpoints

### 2. Build

```bash
cargo build --release
```

The binary will be at `target/release/oci-manager` (or `oci-manager.exe` on Windows).

### 3. Configure

Copy the example config and fill in your credentials:

```bash
# Linux / macOS
cp config.example ~/.oci/config

# Windows (PowerShell)
Copy-Item config.example $env:USERPROFILE\.oci\config
```

Edit the file and replace the placeholder values with your real OCI credentials.

> ⚠️ **NEVER commit your real `config` file or `.pem` keys to git!**
> The `config` file is in `.gitignore` — only `config.example` is tracked.

---

## Configuration Reference

The config file uses INI format (same as `~/.oci/config`).

### Config File Location (priority order)

| Priority | Source |
|----------|--------|
| 1 | `--config <path>` CLI flag |
| 2 | `./config` (current working directory) |
| 3 | `~/.oci/config` (user home) |

### Profile Fields

```ini
[DEFAULT]
# ── Required ──────────────────────────────────
user=ocid1.user.oc1..aaaaaaaaexample      # Your user OCID
fingerprint=aa:bb:cc:dd:ee:ff:00:11:22:33  # API key fingerprint
tenancy=ocid1.tenancy.oc1..aaaaaaaaexample # Tenancy OCID
region=us-phoenix-1                         # OCI region identifier
key_file=/path/to/oci_api_key.pem          # Path to private key

# ── Optional defaults ─────────────────────────
compartment=ocid1.compartment.oc1..example # Default compartment
subnet=ocid1.subnet.oc1..example           # Default subnet
shape=VM.Standard.E4.Flex                  # Default shape
availability_domain=Uocm:PHX-AD-1          # Default AD
ssh_public_key=/path/to/id_rsa.pub         # SSH public key (path or inline)
display_name_prefix=auto                   # Prefix for auto-generated names
boot_volume_size_gbs=50                    # Boot volume size (GB)
ocpus=1                                    # Default OCPUs (Flex shapes)
memory_in_gbs=6                            # Default memory GB (Flex shapes)

# ── Web UI ────────────────────────────────────
enable_admin=true                          # Enable web UI
admin_key=your-strong-random-key           # Authentication key
```

### Multiple Profiles

Add additional `[SECTION]` blocks for different tenancies:

```ini
[SECONDARY]
user=ocid1.user.oc1..example2
fingerprint=bb:cc:dd:ee:ff:00:11:22:33:44
tenancy=ocid1.tenancy.oc1..example2
region=eu-frankfurt-1
key_file=/path/to/key2.pem
```

Switch profiles with `--profile SECONDARY` (CLI) or the dropdown in the Web UI.

### Presets

Define reusable instance configurations with `[preset:NAME]`:

```ini
[preset:ARM-1cpu-6gb-Ubuntu]
shape=VM.Standard.A1.Flex
ocpus=1
memory_in_gbs=6
image_os=Canonical Ubuntu
image_version=22.04
display_name_prefix=arm-ubuntu
```

All preset fields are optional and override profile defaults when selected.

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

# Terminate
oci-manager instance terminate --instance <ocid>

# Reboot (soft or hard)
oci-manager instance reboot --instance <ocid>
oci-manager instance reboot --instance <ocid> --hard

# Check availability domains and shapes
oci-manager availability --compartment <ocid>
```

### Web UI

```bash
# Start on localhost (default)
oci-manager serve

# Start on custom port
oci-manager serve --port 9090

# Allow remote access (use with caution — add TLS via reverse proxy)
oci-manager serve --host 0.0.0.0 --port 8080 --allow-remote
```

Open `http://127.0.0.1:8080`, enter your `admin_key`, and use the UI to:
- Select profiles and presets
- Create instances with full form validation
- Queue tasks with automatic retry (and **Stop** them)
- View, reboot, and terminate running instances

---

## Linux One-Click Installation (Ubuntu/CentOS/ARM/x86)

Run this command on your Linux server to automatically download the latest binary and setup the **systemd** service on port `9927`:

```bash
curl -sSf https://raw.githubusercontent.com/umalaaa/oci-manager/main/install.sh | sudo bash
```

### After Installation:
1. **Configure**: `sudo nano /etc/oci-manager/config` (fill in your OCIDs).
2. **Key**: Place your OCI API `.pem` key at `/etc/oci-manager/key.pem`.
3. **Start**: `sudo systemctl enable --now oci-manager`
4. **Access**: Open `http://your-server-ip:9927` in your browser.

## Uninstallation

To stop the service and remove all files (including configs):

```bash
curl -sSf https://raw.githubusercontent.com/umalaaa/oci-manager/main/uninstall.sh | bash
```


### Cron Mode (Background / Scheduled)

The `cron` subcommand runs a single create attempt (or retry loop) and exits. Perfect for system schedulers:

```bash
# Single attempt using a preset
oci-manager cron --preset ARM-1cpu-6gb-Ubuntu

# With retry (keeps trying every 3 minutes, max 10 attempts)
oci-manager cron --preset ARM-4cpu-24gb-OracleLinux --retry --retry-seconds 180 --retry-max 10

# Override preset values
oci-manager cron --preset ARM-1cpu-6gb-Ubuntu --ocpus 2 --memory-gbs 12

# Full manual specification
oci-manager cron \
  --shape VM.Standard.A1.Flex --ocpus 1 --memory-gbs 6 \
  --image-os "Canonical Ubuntu" --image-version 22.04 \
  --retry
```

**Linux cron example** (try every 5 minutes):
```cron
*/5 * * * * /usr/local/bin/oci-manager --config /home/user/.oci/config cron --preset ARM-1cpu-6gb-Ubuntu >> /var/log/oci-cron.log 2>&1
```

**Windows Task Scheduler**: Create a task that runs `oci-manager.exe cron --preset ARM-1cpu-6gb-Ubuntu --retry` on your desired schedule.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OCI_PROFILE` | Default profile name (instead of `--profile`) |
| `OCI_ADMIN_KEY` | Admin key for web UI (instead of config/`--admin-key`) |
| `RUST_LOG` | Log level (`info`, `debug`, `trace`) |

---

## Security

### For Public Repositories

This project is designed to be safe for public GitHub repos:

| Item | Protection |
|------|------------|
| OCI credentials | `.gitignore` blocks `config`, `*.pem`, `*.key` |
| Admin key | Never hardcoded; set via config file or `OCI_ADMIN_KEY` env var |
| Web UI binding | Defaults to `127.0.0.1`; requires `--allow-remote` for non-loopback |
| Authentication | All API endpoints require `admin_key` via header, bearer token, or cookie |
| SSH keys (Web UI) | Inline-only validation prevents file path traversal |

### Recommendations

- Use a **strong, random `admin_key`** (32+ characters)
- For remote access, place behind a **reverse proxy with TLS** (Caddy, nginx)
- Set `RUST_LOG=info` in production to avoid leaking sensitive data in debug logs
- Rotate API keys periodically

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## Development

### Run Tests

```bash
cargo test
```

### Format & Lint

```bash
cargo fmt
cargo clippy --all-targets -- -D warnings
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
├── config.example   # Safe example config (tracked in git)
├── .gitignore       # Blocks credentials, build artifacts, logs
├── SECURITY.md      # Security policy & vulnerability reporting
├── Cargo.toml       # Rust dependencies
└── .github/
    └── workflows/
        └── ci.yml   # CI: lint, test, audit, cross-platform builds
```

---

## CI / CD

The GitHub Actions pipeline (`.github/workflows/ci.yml`) runs on every push and PR:

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
| `x86_64-unknown-linux-gnu` | Linux | x64 |
| `aarch64-unknown-linux-gnu` | Linux | ARM64 |
| `x86_64-apple-darwin` | macOS | x64 |
| `aarch64-apple-darwin` | macOS | ARM64 (Apple Silicon) |
| `x86_64-pc-windows-msvc` | Windows | x64 |

### Creating a Release

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions will build all targets and create a release with downloadable binaries.

---

## License

MIT
