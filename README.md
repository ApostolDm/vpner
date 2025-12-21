# vpner

[Читать на русском](README.ru.md)

vpner is a compact networking stack for Entware/OpenWrt-style routers. It combines:

- an opinionated gRPC daemon (`vpnerd`) that controls iptables/ipset rules, DNS filtering, and Xray chains;
- a CLI (`vpnerctl`) that talks to the daemon over TCP or a UNIX socket;
- packaging scripts that produce installable `.ipk` images for multiple CPU architectures.

The whole system lives under `/opt/etc/vpner` by default and is designed to be dropped onto routers together with `xray-core`, `ipset`, and `iptables`.

---

## Highlights

- **Xray orchestration** – import links (`vmess://`, `vless://`, `ss://`), assign autorun, start/stop chains, delete stale configs, and wire them into iptables automatically.
- **DNS proxy with DoH upstreams** – UDP server with local caching, `custom-resolve` overrides that forward specific domains to arbitrary recursive resolvers, plus on-the-fly ipset population for unblock rules.
- **Unblock rules** – YAML-driven domain/IP/CIDR lists mapped to chain names, synced to ipset with comments so deletions clean up immediately.
- **Router-friendly packaging** – `make.sh` emits `.ipk` packages (config + init script + defaults) for any Go-supported architecture.
- **`vpnerctl` CLI** – manage DNS, Xray, interfaces, and unblock lists via gRPC; store connection info in `~/.vpner.cnf` or pass flags.
- **GitHub Releases** – tagging a version builds all binaries and attaches them to the release automatically.

---

## Repository layout

| Path | Description |
| --- | --- |
| `cmd/vpnerd` | Main daemon entrypoint. |
| `cmd/vpnerctl` | CLI for managing `vpnerd`. |
| `internal/network`, `internal/routing`, `internal/server` | iptables/ipset logic, Xray orchestration, and gRPC handlers. |
| `internal/runtime` | Wiring: DoH resolver, DNS service, gRPC setup. |
| `config/` | Configuration loader (`vpner.yaml`). |
| `proto/` + `internal/grpc/` | Protobuf definitions and generated gRPC code. |
| `tools/regenerate-proto` | Helper to re-run `protoc`. |
| `make.sh` | Multi-arch packaging script that produces `.ipk` files and raw binaries. |
| `.github/workflows/release.yml` | CI workflow that builds/attaches release artifacts. |

---

## Requirements

- Router/host with `/opt` (Entware/OpenWrt) and `opkg`.
- `xray-core`, `ipset`, `iptables`, `start-stop-daemon` (installed automatically when using the `.ipk`).
- Golang 1.25+ if you plan to build from source.
- `protoc` only if regenerating protobufs.

---

## Installation

### Option 1 – Install from release packages

1. Download the `.ipk` for your architecture from the GitHub Releases page. Filenames follow `vpnerd_<version>_<arch>.ipk` (e.g. `vpnerd_0.0.1_arm64.ipk`).
2. Copy it to the router and run:
   ```sh
   opkg update
   opkg install ./vpnerd_<version>_<arch>.ipk
   ```
   Dependencies (`xray-core`, `ipset`, `iptables`, `start-stop-daemon`) will be pulled automatically.
3. Files are installed under `/opt/etc/vpner/`:
- `/opt/etc/vpner/vpnerd` – the daemon binary.
- `/opt/etc/vpner/vpner.yaml` – created from `.example` on first install.
- `/opt/etc/vpner/vpner_unblock.yaml` – created lazily by the daemon.
- `/opt/etc/init.d/S95vpnerd` – init script.
- `/opt/etc/ndm/netfilter.d/50-vpner` – Keenetic hook that replays routing whenever the NAT table is rebuilt (it invokes `vpshookcli`).
4. Control the service via the init script:
   ```sh
   /opt/etc/init.d/S95vpnerd start   # stop|restart|status
   ```

### Keenetic DNS override

If you install vpner on Keenetic firmware you must force the router to push all DNS traffic through Entware. Right after installing the package run the following commands in the Entware shell:

```sh
opkg dns-override          # switch Keenetic DNS to /opt
system configuration save  # persist the change
reboot                     # apply it after a restart
```

After reboot every LAN client will use the DNS server shipped with `vpnerd`, and the bundled ndm hook (`/opt/etc/ndm/netfilter.d/50-vpner`) will automatically call `/opt/etc/vpner/vpshookcli --unix /tmp/vpner.sock` whenever Keenetic rebuilds the `nat` table.

### Option 2 – Build manually (vpnerd + vpnerctl)

1. Ensure Go 1.25+ is available on your machine.
2. Clone the repo and run:
   ```sh
   go build -ldflags="-s -w" -o vpnerd ./cmd/vpnerd
   go build -ldflags="-s -w" -o vpnerctl ./cmd/vpnerctl
   ```
3. Copy `vpnerd` to the router (e.g. `/opt/etc/vpner/vpnerd`), provide a config at `/opt/etc/vpner/vpner.yaml`, and create your own init script/service wrapper.

### Packaging with `make.sh`

`make.sh` automates the entire router-friendly packaging flow:

```sh
ARCH_LIST="arm64 mipsle:mipsel" ./make.sh
```

Produces:
- `build/vpnerd_<ver>_arm64.ipk`, `build/vpnerd_<ver>_mipsel.ipk`.
- `vpnerd`, `vpnerd-arm64`, `vpnerd-mipsle` in the repo root for manual flashing.

Key environment variables:

| Variable | Description | Default |
| --- | --- | --- |
| `ARCH_LIST` | Space-separated `goarch[:opkg-arch]` pairs to build. | `arm64` |
| `GOOS` | Target OS (shared by all arches). | `linux` |
| `INSTALL_PREFIX` | Where files land inside the package. | `/opt` |
| `PKG_VERSION` | Package version string. | `git describe` |
| `OPKG_DEPENDS` | Dependencies declared in `control`. | `"xray-core, ipset, iptables"` |
| `INIT_NAME` | Name of init script under `/opt/etc/init.d`. | `S95vpnerd` |
| `UPX_ARGS` | Arguments passed to `upx`. | `--best` |
| `DEFAULT_OPKG_ARCH` | Default opkg architecture if spec does not include `:arch`. | *(empty)* |
| `TAR_FORMAT` | Tar format used when creating `control.tar.gz`, `data.tar.gz`, and the final `.ipk`. Use `ustar` (default) to avoid Pax headers on macOS. | `ustar` |

Tip: run `opkg print-architecture` on the router to see the exact strings (e.g. `aarch64_cortex-a53`). Either set per-entry overrides (`ARCH_LIST="arm64:aarch64_cortex-a53"`) or export `DEFAULT_OPKG_ARCH=aarch64_cortex-a53` before invoking `make.sh`.

---

## Configuration

All settings live in `/opt/etc/vpner/vpner.yaml`. Example:

```yaml
dnsServer:
  port: 53
  max-concurrent-connections: 200
  verbose: false
  running: true
  custom-resolve:
    "1.1.1.1:53":
      - "*.example.internal"

doh:
  servers:
    - "https://dns.google/dns-query"
    - "https://cloudflare-dns.com/dns-query"
  resolvers:
    - "1.1.1.1"
    - "8.8.8.8"
  cache-ttl: 300

grpc:
  tcp:
    enabled: true
    address: ":50051"
    auth: true
  unix:
    enabled: true
    path: "/tmp/vpner.sock"
    auth: false
  auth:
    password: "secret123"

unblock-rules-path: "/opt/etc/vpner/vpner_unblock.yaml"
network:
  lan-interface: "br0"
  enable-ipv6: false
  ipset-debug: false
```

**Sections:**
- `dnsServer` – embedded UDP DNS proxy. `custom-resolve` maps wildcard domains to plain resolvers (`ip:port`). When `running: true`, the daemon autostarts the DNS service.
- `doh` – upstream DoH endpoints plus fallback UDP resolvers. Cache expiry in seconds.
- `grpc` – server endpoints for `vpnerctl`. TCP listener supports optional password (`authorization` metadata). UNIX socket can be auth-free.
- `unblock-rules-path` – YAML file storing domain/IP/CIDR rules. Each rule maps to an interface/chain and is synchronized into ipset with comments.
- `network.lan-interface` – interface used for iptables redirection when applying Xray routes.
- `network.enable-ipv6` – enable IPv6 ipset/ip6tables/ip -6 routing (default: false).
- `network.ipset-debug` – log reasons for ipset add/remove decisions (default: false).

The unblock file (`/opt/etc/vpner/vpner_unblock.yaml`) is created on demand and can include rules like:

```yaml
Xray:
  xray1:
    - "*.netflix.com"
    - "203.0.113.45"
OpenVPN:
  myvpn:
    - "internal.example.com"
```

Pattern validation matches `vpnerctl unblock` behavior (`*` at start/end only); IPs/CIDRs are stored with `timeout 0`.

---

## Running & managing

1. Start/stop the service via the init script or `start-stop-daemon` commands.
2. Interact with the daemon from any machine using `vpnerctl`. By default it tries `~/.vpner.cnf`:
   ```yaml
   addr: "router-hostname:50051"
   password: "secret123"
   # or specify unix: "/tmp/vpner.sock"
   ```
   Flags `--addr`, `--unix`, `--password`, `-c` override these values per command.

### Key `vpnerctl` commands

| Command | Description |
| --- | --- |
| `vpnerctl dns manage <start|stop|status|restart>` | Control the embedded DNS service. |
| `vpnerctl unblock list` | Show all unblock chains/rules. |
| `vpnerctl unblock add --chain <name> <pattern>` | Add domain/IP/CIDR to a chain; duplicates and overlaps are rejected. |
| `vpnerctl unblock del <pattern>` | Remove a pattern (domain or IP). |
| `vpnerctl unblock import-file --chain <name> --file rules.txt` | Bulk import; file may contain comments (`#`). |
| `vpnerctl unblock delete-file --file rules.txt` | Bulk delete.
| `vpnerctl interface scan` / `list` / `add` / `del` | Discover and register router interfaces. |
| `vpnerctl xray list` | Show chains, host, port, autorun and status. |
| `vpnerctl xray create <link> [--autorun]` | Import a new Xray config from link. |
| `vpnerctl xray start|stop|status <chain>` | Control chains manually. |
| `vpnerctl xray delete <chain>` | Remove config and related unblock chain. |
| `vpnerctl xray autorun <chain> --enable|--disable` | Toggle autorun on existing configs. |
| `vpnerctl hook restore` | Reapply iptables/ipset routing for all running VPN hooks (useful for Keenetic ndm hooks). |

### Router hooks (`vpshookcli`)

The package installs `/opt/etc/vpner/vpshookcli` – a tiny binary intended for automation scripts. It uses the same config resolution as `vpnerctl` (defaults to `/tmp/vpner.sock` / `:50051`). Running it triggers `HookRestore`, which re-applies routing for every running chain.

The opkg package already drops `/opt/etc/ndm/netfilter.d/50-vpner`, so Keenetic automatically runs `vpshookcli` whenever the firewall (iptables nat table) is rebuilt. OpenWrt/other systems can call the same binary from cron or custom rc scripts.

Every time Keenetic rebuilds the firewall, the hook replays vpner routing instantly. OpenWrt users can wire the same binary into `/etc/rc.local` or cron.

All commands return friendly messages; errors propagate as `GenericResponse_Error` with context.

---

## Building & testing

- Run `gofmt` on touched files and `GOCACHE=$(mktemp -d) go test ./...` before committing.
- Regenerate protobufs after editing `proto/*.proto`: `go run ./tools/regenerate-proto`.
- `make.sh` handles cross-compilation; you can also set `GOOS/GOARCH` manually for `vpnerctl`:
  ```sh
  GOOS=linux GOARCH=amd64 go build ./cmd/vpnerctl
  ```

---

## CI / Releases

`.github/workflows/release.yml` runs on tagged pushes (`v*`) or manual dispatch. It:
1. Builds `.ipk` packages via `make.sh` (using `ARCH_LIST` defined in the workflow).
2. Builds `vpnerctl` binaries for Linux amd64/arm64, macOS arm64, and Windows amd64.
3. Builds `vpshookcli` binaries for every router architecture in `ARCH_LIST`.
4. Uploads artifacts to the workflow run and attaches them to the GitHub Release corresponding to the tag.

To publish a release:
```sh
git tag v1.2.3
git push --tags
```
GitHub Actions will take care of the rest.

---

## Support & contributions

Bug reports, feature requests, and PRs are welcome. Please include:
- your router model / architecture;
- `vpner.yaml` snippets (redact secrets);
- logs from `/opt/etc/init.d/S95vpnerd status` or `vpnerctl` commands.

Before submitting patches:
1. Run `go test ./...` as shown above.
2. Ensure `make.sh` still finishes successfully (or at least `go build ./cmd/vpnerd` / `./cmd/vpnerctl`).
3. Explain any packaging/runtime changes in the PR description.

License: see `LICENSE` in the repository.
