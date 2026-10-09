# vpner

[Русская версия](README.ru.md)

`vpner` is a router-oriented networking stack for Entware/OpenWrt-style systems. It combines a daemon that manages DNS, Xray, iptables/ipset routing, and persistent unblock rules with small CLI utilities for administration and router hooks.

The project is designed first of all for Linux routers with `/opt`, and it fits Keenetic + Entware especially well.

## What is included

- `vpnerd` — the main daemon. Loads `vpner.yaml`, starts gRPC listeners, manages DNS, restores routing, and controls Xray chains.
- `vpnerctl` — the management CLI. Talks to `vpnerd` over a UNIX socket or TCP.
- `vpnerhookcli` — a small helper for router hooks. Reapplies routing after firmware/scripts rebuild `nat` or `mangle`.
- `make.sh` — packaging script that builds router-friendly `.ipk` packages.

## What `vpner` does

- Creates and manages Xray chains from `vmess://`, `vless://`, `trojan://`, `ss://` and `hysteria2://` links (3x-ui share links incl. XHTTP `extra`, REALITY/pqv, VLESS encryption, ECH, finalmask, mKCP headers, Hysteria2 salamander/port hopping). Hysteria2 and the `finalmask`-based features need an Xray-core from 2026 (v26.9+) on the router; TUIC and WireGuard/AmneziaWG links are not possible inside Xray.
- Runs a local DNS service with DoH upstreams and optional per-domain custom resolvers.
- Stores unblock rules in YAML and synchronizes them to `ipset`.
- Can switch to a full tunnel: all LAN internet traffic through one chain (`vpnerctl route all`), while explicit rules for other chains keep priority.
- Rebuilds iptables/ipset routing when the router flushes tables.
- Supports both classic `REDIRECT` mode and `TPROXY` mode.

## Requirements

- Linux router or host with root access.
- `/opt` filesystem layout if you use the packaged install.
- `opkg` for `.ipk` installation.
- `xray` available in `PATH` on the router.
- `iptables`, `ipset`, and `ip` tools available on the router.
- Go `1.25.4+` if you build from source.

## Recommended installation: `.ipk`

1. Download the package for your target architecture from Releases.
2. Copy it to the router and install it:

   ```sh
   opkg update
   opkg install ./vpnerd_<version>_<arch>.ipk
   ```

3. After installation, the router will have:

   | Path | Purpose |
   | --- | --- |
   | `/opt/etc/vpner/vpnerd` | Daemon binary |
   | `/opt/etc/vpner/vpnerhookcli` | Hook helper binary |
   | `/opt/etc/vpner/vpner.yaml.example` | Default config template |
   | `/opt/etc/vpner/vpner.yaml` | Active config, created on first install if missing |
   | `/opt/etc/vpner/vpner_unblock.yaml` | Persistent unblock rules file, created when rules are written |
   | `/opt/etc/vpner/xray/` | Stored Xray chain configs |
   | `/opt/etc/init.d/S95vpnerd` | Init script |
   | `/opt/etc/ndm/netfilter.d/50-vpner` | Keenetic hook that replays routing after `nat`/`mangle` rebuilds |

4. Edit `/opt/etc/vpner/vpner.yaml`.
5. Start the service:

   ```sh
   /opt/etc/init.d/S95vpnerd start
   ```

Useful service commands:

```sh
/opt/etc/init.d/S95vpnerd stop
/opt/etc/init.d/S95vpnerd restart
/opt/etc/init.d/S95vpnerd status
tail -f /opt/var/log/vpnerd.log
```

## Keenetic notes

### DNS override

If you run `vpner` on Keenetic with Entware, enable the Keenetic DNS override to `/opt` after installation.
Run the following commands from the **Keenetic CLI / Web CLI**, not from the Entware shell:

```sh
opkg dns-override
system configuration save
reboot
```

After reboot, LAN clients will use the DNS service handled by `vpnerd`, and the installed NDM hook will automatically call `vpnerhookcli` whenever Keenetic rebuilds `nat` or `mangle`.

### TPROXY on Keenetic

If you want transparent proxying through `TPROXY`, set:

```yaml
network:
  enable-tproxy: true
```

Important for Keenetic:

- `TPROXY` works only if the KeeneticOS **Kernel modules for Netfilter** component is installed in `General System Settings -> Component options`.
- In practice, `vpnerd` needs the kernel support behind `xt_TPROXY` and `xt_socket`.
- If the required netfilter modules are missing or unsupported, `vpnerd` logs a warning and automatically falls back to `REDIRECT` mode.

This is the exact case to check first if `enable-tproxy: true` does not have any effect on Keenetic.

## Configuration

The main config file is `/opt/etc/vpner/vpner.yaml`.

Minimal example:

```yaml
dnsServer:
  port: 53
  max-concurrent-connections: 100
  verbose: false
  running: true
  custom-resolve: {}

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
  auth:
    password: "secret123"

unblock-rules-path: "/opt/etc/vpner/vpner_unblock.yaml"

network:
  lan-interfaces:
    - "br0"
  enable-ipv6: false
  enable-tproxy: false
  ipset-debug: false
  ipset-stale-queries: 100
```

Important settings:

- `dnsServer.running` — start the embedded DNS server automatically on daemon startup.
- `dnsServer.custom-resolve` — map resolver addresses like `1.1.1.1:53` to domain patterns.
- `doh.servers` — DoH upstreams.
- `doh.resolvers` — classic DNS resolvers used for bootstrap/fallback logic.
- `grpc.tcp.enabled` — expose gRPC over TCP.
- `grpc.tcp.auth` — require the password from `grpc.auth.password` on the TCP listener.
- `grpc.unix.path` — local UNIX socket path for router-local administration.
- `network.lan-interfaces` — LAN interfaces whose traffic should be intercepted.
- `network.enable-ipv6` — enable IPv6 iptables/ipset/ip-rule handling.
- `network.enable-tproxy` — switch Xray/routing to transparent proxy mode when supported.
- `network.ipset-stale-queries` — delay removal of domain-derived IPs from `ipset` (legacy mode only, i.e. `ipset-entry-timeout: -1`): an IP is dropped after this many consecutive DNS answers for the same domain without it; `0` drops it on the first mismatch, `-1` never deletes (sets only grow, safest for long UDP sessions such as voice chats).

## Unblock rules file

`unblock-rules-path` points to a YAML file that stores domain/IP/CIDR rules grouped by VPN type and chain.

Example:

```yaml
Xray:
  xray1:
    - "*.netflix.com"
    - "203.0.113.45"
OpenVPN:
  myvpn:
    - "*.example.org"
```

Notes:

- Domain patterns must match the project validation rules.
- IPs and CIDRs are stored as static `ipset` entries.
- The file is updated automatically when you add or delete rules through `vpnerctl`.
- The full-tunnel target (`vpnerctl route all`) is NOT stored here; it lives next to it in `vpner_default_route.yaml` (`type:` + `chain:`). Delete that file to disable the full tunnel while the daemon is stopped.

## Full tunnel (route all)

`vpnerctl route all <chain>` sends **all** LAN internet traffic through one chain — a tracked router VPN interface (`OpenVPN0`, `Wireguard0`, ...) or an Xray chain (`xray1`). `vpnerctl route split` returns to per-rule routing; `vpnerctl route status` shows the mode (exit code 1 when a target is set but not active, e.g. the interface is down).

How it works:

- A `VPN_DEFAULT` chain is appended after every per-rule chain, so explicit `unblock` rules for *other* chains still win.
- The LAN never goes through the tunnel: the router's own addresses and connected subnets (re-read every watchdog tick and on interface events), private/link-local/multicast ranges (the built-in `local-exceptions` list is always applied here, in addition to any override in `vpner.yaml`) and, when the kernel has the `conntrack --ctdir` match, replies to inbound port-forwards are excluded (without that match `route all` prints a warning and port-forward replies follow the tunnel too).
- Only traffic entering from `lan-interfaces` is affected. Traffic originated by the router itself (including `vpnerd`'s DoH queries) stays on the WAN.
- The target is persisted and restored on daemon start, after Keenetic netfilter reloads and when the interface comes back up / the Xray chain is started. With `enable-ipv6: false`, AAAA answers are stripped for every name while the full tunnel is active, so dual-stack clients cannot bypass it over IPv6 via the router's DNS.

Limitations:

- No kill switch: if the router VPN goes down its routing table is empty and LAN traffic falls back to the WAN (`route status` reports it, the daemon logs a warning). A stopped Xray chain removes the full tunnel cleanly; a crashed one blackholes LAN traffic until the supervisor restarts it.
- REDIRECT mode (no TPROXY) proxies TCP only: UDP (QUIC, DNS to external resolvers) bypasses the tunnel. In TPROXY mode *all* LAN UDP goes through the Xray outbound, which must relay UDP (`vpnerctl xray test`). TPROXY/REDIRECT do not tunnel ICMP; a router VPN target does.
- Enabling/disabling resets connections that were established before the switch; in TPROXY mode UDP sessions that were tunnelled stay dark after `route split` until Xray times them out (or `xray stop`/`start`). Per-client exclusions are not supported.
- A `vpnerd` restart or upgrade leaves a short window on the WAN until routing is restored.

## Managing the daemon

`vpnerd` starts the following automatically:

- DNS service, if `dnsServer.running: true`
- all Xray chains with `auto_run: true`
- routing restore for already configured chains, including the full-tunnel target

The default daemon start command is:

```sh
/opt/etc/vpner/vpnerd --config /opt/etc/vpner/vpner.yaml
```

## `vpnerctl`

The `.ipk` package installs `vpnerd` and `vpnerhookcli`, but **does not install `vpnerctl`**. Build it separately if you want the admin CLI.

Build:

```sh
go build -o vpnerctl ./cmd/vpnerctl
```

Optional CLI config file: `~/.vpner.cnf`

```yaml
unix: "/tmp/vpner.sock"
addr: "router.example:50051"
password: "secret123"
timeout: "5s"
default-chain: "xray1"
```

Notes:

- If `unix` is set, `vpnerctl` uses the UNIX socket first.
- If neither `unix` nor `addr` is set, the defaults are `/tmp/vpner.sock` and `:50051`.
- TCP gRPC uses insecure transport in the current implementation. Keep it on a trusted network, or wrap it in SSH/VPN.

Common commands:

```sh
vpnerctl dns status
vpnerctl dns restart

vpnerctl xray list
vpnerctl xray create 'vless://...'         # also vmess://, trojan://, ss://, hysteria2://
vpnerctl xray create 'https://panel.example.com/sub/ID'   # subscription URL: every node becomes a chain (--index N for one)
vpnerctl xray update xray1 'https://panel.example.com/sub/ID' --index 1
vpnerctl xray create --file /opt/tmp/link.txt   # long links (REALITY pqv): the router shell cuts pasted lines
vpnerctl xray update xray1 'vless://...'   # swap server, keep the chain's rule pool
vpnerctl xray start xray1
vpnerctl xray stop xray1
vpnerctl xray autorun xray1 --enable
vpnerctl xray delete xray1

vpnerctl interface scan
vpnerctl interface list

vpnerctl unblock list
vpnerctl unblock add --chain xray1 "*.netflix.com"
vpnerctl unblock del "*.netflix.com"
vpnerctl unblock import-file --chain xray1 --file rules.txt
vpnerctl unblock delete-file --file rules.txt

vpnerctl route all xray1      # full tunnel: everything from the LAN via xray1
vpnerctl route status
vpnerctl route split          # back to per-rule routing
```

`default-chain` in `~/.vpner.cnf` only pre-fills `--chain` for `unblock` commands; `route all` always needs an explicit chain.

For Hysteria2, an empty or missing `sni` defaults to the server address when generating TLS settings. Static `ech`/`echConfigList` values are checked with Go's native TLS before import; invalid ECH is rejected with guidance. Replace it with a valid config, or remove the parameter if connecting without ECH is acceptable (the server name will be visible in the TLS ClientHello). Certificate verification stays enabled. Use `vpnerctl xray update` to change the stored link so the fix survives restarts: the JSON is regenerated from that link at startup.

## `vpnerhookcli`

`vpnerhookcli` is meant for automation and router hooks. In normal Keenetic installation you usually do not need to run it manually because the package installs `/opt/etc/ndm/netfilter.d/50-vpner`.

Manual example:

```sh
/opt/etc/vpner/vpnerhookcli --unix /tmp/vpner.sock --family ipv4 --table nat
```

Accepted values:

- `--family`: `ipv4`, `ipv6`, `v4`, `v6`
- `--table`: `nat`, `mangle`

## Build from source

Build all user-facing binaries:

```sh
go build -o vpnerd ./cmd/vpnerd
go build -o vpnerhookcli ./cmd/vpnerhookcli
go build -o vpnerctl ./cmd/vpnerctl
```

Run tests:

```sh
go test ./...
```

## Build `.ipk` packages

Basic example:

```sh
ARCH_LIST="arm64:aarch64_cortex-a53 mipsle:mipsel_24kc" ./make.sh
```

Universal package:

```sh
ARCH_LIST="arm64:aarch64_cortex-a53 mipsle:mipsel_24kc mips:mips_24kc" UNIVERSAL_IPK=1 ./make.sh
```

Useful variables:

- `ARCH_LIST` — target architectures in `goarch[:opkg-arch]` format.
- `DEFAULT_OPKG_ARCH` — default opkg architecture when `ARCH_LIST` entries omit `:opkg-arch`.
- `INSTALL_PREFIX` — package install prefix, `/opt` by default.
- `PKG_VERSION` — package version string.
- `UNIVERSAL_IPK` — build an additional `*_all.ipk`.

Build output:

- `build/*.ipk`
- `vpnerd`, `vpnerd-<goarch>`
- `vpnerhookcli`, `vpnerhookcli-<goarch>`

## Repository layout

| Path | Purpose |
| --- | --- |
| `cmd/vpnerd` | Daemon entrypoint |
| `cmd/vpnerctl` | Admin CLI |
| `cmd/vpnerhookcli` | Hook helper |
| `internal/app` | Runtime/bootstrap |
| `internal/network` | iptables/ipset/TPROXY logic |
| `internal/dns` | Embedded DNS server |
| `internal/doh` | DoH resolver |
| `internal/xray` | Xray config/process management |
| `internal/grpcserver` | gRPC handlers |
| `internal/config` | YAML config loading |
| `proto/` | Protobuf definitions |
| `make.sh` | `.ipk` packaging |

## Troubleshooting

- `xray binary not found in PATH`: install `xray-core` and make sure `xray` is visible in the daemon environment.
- `vpnerctl xray create` says `xray rejected the generated config`, or a REALITY chain comes out as plain VLESS: the link was cut short while pasting (the easiest workaround is to pass the subscription URL instead of the link: `vpnerctl xray create 'https://panel/sub/ID'`, add `--insecure` for a self-signed panel certificate) — busybox on the router truncates an input line at about 512 characters, and a 3x-ui REALITY link with `pqv` is ~2.8 KB. Put the link into a file (`scp`, or `cat > /opt/tmp/link.txt` followed by paste and Ctrl-D) and run `vpnerctl xray create --file /opt/tmp/link.txt` (or `xray update <chain> --file ...`).
- `vpnerctl xray create 'vpn://...'` (WireGuard / AmneziaWG config) is refused: Xray-core has no AmneziaWG support and 3x-ui runs AmneziaWG inside the panel, not in Xray. Import the `.conf` as a Keenetic WireGuard connection instead (KeeneticOS applies the ASC/AmneziaWG 1.0–2.0 parameters natively; blank the 3.x fields in the 3x-ui inbound), then `vpnerctl interface add <Wireguard id>`.
- DNS does not start on port `53`: another DNS service is already bound to that port.
- `enable-tproxy: true` has no effect on Keenetic: first verify the **Kernel modules for Netfilter** component in KeeneticOS.
- `vpnerctl` cannot reach the daemon: check whether you are connecting over `/tmp/vpner.sock` or TCP and whether the password matches `grpc.auth.password`.
- The whole LAN lost internet, or everything suddenly goes through a VPN: run `vpnerctl route status`; `vpnerctl route split` returns to per-rule routing (or delete `vpner_default_route.yaml` and restart the daemon).
