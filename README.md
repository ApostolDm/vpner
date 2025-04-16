# vpner

This project provides a VPN manager with support for running Xray chains.
Use the `make.sh` script to cross-compile the `vpnerd` daemon for a router (Entware/OpenWrt style environments). The script assembles ready-to-install `.ipk` packages (one per architecture) that include:

- `/opt/etc/vpner/vpnerd` – the daemon binary (launched with `--config /opt/etc/vpner/vpner.yaml`).
- `/opt/etc/vpner/vpner.yaml.example` – default config copied to `vpner.yaml` on first install.
- `/opt/etc/init.d/S95vpnerd` – init script (`start|stop|restart|status`) wired to `start-stop-daemon`.

Example run:

```
$ ./make.sh
==> Building vpnerd for linux/arm64 -> arm64
==> Compressing binary with upx (--best)
==> Creating opkg archive build/vpnerd_<version>_arm64.ipk
==> Package ready: build/vpnerd_<version>_arm64.ipk
```

Artifacts:

- `vpnerd` – raw binary for the first built architecture, plus `vpnerd-<arch>` copies for every target.
- `build/vpnerd_<version>_<arch>.ipk` – opkg packages with config, init script, and dependencies declared.

Use `vpnerctl` to manage the daemon remotely. For example, toggle Xray autorun on an existing chain:

```
vpnerctl xray autorun mychain --enable   # or --disable
```

The script accepts a few helpful overrides via environment variables:

| Variable | Purpose | Default |
| --- | --- | --- |
| `ARCH_LIST` | space-separated list of `GOARCH` targets (`goarch[:opkg-arch]`) | `arm64` |
| `GOOS` | target OS for all builds | `linux` |
| `INSTALL_PREFIX` | install prefix inside the package | `/opt` |
| `PKG_VERSION` | package version string | `git describe` output |
| `OPKG_DEPENDS` | dependencies written to `Depends:` | `"xray-core, ipset, iptables, start-stop-daemon"` |
| `INIT_NAME` | name of the init script under `/opt/etc/init.d` | `S95vpnerd` |

Examples:

Build for arm64 and little-endian MIPS (with custom opkg arch tag) in one pass:

```
ARCH_LIST="arm64 mipsle:mipsel" ./make.sh
```

Override dependencies and init script name:

```
OPKG_DEPENDS="xray-core,ipset" INIT_NAME=S80vpnerd ./make.sh
```

## GitHub CI builds

Tagging a release (`git tag vX.Y.Z && git push --tags`) triggers the `release` workflow (`.github/workflows/release.yml`).
It cross-builds:

- opkg packages for each `ARCH_LIST` target (same layout as `make.sh`).
- `vpnerctl` binaries for Linux (amd64/arm64), Windows (amd64), and macOS (arm64).

Artifacts are uploaded to the workflow run and, when building from a tag, attached to the GitHub release so you can download `.ipk` packages and standalone CLI binaries directly from the Releases page.
