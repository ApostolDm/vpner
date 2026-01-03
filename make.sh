#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "$0")" && pwd)
BUILD_DIR="$ROOT_DIR/build"
PKG_NAME=${PKG_NAME:-vpnerd}
PKG_VERSION=${PKG_VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo "0.0.0")}
GOOS=${GOOS:-linux}
ARCH_LIST=${ARCH_LIST:-arm64}
INSTALL_PREFIX=${INSTALL_PREFIX:-/opt}
OPKG_DEPENDS=${OPKG_DEPENDS:-"xray-core, ipset, iptables"}
INIT_NAME=${INIT_NAME:-S95vpnerd}
UPX_ARGS=${UPX_ARGS:---best}
DEFAULT_OPKG_ARCH=${DEFAULT_OPKG_ARCH:-}
UNIVERSAL_IPK=${UNIVERSAL_IPK:-}
UNIVERSAL_ARCH=${UNIVERSAL_ARCH:-all}
TAR_BIN=${TAR_BIN:-tar}
TAR_FORMAT=${TAR_FORMAT:-ustar}
DEFAULT_BIN_OUT=""
HOOK_SCRIPT_NAME=${HOOK_SCRIPT_NAME:-50-vpner}
DEFAULT_HOOK_OUT=""

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

log() { printf '==> %s\n' "$*"; }

render_postinst() {
  cat <<'POSTINST'
#!/bin/sh
set -e
VP_ROOT="__INSTALL_PREFIX__/etc/vpner"
CONF="$VP_ROOT/vpner.yaml"
EXAMPLE="$VP_ROOT/vpner.yaml.example"
INIT="__INSTALL_PREFIX__/etc/init.d/__INIT_NAME__"

mkdir -p "$VP_ROOT" "__INSTALL_PREFIX__/var/run"
if [ ! -f "$CONF" ] && [ -f "$EXAMPLE" ]; then
  cp "$EXAMPLE" "$CONF"
fi

if [ -d "$VP_ROOT/bins" ]; then
  detect_goarch() {
    arch=$(uname -m 2>/dev/null || echo "")
    case "$arch" in
      aarch64|arm64) echo "arm64" ;;
      armv7*|armv6*|armv5*) echo "arm" ;;
      mips64el|mips64le) echo "mips64le" ;;
      mips64) echo "mips64" ;;
      mipsel) echo "mipsle" ;;
      mips) echo "mips" ;;
      x86_64|amd64) echo "amd64" ;;
      i386|i486|i586|i686) echo "386" ;;
      *) echo "" ;;
    esac
  }

  goarch=$(detect_goarch)
  if [ -z "$goarch" ] && command -v opkg >/dev/null 2>&1; then
    opkg_arch=$(opkg print-architecture | awk '($3>max){max=$3; arch=$2} END{print arch}')
    case "$opkg_arch" in
      *aarch64*|*arm64*) goarch="arm64" ;;
      *armv7*|*armv6*|*arm*) goarch="arm" ;;
      *mipsel*|*mipsle*) goarch="mipsle" ;;
      *mips64le*|*mips64el*) goarch="mips64le" ;;
      *mips64*) goarch="mips64" ;;
      *mips*) goarch="mips" ;;
      *x86_64*|*amd64*) goarch="amd64" ;;
      *i386*|*i486*|*i586*|*i686*) goarch="386" ;;
    esac
  fi

  if [ -z "$goarch" ]; then
    echo "Unable to detect architecture for vpnerd binaries" >&2
    exit 1
  fi

  BIN="$VP_ROOT/bins/vpnerd-$goarch"
  HOOK="$VP_ROOT/bins/vpnerhookcli-$goarch"
  if [ ! -f "$BIN" ] || [ ! -f "$HOOK" ]; then
    echo "No vpnerd binaries for $goarch in $VP_ROOT/bins" >&2
    exit 1
  fi

  cp "$BIN" "$VP_ROOT/vpnerd"
  cp "$HOOK" "$VP_ROOT/vpnerhookcli"
  chmod 755 "$VP_ROOT/vpnerd" "$VP_ROOT/vpnerhookcli"
fi
if [ -x "$INIT" ]; then
  echo "Use $INIT {start|stop|restart|status} to control vpnerd"
fi
exit 0
POSTINST
}

render_ndm_hook() {
  cat <<'HOOK'
#!/bin/sh
if [ "${table}" = 'nat' ] && [ "${type}" = 'iptables' ]; then
  __INSTALL_PREFIX__/etc/vpner/vpnerhookcli --unix /tmp/vpner.sock --family ipv4 >/dev/null 2>&1 &
elif [ "${table}" = 'nat' ] && [ "${type}" = 'ip6tables' ]; then
  __INSTALL_PREFIX__/etc/vpner/vpnerhookcli --unix /tmp/vpner.sock --family ipv6 >/dev/null 2>&1 &
fi
exit 0
HOOK
}

render_init_script() {
  cat <<'INIT'
#!/bin/sh

CMD=/opt/etc/vpner/vpnerd
CFG=/opt/etc/vpner/vpner.yaml
PIDFILE=/opt/var/run/vpnerd.pid
LOGFILE=/opt/var/log/vpnerd.log
ARGS="--config $CFG"
PATH=/opt/sbin:/opt/bin:/opt/usr/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

is_running() {
  [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

start() {
  if is_running; then
    echo "vpnerd already running"
    return 0
  fi
  mkdir -p /opt/var/run /opt/var/log
  "$CMD" $ARGS >>"$LOGFILE" 2>&1 &
  echo $! > "$PIDFILE"
  echo "vpnerd started"
}

stop() {
  if is_running; then
    kill -15 "$(cat "$PIDFILE")" 2>/dev/null || true
    sleep 1
  fi
  rm -f "$PIDFILE"
  echo "vpnerd stopped"
}

status() {
  if is_running; then
    echo "vpnerd is running"
    return 0
  fi
  echo "vpnerd is stopped"
  return 1
}

case "$1" in
  start)
    start
    ;;
  stop)
    stop
    ;;
  restart)
    stop
    sleep 1
    start
    ;;
  status)
    status
    exit $?
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}" >&2
    exit 1
    ;;
esac
exit 0
INIT
}

apply_placeholders() {
  local file=$1
  local tmp="${file}.tmp"
  sed -e "s#__INSTALL_PREFIX__#$INSTALL_PREFIX#g" -e "s#__INIT_NAME__#$INIT_NAME#g" "$file" > "$tmp"
  mv "$tmp" "$file"
}

cleanup_dir() {
  local dir=$1
  if [[ -d $dir ]]; then
    chmod -R u+w "$dir" 2>/dev/null || true
    rm -rf "$dir"
  fi
}

build_arch() {
  local spec=$1
  local goarch=${spec%%:*}
  local pkgarch=${spec##*:}
  if [[ $spec != *:* ]]; then
    if [[ -n $DEFAULT_OPKG_ARCH ]]; then
      pkgarch=$DEFAULT_OPKG_ARCH
    else
      pkgarch=$goarch
    fi
  fi

  local work="$BUILD_DIR/$pkgarch"
  local bin_dir="$work/bin"
  local data_dir="$work/opkg/data"
  local control_dir="$work/opkg/CONTROL"
  local pkg_file="$BUILD_DIR/${PKG_NAME}_${PKG_VERSION}_${pkgarch}.ipk"
  local bin_path="$bin_dir/$PKG_NAME"
  local hook_bin="$bin_dir/vpnerhookcli"
  local conf_dir="$data_dir$INSTALL_PREFIX/etc/vpner"
  local init_dir="$data_dir$INSTALL_PREFIX/etc/init.d"
  local ndm_dir="$data_dir$INSTALL_PREFIX/etc/ndm/netfilter.d"

  cleanup_dir "$work"
  mkdir -p "$bin_dir" "$data_dir" "$control_dir" "$conf_dir" "$init_dir" "$ndm_dir" "$work/opkg"

  local gomodcache gocache gopath
  gomodcache=$(mktemp -d)
  gocache=$(mktemp -d)
  gopath=$(mktemp -d)

  log "Building $PKG_NAME for ${GOOS}/${goarch} -> $pkgarch"
  GOOS=$GOOS GOARCH=$goarch GOMODCACHE=$gomodcache GOCACHE=$gocache GOPATH=$gopath \
    go build -ldflags="-s -w" -o "$bin_path" ./cmd/vpnerd

  if command -v upx >/dev/null 2>&1; then
    log "Compressing binary with upx ($UPX_ARGS)"
    upx $UPX_ARGS "$bin_path" >/dev/null
  else
    log "upx not found; skipping compression"
  fi

  if [[ -z $DEFAULT_BIN_OUT ]]; then
    cp "$bin_path" "$ROOT_DIR/$PKG_NAME"
    chmod +x "$ROOT_DIR/$PKG_NAME"
    DEFAULT_BIN_OUT=1
  fi
  cp "$bin_path" "$ROOT_DIR/${PKG_NAME}-${goarch}"
  chmod +x "$ROOT_DIR/${PKG_NAME}-${goarch}"

  GOOS=$GOOS GOARCH=$goarch GOMODCACHE=$gomodcache GOCACHE=$gocache GOPATH=$gopath \
    go build -ldflags="-s -w" -o "$hook_bin" ./cmd/vpnerhookcli
  if command -v upx >/dev/null 2>&1; then
    log "Compressing hook binary with upx ($UPX_ARGS)"
    upx $UPX_ARGS "$hook_bin" >/dev/null || true
  fi

  if [[ -z $DEFAULT_HOOK_OUT ]]; then
    cp "$hook_bin" "$ROOT_DIR/vpnerhookcli"
    chmod +x "$ROOT_DIR/vpnerhookcli"
    DEFAULT_HOOK_OUT=1
  fi
  cp "$hook_bin" "$ROOT_DIR/vpnerhookcli-${goarch}"
  chmod +x "$ROOT_DIR/vpnerhookcli-${goarch}"

  install -m755 "$bin_path" "$conf_dir/vpnerd"
  install -m755 "$hook_bin" "$conf_dir/vpnerhookcli"
  install -m644 "$ROOT_DIR/vpner.yaml" "$conf_dir/vpner.yaml.example"
  mkdir -p "$data_dir$INSTALL_PREFIX/var/run"

  local init_tmp="$init_dir/$INIT_NAME"
  render_init_script > "$init_tmp"
  apply_placeholders "$init_tmp"
  chmod 755 "$init_tmp"

  local hook_tmp="$ndm_dir/$HOOK_SCRIPT_NAME"
  render_ndm_hook > "$hook_tmp"
  apply_placeholders "$hook_tmp"
  chmod 755 "$hook_tmp"

  render_postinst > "$control_dir/postinst"
  apply_placeholders "$control_dir/postinst"
  chmod 755 "$control_dir/postinst"

  cat <<CONTROL > "$control_dir/control"
Package: $PKG_NAME
Version: $PKG_VERSION
Architecture: $pkgarch
Maintainer: vpner
Section: net
Priority: optional
Depends: $OPKG_DEPENDS
Description: VPN orchestrator daemon with DNS + Xray controls
CONTROL

  log "Creating opkg archive $pkg_file"
  ( cd "$work/opkg" && \
    "$TAR_BIN" --format="$TAR_FORMAT" -czf control.tar.gz -C "$control_dir" . && \
    "$TAR_BIN" --format="$TAR_FORMAT" -czf data.tar.gz -C "$data_dir" . && \
    printf '2.0\n' > debian-binary && \
    "$TAR_BIN" --format="$TAR_FORMAT" -czf "$pkg_file" control.tar.gz data.tar.gz debian-binary && \
    rm -f control.tar.gz data.tar.gz debian-binary )

  cleanup_dir "$gomodcache"
  cleanup_dir "$gocache"
  cleanup_dir "$gopath"
  log "Package ready: $pkg_file"
}

build_universal() {
  local pkgarch=$UNIVERSAL_ARCH
  local work="$BUILD_DIR/universal"
  local data_dir="$work/opkg/data"
  local control_dir="$work/opkg/CONTROL"
  local pkg_file="$BUILD_DIR/${PKG_NAME}_${PKG_VERSION}_${pkgarch}.ipk"
  local conf_dir="$data_dir$INSTALL_PREFIX/etc/vpner"
  local bin_dir="$conf_dir/bins"
  local init_dir="$data_dir$INSTALL_PREFIX/etc/init.d"
  local ndm_dir="$data_dir$INSTALL_PREFIX/etc/ndm/netfilter.d"

  cleanup_dir "$work"
  mkdir -p "$bin_dir" "$data_dir" "$control_dir" "$conf_dir" "$init_dir" "$ndm_dir" "$work/opkg"

  for spec in $ARCH_LIST; do
    local goarch=${spec%%:*}
    local bin_src="$ROOT_DIR/$PKG_NAME-$goarch"
    local hook_src="$ROOT_DIR/vpnerhookcli-$goarch"
    if [[ ! -f $bin_src || ! -f $hook_src ]]; then
      log "Missing binaries for $goarch; build them first"
      exit 1
    fi
    install -m755 "$bin_src" "$bin_dir/vpnerd-$goarch"
    install -m755 "$hook_src" "$bin_dir/vpnerhookcli-$goarch"
  done

  install -m644 "$ROOT_DIR/vpner.yaml" "$conf_dir/vpner.yaml.example"
  mkdir -p "$data_dir$INSTALL_PREFIX/var/run"

  local init_tmp="$init_dir/$INIT_NAME"
  render_init_script > "$init_tmp"
  apply_placeholders "$init_tmp"
  chmod 755 "$init_tmp"

  local hook_tmp="$ndm_dir/$HOOK_SCRIPT_NAME"
  render_ndm_hook > "$hook_tmp"
  apply_placeholders "$hook_tmp"
  chmod 755 "$hook_tmp"

  render_postinst > "$control_dir/postinst"
  apply_placeholders "$control_dir/postinst"
  chmod 755 "$control_dir/postinst"

  cat <<CONTROL > "$control_dir/control"
Package: $PKG_NAME
Version: $PKG_VERSION
Architecture: $pkgarch
Maintainer: vpner
Section: net
Priority: optional
Depends: $OPKG_DEPENDS
Description: VPN orchestrator daemon with DNS + Xray controls
CONTROL

  log "Creating opkg archive $pkg_file"
  ( cd "$work/opkg" && \
    "$TAR_BIN" --format="$TAR_FORMAT" -czf control.tar.gz -C "$control_dir" . && \
    "$TAR_BIN" --format="$TAR_FORMAT" -czf data.tar.gz -C "$data_dir" . && \
    printf '2.0\n' > debian-binary && \
    "$TAR_BIN" --format="$TAR_FORMAT" -czf "$pkg_file" control.tar.gz data.tar.gz debian-binary && \
    rm -f control.tar.gz data.tar.gz debian-binary )

  log "Universal package ready: $pkg_file"
}

for spec in $ARCH_LIST; do
  build_arch "$spec"
done

if [[ -n $UNIVERSAL_IPK ]]; then
  build_universal
fi
patch placeholder
