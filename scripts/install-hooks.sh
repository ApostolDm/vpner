#!/bin/sh
set -e

PREFIX="${PREFIX:-/opt}"
HOOK_NAME="${HOOK_NAME:-50-vpner}"
DEBUG="${DEBUG:-1}"
LOG="${LOG:-$PREFIX/var/log/vpner-hooks.log}"
NDM="$PREFIX/etc/ndm"
BIN="$PREFIX/etc/vpner/vpnerhookcli"
SOCK="/tmp/vpner.sock"

if [ ! -x "$BIN" ]; then
	echo "WARNING: $BIN not found or not executable." >&2
	echo "         Hooks will be created but do nothing until vpnerhookcli is installed there." >&2
fi

mkdir -p "$(dirname "$LOG")"

emit_log_block() {
	[ "$DEBUG" = "1" ] || return 0
	cat >> "$2" <<EOF
{
  echo "===== \$(date) hook=$1 args=[\$*] ====="
  env
  echo
} >> $LOG 2>&1
EOF
}

write_netfilter_hook() {
	printf '#!/bin/sh\n' > "$1"
	emit_log_block "netfilter" "$1"
	cat >> "$1" <<EOF
case "\${table}" in
  nat|mangle)
    case "\${type}" in
      iptables)
        $BIN --unix $SOCK --family ipv4 --table "\${table}" >/dev/null 2>&1 &
        ;;
      ip6tables)
        $BIN --unix $SOCK --family ipv6 --table "\${table}" >/dev/null 2>&1 &
        ;;
    esac
    ;;
esac
exit 0
EOF
}
write_iface_hook() {
	printf '#!/bin/sh\n' > "$1"
	emit_log_block "$2" "$1"
	cat >> "$1" <<EOF
[ -n "\${id}" ] || exit 0
[ "\${connected}" = "yes" ] || exit 0
$BIN --unix $SOCK --iface "\${id}" --sysname "\${system_name}" --event up >/dev/null 2>&1 &
exit 0
EOF
}

for d in netfilter.d ifstatechanged.d ifipchanged.d ifip6changed.d; do
	mkdir -p "$NDM/$d"
done

write_netfilter_hook "$NDM/netfilter.d/$HOOK_NAME"
write_iface_hook "$NDM/ifstatechanged.d/$HOOK_NAME" "ifstatechanged"
write_iface_hook "$NDM/ifipchanged.d/$HOOK_NAME" "ifipchanged"
write_iface_hook "$NDM/ifip6changed.d/$HOOK_NAME" "ifip6changed"

chmod 755 \
	"$NDM/netfilter.d/$HOOK_NAME" \
	"$NDM/ifstatechanged.d/$HOOK_NAME" \
	"$NDM/ifipchanged.d/$HOOK_NAME" \
	"$NDM/ifip6changed.d/$HOOK_NAME"

rm -f "$NDM/iflayerchanged.d/$HOOK_NAME"

echo "Recreated vpner hooks:"
for d in netfilter.d ifstatechanged.d ifipchanged.d ifip6changed.d; do
	echo "  $NDM/$d/$HOOK_NAME"
done

if [ "$DEBUG" = "1" ]; then
	echo
	echo "DEBUG logging is ON. Every trigger appends its env to:"
	echo "  $LOG"
	echo "Watch it live with:  tail -f $LOG"
	echo "Turn it off later with:  DEBUG=0 sh install-hooks.sh"
fi

if [ -x "$BIN" ] && [ -S "$SOCK" ]; then
	echo "Triggering an immediate routing restore..."
	"$BIN" --unix "$SOCK" >/dev/null 2>&1 || echo "  (vpnerd not reachable on $SOCK; it will restore on the next event)"
fi

echo "Done."
echo
echo "Test manually (simulate a connected interface):"
echo "  id=OpenVPN0 system_name=ovpn_br0 connected=yes up=up $NDM/ifstatechanged.d/$HOOK_NAME hook"
echo "then check the vpnerd log."
