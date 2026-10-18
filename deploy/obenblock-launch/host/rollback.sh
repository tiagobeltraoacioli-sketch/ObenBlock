#!/bin/bash
# Stop, roll back or remove ObenBlock on this host (run with sudo).
#
#   rollback.sh stop        stop and disable the obenblock-* units (data kept)
#   rollback.sh previous    point /opt/obenblock/current back at
#                           /opt/obenblock/previous and restart the units that
#                           were running (a bad binary upgrade)
#   rollback.sh remove      stop, disable and delete the obenblock-* units,
#                           /etc/obenblock and the ufw rules; /opt/obenblock
#                           and the chain data are moved aside to
#                           *.removed-<UTC time>, never deleted
#
# Only obenblock-* units and obenblock paths. GnB's gnb-node and the bloch-*
# units are never named here.
set -euo pipefail
die() { echo "rollback.sh: $*" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || die "run with sudo"
UNITS="obenblock-stratum.service obenblock-explorer-api.service obenblock-node.service"
stamp=$(date -u +%Y%m%dT%H%M%SZ)

stop_all() {
  for u in $UNITS; do
    if systemctl list-unit-files "$u" >/dev/null 2>&1 && systemctl cat "$u" >/dev/null 2>&1; then
      systemctl disable --now "$u" >/dev/null 2>&1 || true
      echo "$u: $(systemctl is-active "$u" 2>/dev/null || true)"
    fi
  done
  if pgrep -x obenblock >/dev/null; then
    die "an obenblock process is still running: $(pgrep -a -x obenblock | head -3)"
  fi
}

case ${1:-} in
  stop)
    stop_all
    echo "stopped; data in /var/lib/obenblock kept"
    ;;
  previous)
    prev=$(readlink /opt/obenblock/previous 2>/dev/null || true)
    [ -n "$prev" ] && [ -d "/opt/obenblock/$prev" ] || die "no previous release recorded"
    cur=$(readlink /opt/obenblock/current)
    running=""
    for u in $UNITS; do systemctl is-active --quiet "$u" && running="$running $u"; done
    ln -sfn "$prev" /opt/obenblock/current
    ln -sfn "$cur" /opt/obenblock/previous
    for u in $running; do systemctl restart "$u"; done
    echo "current -> $prev (was $cur); restarted:${running:- none}"
    ;;
  remove)
    stop_all
    for u in $UNITS; do rm -f "/etc/systemd/system/$u"; done
    rm -rf /etc/systemd/system/obenblock-explorer-api.service.d
    systemctl daemon-reload
    if command -v ufw >/dev/null; then
      ufw status numbered | grep 'ObenBlock' | sed -n 's/^\[ *\([0-9]*\)\].*/\1/p' | sort -rn |
        while read -r n; do ufw --force delete "$n" >/dev/null; done
    fi
    [ -d /etc/obenblock ] && mv /etc/obenblock "/etc/obenblock.removed-$stamp"
    [ -d /opt/obenblock ] && mv /opt/obenblock "/opt/obenblock.removed-$stamp"
    [ -d /var/lib/obenblock ] && mv /var/lib/obenblock "/var/lib/obenblock.removed-$stamp"
    echo "removed; kept as /etc/obenblock.removed-$stamp, /opt/obenblock.removed-$stamp, /var/lib/obenblock.removed-$stamp"
    ;;
  *) sed -n 2,16p "$0"; exit 64 ;;
esac
