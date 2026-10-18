#!/bin/bash
# Stop, roll back or remove ObenBlock on this host (run with sudo).
#
#   rollback.sh stop        stop and disable the obenblock-* units (data kept)
#   rollback.sh previous    point /opt/obenblock/current back at
#                           /opt/obenblock/previous, reinstall that release's
#                           units and restart every enabled obenblock unit
#                           (a bad binary upgrade)
#   rollback.sh remove      stop, disable and delete the obenblock-* units,
#                           /etc/obenblock and the ufw rules; /opt/obenblock
#                           and the chain data are moved aside to
#                           *.removed-<UTC time>, never deleted (the
#                           witness key and the Stratum V2 authority key
#                           are inside /var/lib/obenblock)
#
# Only obenblock-* units and obenblock paths. GnB's gnb-node and the bloch-*
# units are never named here.
set -euo pipefail
die() { echo "rollback.sh: $*" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || die "run with sudo"
UNITS="obenblock-cpu-miner.service obenblock-stratum.service obenblock-explorer-api.service obenblock-explorer-firewall-reapply.timer obenblock-explorer-firewall-reapply.service obenblock-explorer-firewall.service obenblock-node.service"
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
  if pgrep -f '^/opt/obenblock/[^ ]*/obenblock-cpu-miner ' >/dev/null; then
    die "an obenblock-cpu-miner process is still running"
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
    ln -sfn "$prev" /opt/obenblock/current
    ln -sfn "$cur" /opt/obenblock/previous
    # The units of the release we go back to, then every enabled unit is
    # (re)started, including one crash-looping or failed on the bad release.
    for u in $UNITS; do
      [ -f "/etc/systemd/system/$u" ] && [ -f "/opt/obenblock/$prev/units/$u" ] && install -m 644 "/opt/obenblock/$prev/units/$u" "/etc/systemd/system/$u"
    done
    systemctl daemon-reload
    restarted=""
    for u in obenblock-node.service obenblock-cpu-miner.service obenblock-explorer-api.service obenblock-stratum.service; do
      if systemctl is-enabled --quiet "$u" 2>/dev/null; then
        systemctl reset-failed "$u" 2>/dev/null || true
        systemctl restart "$u"
        restarted="$restarted $u"
        [ "$u" = obenblock-node.service ] && sleep 5
      fi
    done
    echo "current -> $prev (was $cur); restarted:${restarted:- none}"
    ;;
  remove)
    stop_all
    for u in $UNITS; do rm -f "/etc/systemd/system/$u"; done
    rm -rf /etc/systemd/system/obenblock-explorer-api.service.d /etc/systemd/system/obenblock-node.service.d
    if [ -s /etc/obenblock/tls/cert-name ] && command -v certbot >/dev/null; then
      certbot delete --non-interactive --cert-name "$(head -1 /etc/obenblock/tls/cert-name)" >/dev/null 2>&1 || true
    fi
    rm -f /etc/letsencrypt/renewal-hooks/pre/obenblock-acme-open.sh /etc/letsencrypt/renewal-hooks/post/obenblock-acme-close.sh \
          /etc/letsencrypt/renewal-hooks/deploy/obenblock-explorer.sh
    systemctl daemon-reload
    command -v nft >/dev/null && nft delete table inet gnb_explorer 2>/dev/null || true
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
