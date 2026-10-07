#!/usr/bin/env bash
# Runs in the guest as root (hwcheck/scripts/*-hwcheck.sh, the pre-play check): with the time service stopped, moves
# the wall clock OFFSET seconds (ahead if positive, behind if negative), makes Evidence for an Enrollment at the
# Credential Authority and a Retrieval at the Secret Vault (hwrun, beside this script), and puts the clock and the time
# service back, whatever happens. The guest's root can set the clock so; so can a host that serves the guest its time
# (docs/limits.md, "Time").
#
#   preplay-guest.sh OFFSET OUT TEE KINDS
#
# KINDS: the Freshness Kinds to make Evidence for, comma-separated, or "all". The Targets of each kind are the host's
# (preplay-ca-targets.json and preplay-vault-targets.json beside this script); so are the Handles, minted by the live
# RRPs, which present-nonce and the epochs need (preplay-handles.json).
set -euo pipefail
offset=$1 out=$2 tee=$3 kinds=$4
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"
only=(); [ "$kinds" = all ] || only=(-kinds "$kinds")
handles=(); [ -f "$here/preplay-handles.json" ] && handles=(-handles "$here/preplay-handles.json")
stopped=()
for s in chrony chronyd systemd-timesyncd; do
  if systemctl is-active --quiet "$s" 2>/dev/null; then
    systemctl stop "$s"
    stopped+=("$s")
  fi
done
restore() {
  local now
  now=$(date -u +%s)
  date -u -s "@$((now - offset))" >/dev/null
  for s in ${stopped[@]+"${stopped[@]}"}; do systemctl start "$s"; done
  echo "the clock set back at $now (guest), to $((now - offset)); the time service started again: ${stopped[*]:-none}" \
    >>"$out/clock-offset-set.txt"
}
set_at=$(date -u +%s)
date -u -s "@$((set_at + offset))" >/dev/null
trap restore EXIT
echo "the time service stopped: ${stopped[*]:-none}; the clock set at $set_at (guest), to $((set_at + offset)), by $offset s" \
  >"$out/clock-offset-set.txt"
"$here/hwrun" -tee "$tee" ${only[@]+"${only[@]}"} -modes enroll -targets "$here/preplay-ca-targets.json" \
  ${handles[@]+"${handles[@]}"} -csr-cn payments.workload.tacra.example -out "$out/ca"
"$here/hwrun" -tee "$tee" ${only[@]+"${only[@]}"} -modes retrieve -targets "$here/preplay-vault-targets.json" \
  ${handles[@]+"${handles[@]}"} -cek mlkem768-p256 -out "$out/vault"
