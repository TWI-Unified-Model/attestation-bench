#!/usr/bin/env bash
# Runs in the guest as root (hwcheck/scripts/*-hwcheck.sh, the pre-play check): with the time service stopped, sets the
# wall clock AHEAD seconds ahead, makes absent-timestamp Evidence for an Enrollment at ENROLL_TARGET and a Retrieval at
# RETRIEVE_TARGET (hwrun, beside this script), and puts the clock and the time service back, whatever happens. The
# guest's root can set the clock so; so can a host that serves the guest its time (docs/limits.md, "Time").
#
#   preplay-guest.sh AHEAD OUT TEE ENROLL_TARGET RETRIEVE_TARGET
set -euo pipefail
ahead=$1 out=$2 tee=$3 enroll_target=$4 retrieve_target=$5
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$out"
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
  date -u -s "@$((now - ahead))" >/dev/null
  for s in ${stopped[@]+"${stopped[@]}"}; do systemctl start "$s"; done
  echo "the clock set back at $now (guest), to $((now - ahead)); the time service started again: ${stopped[*]:-none}" \
    >>"$out/clock-ahead.txt"
}
set_at=$(date -u +%s)
date -u -s "@$((set_at + ahead))" >/dev/null
trap restore EXIT
echo "the time service stopped: ${stopped[*]:-none}; the clock set at $set_at (guest), to $((set_at + ahead)), $ahead s ahead" \
  >"$out/clock-ahead.txt"
"$here/hwrun" -tee "$tee" -kinds absent-timestamp -modes enroll -target "$enroll_target" \
  -csr-cn payments.workload.tacra.example -out "$out/ca"
"$here/hwrun" -tee "$tee" -kinds absent-timestamp -modes retrieve -target "$retrieve_target" -cek mlkem768-p256 \
  -out "$out/vault"
