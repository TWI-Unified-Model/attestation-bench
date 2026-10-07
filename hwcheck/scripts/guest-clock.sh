#!/usr/bin/env bash
# Runs in the guest as root (hwcheck/scripts/*-hwcheck.sh): writes DIR/clock.txt, what the guest's clock rests on. The
# kernel's clocksource and the ones it could take, its command line (no-kvmclock, tsc=), the boot lines on SEV, TDX,
# the TSC and the clocksource (the "SEV: Status:" line lists SecureTSC when the guest has AMD's Secure TSC), and the
# time service with its servers. Neither SEV-SNP nor TDX gives a guest a trusted date: it comes from the host, through
# kvm-clock or the RTC, or from the cloud's time service (docs/limits.md, "Time").
#
#   guest-clock.sh DIR
set -uo pipefail
dir=$1
{
  echo "guest clock (UTC, seconds): $(date -u +%s.%N)"
  echo "clocksource: $(cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null)"
  echo "available clocksources: $(cat /sys/devices/system/clocksource/clocksource0/available_clocksource 2>/dev/null)"
  echo "kernel command line: $(cat /proc/cmdline)"
  echo "-- boot lines on SEV, TDX, the TSC and the clocksource (dmesg)"
  dmesg 2>/dev/null | grep -i -E 'SEV: Status|Memory Encryption|tdx|secure.?tsc|tsc|clocksource|kvm-clock' | head -40
  echo "-- the time service"
  for s in chrony chronyd systemd-timesyncd ntp ntpsec; do
    if systemctl is-active --quiet "$s" 2>/dev/null; then echo "active: $s"; fi
  done
  chronyc -n sources 2>/dev/null
  chronyc -n authdata 2>/dev/null # how each source is authenticated: NTS, a symmetric key, or none
  timedatectl show-timesync --all 2>/dev/null
} >"$dir/clock.txt"
exit 0 # a record: what a command could not tell (no chrony, no timesyncd) is missing from it, and stops nothing
