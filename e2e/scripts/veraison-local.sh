#!/usr/bin/env bash
# Start or stop the native Veraison deployment (VERAISON_DEPLOYMENT, default BENCH_HOME/veraison: scripts/lib.sh) as
# plain background processes: no launchd or systemd units are installed. Logs and pids go to its logs/ directory.
#
#   e2e/scripts/veraison-local.sh start|stop|status
set -euo pipefail
# shellcheck source=SCRIPTDIR/../../scripts/lib.sh
. "$(cd "$(dirname "$0")/../.." && pwd)/scripts/lib.sh"
D="$VERAISON_DEPLOYMENT"
CFG="$D/config/services/config.yaml"
SERVICES=(vts provisioning verification management)
mkdir -p "$D/logs"
case "${1:-status}" in
  start)
    for s in "${SERVICES[@]}"; do
      pidf="$D/logs/$s.pid"
      if [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then echo "$s already running ($(cat "$pidf"))"; continue; fi
      cd "$D"
      nohup "$D/bin/$s-service" --config="$CFG" > "$D/logs/$s.log" 2>&1 &
      echo $! > "$pidf"
      echo "$s started ($(cat "$pidf"))"
      # the other services connect to VTS when they start (gRPC, localhost:50051) and back off for a while when it is
      # not there yet, so they start only once VTS listens; a fixed pause was too short on a first start
      if [ "$s" = vts ]; then bench_wait_port 50051 || { echo "vts did not open 50051 (see $D/logs/vts.log)" >&2; exit 1; }; fi
    done ;;
  stop)
    for s in "${SERVICES[@]}"; do
      pidf="$D/logs/$s.pid"
      if [ -f "$pidf" ]; then
        pid="$(cat "$pidf")"
        if kill "$pid" 2>/dev/null; then
          for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
          echo "$s stopped"
        else
          echo "$s was not running"
        fi
        rm -f "$pidf"
      fi
    done ;;
  status)
    for s in "${SERVICES[@]}"; do
      pidf="$D/logs/$s.pid"
      if [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then echo "$s running ($(cat "$pidf"))"; else echo "$s stopped"; fi
    done ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
