#!/usr/bin/env bash
# Start or stop the native Veraison deployment (~/veraison-deployment) as plain background processes: no launchd or
# systemd units are installed. Logs and pids go to ~/veraison-deployment/logs.
#
#   e2e/scripts/veraison-local.sh start|stop|status
set -euo pipefail
D="${VERAISON_DEPLOYMENT:-$HOME/veraison-deployment}"
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
      if [ "$s" = vts ]; then sleep 2; fi
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
