#!/usr/bin/env bash
# PoWS — stop ALL running PoWS services (by PID file AND by process scan)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/.pows_pids"

YELLOW='\033[93m'
GREEN='\033[92m'
DIM='\033[2m'
RED='\033[91m'
NC='\033[0m'

echo -e "${YELLOW}Stopping all PoWS services…${NC}"

KILLED=0

# ── 1. Kill by PID file ───────────────────────────────────────────────────────
if [[ -f "$PID_FILE" ]]; then
  while IFS= read -r line; do
    name="${line%%:*}"
    pid="${line##*:}"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null
      echo -e "  ${DIM}stopped $name (pid $pid)${NC}"
      KILLED=$((KILLED + 1))
    fi
  done < "$PID_FILE"
  rm -f "$PID_FILE"
fi

# ── 2. Kill any leftover Python processes on PoWS ports ──────────────────────
for PORT in 8000 8080 3000 9001 9002 9003; do
  PIDS=$(lsof -ti tcp:$PORT 2>/dev/null || true)
  for PID in $PIDS; do
    CMD=$(ps -p "$PID" -o comm= 2>/dev/null || true)
    if [[ "$CMD" == *python* ]]; then
      kill "$PID" 2>/dev/null && \
        echo -e "  ${DIM}killed leftover python on :$PORT (pid $PID)${NC}"
      KILLED=$((KILLED + 1))
    fi
  done
done

if (( KILLED == 0 )); then
  echo -e "${DIM}  Nothing was running.${NC}"
fi

echo -e "${GREEN}Done.${NC}"
