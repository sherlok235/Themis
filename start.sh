#!/usr/bin/env bash
# PoWS — start all services in one command
# Usage: ./start.sh [--no-validators]

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

CYAN='\033[96m'
GREEN='\033[92m'
RED='\033[91m'
YELLOW='\033[93m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

PID_FILE="$SCRIPT_DIR/.pows_pids"

# ── cleanup on exit ───────────────────────────────────────────────────────────
STARTED=0
cleanup() {
  local code=$?
  if (( STARTED == 0 && code != 0 )); then
    # Failed during startup — just kill whatever was registered
    if [[ -f "$PID_FILE" ]]; then
      while IFS= read -r line; do
        pid="${line##*:}"
        kill "$pid" 2>/dev/null || true
      done < "$PID_FILE"
      rm -f "$PID_FILE"
    fi
    return
  fi
  echo -e "\n${YELLOW}Stopping all PoWS services…${NC}"
  if [[ -f "$PID_FILE" ]]; then
    while IFS= read -r line; do
      name="${line%%:*}"
      pid="${line##*:}"
      if kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null && echo -e "  ${DIM}stopped $name (pid $pid)${NC}"
      fi
    done < "$PID_FILE"
    rm -f "$PID_FILE"
  fi
  echo -e "${GREEN}All services stopped.${NC}"
}
trap cleanup EXIT INT TERM

# ── helpers ───────────────────────────────────────────────────────────────────
log()  { echo -e "${CYAN}▸${NC} $*"; }
ok()   { echo -e "${GREEN}✓${NC} $*"; }
err()  { echo -e "${RED}✗${NC} $*"; }
wait_for_port() {
  local port=$1 name=$2 logfile=${3:-""} attempts=0
  while ! nc -z 127.0.0.1 "$port" 2>/dev/null; do
    sleep 0.3
    (( attempts++ )) || true
    if (( attempts > 40 )); then
      err "$name did not start on port $port after 12s"
      if [[ -n "$logfile" && -f "$logfile" ]]; then
        echo -e "${DIM}  Last log lines from $logfile:${NC}"
        tail -5 "$logfile" | sed 's/^/    /'
      fi
      echo -e "${RED}Fix the error above, then re-run ./start.sh${NC}"
      exit 1
    fi
  done
  ok "$name ready on :$port"
}

register_pid() { echo "$1:$2" >> "$PID_FILE"; }
rm -f "$PID_FILE"

echo -e "\n${CYAN}${BOLD}⬡  PoWS — Proof-of-Web-State${NC}"
echo -e "${DIM}  Starting all services…${NC}\n"

# ── Kill anything already on PoWS ports (stale processes from old runs) ───────
for PORT in 3000 8000 8080 9001 9002 9003; do
  PIDS=$(lsof -ti tcp:$PORT 2>/dev/null || true)
  for PID in $PIDS; do
    CMD=$(ps -p "$PID" -o comm= 2>/dev/null || true)
    if [[ "$CMD" == *python* ]]; then
      kill "$PID" 2>/dev/null && echo -e "  ${YELLOW}⚠ killed stale python on :$PORT (pid $PID)${NC}"
    fi
  done
done

# ── Create logs directory ─────────────────────────────────────────────────────
mkdir -p "$SCRIPT_DIR/logs"

# ── helper: start a directory HTTP server (works on Python 3.6 and 3.7+) ─────
serve_dir() {
  local port=$1 dir=$2
  # --directory flag was added in Python 3.7; use cd fallback for safety
  (cd "$dir" && python3 -m http.server "$port")
}

# ── 1. Dashboard server ───────────────────────────────────────────────────────
log "Dashboard server → http://localhost:3000"
serve_dir 3000 "$SCRIPT_DIR/dashboard" \
  >> "$SCRIPT_DIR/logs/dashboard.log" 2>&1 &
register_pid "dashboard" $!
wait_for_port 3000 "Dashboard" "$SCRIPT_DIR/logs/dashboard.log"

# ── 2. Demo targets server ────────────────────────────────────────────────────
log "Demo targets server → http://localhost:8080"
serve_dir 8080 "$SCRIPT_DIR/demo_targets" \
  >> "$SCRIPT_DIR/logs/demo-targets.log" 2>&1 &
register_pid "demo-targets" $!
wait_for_port 8080 "Demo targets" "$SCRIPT_DIR/logs/demo-targets.log"

# ── 3. Validators ─────────────────────────────────────────────────────────────
if [[ "${1:-}" != "--no-validators" ]]; then
  for i in 1 2 3; do
    PORT=$((9000 + i))
    log "Validator-$i → http://localhost:$PORT"
    VALIDATOR_ID="validator-$i" PORT="$PORT" \
      python3 "$SCRIPT_DIR/validator/validator.py" \
      >> "$SCRIPT_DIR/logs/validator-$i.log" 2>&1 &
    register_pid "validator-$i" $!
    wait_for_port $PORT "Validator-$i" "$SCRIPT_DIR/logs/validator-$i.log"
  done

  # ── 4. Coordinator ───────────────────────────────────────────────────────────
  log "Coordinator → http://localhost:8000"
  VALIDATOR_1_URL="http://localhost:9001" \
  VALIDATOR_2_URL="http://localhost:9002" \
  VALIDATOR_3_URL="http://localhost:9003" \
  PORT=8000 \
    python3 "$SCRIPT_DIR/coordinator/coordinator.py" \
    >> "$SCRIPT_DIR/logs/coordinator.log" 2>&1 &
  register_pid "coordinator" $!
  wait_for_port 8000 "Coordinator" "$SCRIPT_DIR/logs/coordinator.log"
else
  echo -e "  ${DIM}Skipping validators + coordinator (--no-validators)${NC}"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo -e "\n${GREEN}${BOLD}All services running.${NC}\n"
echo -e "  ${BOLD}Dashboard${NC}      →  ${CYAN}http://localhost:3000${NC}"
echo -e "  ${BOLD}Demo targets${NC}   →  ${CYAN}http://localhost:8080${NC}"
if [[ "${1:-}" != "--no-validators" ]]; then
echo -e "  ${BOLD}Coordinator${NC}    →  ${CYAN}http://localhost:8000${NC}"
echo -e "  ${BOLD}Validator 1${NC}    →  ${CYAN}http://localhost:9001${NC}"
echo -e "  ${BOLD}Validator 2${NC}    →  ${CYAN}http://localhost:9002${NC}"
echo -e "  ${BOLD}Validator 3${NC}    →  ${CYAN}http://localhost:9003${NC}"
fi
echo -e "\n  ${DIM}Logs → $SCRIPT_DIR/logs/${NC}"
echo -e "  ${DIM}Press Ctrl+C to stop everything.${NC}\n"

# ── Open browser ──────────────────────────────────────────────────────────────
if command -v xdg-open &>/dev/null; then
  xdg-open "http://localhost:3000" &>/dev/null &
elif command -v open &>/dev/null; then
  open "http://localhost:3000" &>/dev/null &
fi

# ── Keep alive (wait for Ctrl+C) ──────────────────────────────────────────────
STARTED=1
wait
