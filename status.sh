#!/usr/bin/env bash
# PoWS — show what is currently running on each service port

CYAN='\033[96m'
GREEN='\033[92m'
RED='\033[91m'
DIM='\033[2m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "\n${CYAN}${BOLD}⬡  PoWS — Service Status${NC}\n"

declare -A NAMES=(
  [3000]="Dashboard       "
  [8080]="Demo targets    "
  [8000]="Coordinator     "
  [9001]="Validator-1     "
  [9002]="Validator-2     "
  [9003]="Validator-3     "
)

for PORT in 3000 8080 8000 9001 9002 9003; do
  NAME="${NAMES[$PORT]}"
  PIDS=$(lsof -ti tcp:$PORT 2>/dev/null || true)
  if [[ -n "$PIDS" ]]; then
    PID=$(echo "$PIDS" | head -1)
    CMD=$(ps -p "$PID" -o args= 2>/dev/null | cut -c1-60 || echo "?")
    echo -e "  ${GREEN}●${NC} $NAME :$PORT  ${DIM}pid=$PID  $CMD${NC}"
  else
    echo -e "  ${RED}○${NC} $NAME :$PORT  ${DIM}not running${NC}"
  fi
done

echo ""
