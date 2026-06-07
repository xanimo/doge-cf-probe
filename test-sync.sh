#!/usr/bin/env bash
# test-sync.sh
# Times a fresh doge-cf-probe index sync from genesis with N workers, then verifies
# serve mode responds correctly to a BIP157 filter request.
#
# Usage:
#   ./test-sync.sh                      # 8 workers, mainnet, temp db
#   WORKERS=4 ./test-sync.sh
#   NET=testnet ./test-sync.sh
#   DB=/tmp/test.db ./test-sync.sh      # keep db after run
#   SERVE_TEST=0 ./test-sync.sh         # skip serve verification

set -euo pipefail

PROBE_DIR="$(cd "$(dirname "$0")" && pwd)"
PROBE_BIN="$PROBE_DIR/doge-cf-probe"

NET="${NET:-mainnet}"
WORKERS="${WORKERS:-8}"
SERVE_PORT="${SERVE_PORT:-29999}"
SERVE_TEST="${SERVE_TEST:-1}"

# Temp db unless caller provides one
KEEP_DB=0
if [[ -n "${DB:-}" ]]; then
  KEEP_DB=1
else
  DB="$(mktemp /tmp/doge-cf-probe-test-XXXXXX.db)"
  rm -f "$DB"  # mktemp creates the file; bbolt will create it fresh
fi

# -- RPC credentials ----------------------------------------------------------

RPC_USER="${DOGE_RPC_USER:-}"
RPC_PASS="${DOGE_RPC_PASS:-}"

if [[ -z "$RPC_PASS" ]]; then
  CONF="$HOME/.dogecoin/dogecoin.conf"
  [[ "$NET" == "testnet" ]] && CONF="$HOME/.dogecoin/testnet3/dogecoin.conf"
  if [[ -f "$CONF" ]]; then
    RPC_PASS=$(grep -E '^rpcpassword=' "$CONF" | cut -d= -f2- | tr -d '[:space:]' || true)
    RPC_USER=$(grep -E '^rpcuser='     "$CONF" | cut -d= -f2- | tr -d '[:space:]' || echo "dogecoinrpc")
  fi
  if [[ -z "$RPC_PASS" ]]; then
    echo "ERROR: set DOGE_RPC_PASS or add rpcpassword= to dogecoin.conf"
    exit 1
  fi
fi

case "$NET" in
  mainnet) RPC_URL="http://127.0.0.1:22555"; P2P_PORT=22556 ;;
  testnet) RPC_URL="http://127.0.0.1:44555"; P2P_PORT=44556 ;;
  regtest) RPC_URL="http://127.0.0.1:18332"; P2P_PORT=18444 ;;
  *) echo "ERROR: unknown NET=$NET"; exit 1 ;;
esac

rpc() {
  curl -s -u "${RPC_USER}:${RPC_PASS}" \
    --data-binary "{\"jsonrpc\":\"1.1\",\"id\":1,\"method\":\"$1\",\"params\":[${2:-}]}" \
    -H 'Content-Type: application/json' "$RPC_URL"
}

rpc_val() {
  rpc "$@" | python3 -c "
import sys,json; d=json.load(sys.stdin)
if d.get('error'): raise SystemExit('rpc error: '+str(d['error']))
print(d['result'])"
}

log() { echo "[$(date '+%H:%M:%S')] $*"; }

cleanup() {
  [[ -n "${SERVE_PID:-}" ]] && kill "$SERVE_PID" 2>/dev/null || true
  if [[ "$KEEP_DB" == "0" ]]; then
    rm -f "$DB"
    log "temp db removed"
  else
    log "db kept at $DB (tip=$(
      "$PROBE_BIN" -index -db="$DB" -net="$NET" \
        -rpcuser="$RPC_USER" -rpcpass="$RPC_PASS" \
        -force -workers=1 2>&1 | grep 'already at' | grep -o '[0-9]*' | head -1
    ) )"
  fi
}
trap cleanup EXIT

# -- Build --------------------------------------------------------------------

log "building $PROBE_BIN..."
go build -o "$PROBE_BIN" "$PROBE_DIR"
log "build OK"

# -- Pre-flight ---------------------------------------------------------------

log "checking node ($NET)..."
TIP=$(rpc_val "getblockcount") || { log "ERROR: node not reachable at $RPC_URL"; exit 1; }
log "  chain tip : $TIP"

INDEX_HEIGHT=$(rpc "getindexinfo" | python3 -c "
import sys,json; d=json.load(sys.stdin)
r=d.get('result',{})
fi=r.get('basic block filter index',{})
if not fi: print(-1)
else: print(fi.get('best_block_height',-1))" 2>/dev/null || echo -1)
log "  filter index tip : $INDEX_HEIGHT"

if [[ "$INDEX_HEIGHT" == "-1" ]]; then
  log "ERROR: blockfilterindex not active — restart node with -blockfilterindex=1 -peerblockfilters=1"
  exit 1
fi

# -- Index sync ---------------------------------------------------------------

log "━━━ INDEX SYNC — $WORKERS workers — $NET ━━━"
log "  db      : $DB"
log "  target  : height $INDEX_HEIGHT"
echo

SYNC_START=$(date +%s)

"$PROBE_BIN" \
  -index \
  -db="$DB" \
  -net="$NET" \
  -rpcuser="$RPC_USER" \
  -rpcpass="$RPC_PASS" \
  -workers="$WORKERS" \
  -force \
  2>&1 | grep -v "version sent\|<- \"version\"\|<- \"verack\"\|verack sent\|-> verack"

SYNC_END=$(date +%s)
SYNC_SECS=$(( SYNC_END - SYNC_START ))
SYNC_RATE=$(python3 -c "print(f'{$INDEX_HEIGHT/$SYNC_SECS:.0f}' if $SYNC_SECS>0 else 'n/a')")

echo
log "━━━ SYNC RESULT ━━━"
log "  elapsed  : ${SYNC_SECS}s"
log "  blocks   : $INDEX_HEIGHT"
log "  rate     : ~${SYNC_RATE} blocks/s"
log "  workers  : $WORKERS"

# Verify db tip matches
DB_TIP=$("$PROBE_BIN" \
  -index -db="$DB" -net="$NET" \
  -rpcuser="$RPC_USER" -rpcpass="$RPC_PASS" \
  -force -workers=1 2>&1 | grep -oP '(?<=already at chain tip \()\d+' | head -1 || echo "?")
log "  db tip   : $DB_TIP"

if [[ "$DB_TIP" == "$INDEX_HEIGHT" || "$DB_TIP" == "$(( INDEX_HEIGHT + 1 ))" ]]; then
  log "  result   : PASS ✓"
else
  log "  result   : FAIL — db tip $DB_TIP != expected $INDEX_HEIGHT"
  exit 1
fi

[[ "$SERVE_TEST" == "0" ]] && exit 0

# -- Serve test ---------------------------------------------------------------

echo
log "━━━ SERVE TEST — port $SERVE_PORT ━━━"

"$PROBE_BIN" \
  -serve \
  -db="$DB" \
  -net="$NET" \
  -listen="127.0.0.1:$SERVE_PORT" \
  2>&1 | sed 's/^/[serve] /' &
SERVE_PID=$!
sleep 2

if ! kill -0 "$SERVE_PID" 2>/dev/null; then
  log "ERROR: serve process exited immediately"
  exit 1
fi
log "  serve process running (pid=$SERVE_PID)"

# Probe the server with a single-block filter request at height 1
log "  probing height 1 via P2P against 127.0.0.1:$SERVE_PORT..."
PROBE_OUT=$("$PROBE_BIN" \
  -net="$NET" \
  -addr="127.0.0.1:$SERVE_PORT" \
  -rpcuser="$RPC_USER" \
  -rpcpass="$RPC_PASS" \
  -start=1 -end=1 \
  2>&1 || true)

if echo "$PROBE_OUT" | grep -q "cfilter"; then
  log "  result   : PASS ✓  (cfilter received for height 1)"
else
  log "  result   : FAIL — no cfilter in probe output"
  echo "$PROBE_OUT" | tail -10
  exit 1
fi

log "━━━ ALL TESTS PASSED ━━━"
