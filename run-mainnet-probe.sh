#!/usr/bin/env bash
# run-mainnet-probe.sh
# Walks the Dogecoin mainnet chain from genesis verifying BIP157/158 filters.
#
# Three verification modes:
#
#   MODE=1  Hash chain integrity only (default, fastest)
#           Verifies every filter header commits correctly to the previous one.
#           No RPC calls per block. ~999 blocks/s sustained.
#
#   MODE=2  Hash chain + P2P vs RPC cross-check (thorough)
#           Every block: P2P filter bytes == RPC getblockfilter.
#           Proves the serving layer and index agree on every block.
#           ~2 extra RPC calls per block. Slower but fully automated.
#
#   MODE=3  Hash chain + RPC cross-check + block reconstruction (ground truth)
#           Samples every Nth block: fetches the full block, extracts all
#           output scriptPubKeys, runs them through GCS construction, and
#           verifies they appear in the filter. Validates filter *construction*
#           logic in the node, not just serving consistency.
#           Controlled by SAMPLE_N (default: every 1000th block).
#
# Usage:
#   ./run-mainnet-probe.sh                   # MODE=1, genesis to tip
#   MODE=2 ./run-mainnet-probe.sh            # full P2P vs RPC cross-check
#   MODE=3 SAMPLE_N=500 ./run-mainnet-probe.sh  # reconstruction every 500 blocks
#   MODE=4 SAMPLE_N=500 ./run-mainnet-probe.sh  # MODE=3 + neutrino cross-check
#   RESUME=0 ./run-mainnet-probe.sh          # force restart from genesis
#   START=500000 ./run-mainnet-probe.sh      # start from specific height
#   CHUNK=500 ./run-mainnet-probe.sh         # override chunk size (max 999)
#   DELAY=1 ./run-mainnet-probe.sh           # 1s between chunks

set -euo pipefail

PROBE_DIR="$HOME/source/repos/doge-cf-probe"
DOGE_CLI="$HOME/source/repos/dogecoin/src/dogecoin-cli"

# -- Config -------------------------------------------------------------------

NET="mainnet"
P2P_ADDR="127.0.0.1:22556"
RPC_URL="http://127.0.0.1:22555"
RPC_USER="${DOGE_RPC_USER:-dogecoinrpc}"
RPC_PASS="${DOGE_RPC_PASS:-}"

MODE="${MODE:-1}"            # 1=hash-chain, 2=+RPC verify, 3=+block reconstruction
CHUNK="${CHUNK:-999}"        # blocks per probe call (hard max 999)
RESUME="${RESUME:-1}"        # 0 = force restart from genesis
DELAY="${DELAY:-0}"          # seconds between chunks
SAMPLE_N="${SAMPLE_N:-1000}" # MODE=3: reconstruct every Nth block

LOG_DIR="$PROBE_DIR/logs"
PROBE_BIN="$PROBE_DIR/doge-cf-probe"

# State files are mode-specific so different modes don't clobber each other
STATE_FILE="$PROBE_DIR/.ibd_state_mode${MODE}"

# -- Validate mode ------------------------------------------------------------

case "$MODE" in
  1|2|3|4) ;;
  *) echo "ERROR: MODE must be 1, 2, 3, or 4"; exit 1 ;;
esac

# -- Setup --------------------------------------------------------------------

mkdir -p "$LOG_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/ibd_mode${MODE}_${TIMESTAMP}.log"

exec > >(tee -a "$LOG_FILE") 2>&1

log()         { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }
log_section() {
  echo
  echo "================================================================"
  log "$*"
  echo "================================================================"
}

log_section "doge-cf-probe chain verification -- mainnet MODE=$MODE"
log "probe dir  : $PROBE_DIR"
log "log file   : $LOG_FILE"
log "state file : $STATE_FILE"
log "binary     : $PROBE_BIN"
log "chunk size : $CHUNK"
log "node addr  : $P2P_ADDR"

case "$MODE" in
  1) log "mode       : 1 -- hash chain integrity only" ;;
  2) log "mode       : 2 -- hash chain + P2P vs RPC cross-check" ;;
  3) log "mode       : 3 -- hash chain + RPC cross-check + block reconstruction (every ${SAMPLE_N} blocks)" ;;
  4) log "mode       : 4 -- MODE=3 + neutrino (btcd/gcs) cross-check (every ${SAMPLE_N} blocks)" ;;
esac

# -- RPC credentials ----------------------------------------------------------

if [[ -z "$RPC_PASS" ]]; then
  CONF="$HOME/.dogecoin/dogecoin.conf"
  if [[ -f "$CONF" ]]; then
    RPC_PASS=$(grep -E '^rpcpassword=' "$CONF" | cut -d= -f2- | tr -d '[:space:]' || true)
    RPC_USER=$(grep -E '^rpcuser='     "$CONF" | cut -d= -f2- | tr -d '[:space:]' || echo "$RPC_USER")
  fi
fi

if [[ -z "$RPC_PASS" ]]; then
  log "ERROR: RPC password not found."
  log "  Set DOGE_RPC_PASS env var, or add rpcpassword= to ~/.dogecoin/dogecoin.conf"
  exit 1
fi

# -- RPC helper ---------------------------------------------------------------

rpc() {
  local method="$1"
  local params="${2:-}"
  curl -s --user "${RPC_USER}:${RPC_PASS}" \
    --data-binary "{\"jsonrpc\":\"1.1\",\"id\":1,\"method\":\"${method}\",\"params\":[${params}]}" \
    -H 'Content-Type: application/json' \
    "$RPC_URL"
}

rpc_result() {
  rpc "$@" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if d.get('error'):
    raise SystemExit('RPC error: ' + str(d['error']))
print(d['result'])
"
}

# -- Pre-flight checks --------------------------------------------------------

log_section "pre-flight checks"

log "node reachable..."
TIP=$(rpc_result "getblockcount" 2>/dev/null) || {
  log "FAILED -- is dogecoind running at $RPC_URL?"
  exit 1
}
log "  tip = $TIP"

log "checking blockfilterindex..."
INDEX_INFO=$(rpc "getindexinfo" 2>/dev/null || true)
if echo "$INDEX_INFO" | grep -q '"basic block filter index"'; then
  log "  blockfilterindex: active"
elif echo "$INDEX_INFO" | grep -q 'Method not found'; then
  log "  getindexinfo unavailable (older build) -- continuing"
else
  log "  WARNING: blockfilterindex may not be enabled"
  log "  Restart node with: -blockfilterindex=1 -peerblockfilters=1"
fi

log "spot-checking filter at height 1..."
GENESIS_HASH=$(rpc_result "getblockhash" "1" 2>/dev/null)
SPOT=$(rpc "getblockfilter" "\"${GENESIS_HASH}\"" | python3 -c "
import sys, json
d = json.load(sys.stdin)
e = d.get('error')
if e:
    print('ERROR: ' + e['message'])
else:
    f = d['result']['filter']
    print('ok -- filter=' + f[:24] + '...')
" 2>/dev/null)
log "  height 1: $SPOT"

if echo "$SPOT" | grep -q "^ERROR"; then
  log "Filter index not ready -- cannot proceed."
  exit 1
fi

# Mode 3: verify txindex is available (needed for getblock verbosity=2)
if [[ "$MODE" == "3" ]]; then
  log "MODE=3: checking txindex for block reconstruction..."
  TEST_HASH=$(rpc_result "getblockhash" "500000" 2>/dev/null)
  TXTEST=$(rpc "getblock" "\"${TEST_HASH}\", 2" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if d.get('error'):
    print('ERROR: ' + d['error']['message'])
else:
    txcount = len(d['result']['tx'])
    print(f'ok -- {txcount} tx in block 500000')
" 2>/dev/null)
  log "  getblock verbosity=2: $TXTEST"
  if echo "$TXTEST" | grep -q "^ERROR"; then
    log "  WARNING: getblock verbosity=2 failed -- block reconstruction may not work"
    log "  Make sure node is running with -txindex=1"
  fi
fi

# -- Build probe binary -------------------------------------------------------

log_section "building probe binary"

cd "$PROBE_DIR"
log "running: go build -o doge-cf-probe ."
if go build -o "$PROBE_BIN" . 2>&1; then
  log "build successful: $PROBE_BIN"
else
  log "ERROR: build failed -- check Go source in $PROBE_DIR"
  exit 1
fi

# -- Resolve start height -----------------------------------------------------

log_section "resolving start height"

if [[ -n "${START:-}" ]]; then
  CURRENT_START="$START"
  log "START overridden by env: $CURRENT_START"
elif [[ "$RESUME" == "1" && -f "$STATE_FILE" ]]; then
  CURRENT_START=$(cat "$STATE_FILE")
  log "resuming from state file: height $CURRENT_START"
else
  CURRENT_START=1
  log "starting from genesis (height 1)"
fi

if (( CHUNK > 999 )); then
  log "WARNING: CHUNK=$CHUNK exceeds protocol max 999 -- clamping to 999"
  CHUNK=999
fi

# -- Mode 3: block reconstruction helper --------------------------------------
# Fetches a block, extracts all output scriptPubKeys, and verifies each one
# appears in the filter served by the node via -match flags on the probe.

reconstruct_verify() {
  local height="$1"
  local rpc_hash
  rpc_hash=$(rpc_result "getblockhash" "$height" 2>/dev/null) || {
    log "  [recon/$height] ERROR: getblockhash failed"
    return 1
  }

  # Write SPKs to a temp file — avoids ARG_MAX limits on high-tx blocks (3000+ SPKs)
  local spk_file
  spk_file=$(mktemp /tmp/doge-recon-XXXXXX.spk)

  local spk_count
  spk_count=$(rpc "getblock" "\"${rpc_hash}\", 2" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if d.get('error'):
    sys.stderr.write('ERROR: ' + d['error']['message'] + '\n')
    sys.exit(1)
block = d['result']
spks = set()
for tx in block['tx']:
    for vout in tx.get('vout', []):
        h = vout.get('scriptPubKey', {}).get('hex', '')
        if h:
            spks.add(h)
for spk in sorted(spks):
    print(spk)
sys.stderr.write(str(len(spks)) + '\n')
" 2>/tmp/doge-recon-count > "$spk_file") || {
    log "  [recon/$height] ERROR: getblock verbosity=2 failed"
    rm -f "$spk_file" /tmp/doge-recon-count
    return 1
  }
  spk_count=$(cat /tmp/doge-recon-count 2>/dev/null || wc -l < "$spk_file" | tr -d ' ')
  rm -f /tmp/doge-recon-count

  if [[ ! -s "$spk_file" ]]; then
    log "  [recon/$height] WARNING: no scriptPubKeys found in block"
    rm -f "$spk_file"
    return 0
  fi

  log "  [recon/$height] block $rpc_hash -- $spk_count unique scriptPubKeys"

  # Run probe using -matchfile (no ARG_MAX risk regardless of block size)
  # In MODE=4, also pass -neutrino to cross-check btcd/gcs on each sampled block
  local neutrino_flag=""
  if [[ "${MODE}" == "4" ]]; then neutrino_flag="-neutrino"; fi

  if "$PROBE_BIN" \
      -net="$NET" \
      -addr="$P2P_ADDR" \
      -rpc="$RPC_URL" \
      -rpcuser="$RPC_USER" \
      -rpcpass="$RPC_PASS" \
      -start="$height" \
      -end="$height" \
      -matchfile="$spk_file" \
      -matchblock \
      -verify \
      ${neutrino_flag} 2>&1 | tee -a "$LOG_FILE"; then
    rm -f "$spk_file"
    log "  [recon/$height] PASS -- all scriptPubKeys confirmed in filter"
    return 0
  else
    rm -f "$spk_file"
    log "  [recon/$height] FAIL -- one or more scriptPubKeys missing from filter"
    return 1
  fi
}

# -- Stats tracking -----------------------------------------------------------

TOTAL_CHUNKS=0
TOTAL_BLOCKS=0
FAILED_CHUNKS=0
RECON_PASS=0
RECON_FAIL=0
START_TIME=$(date +%s)

save_state() { echo "$1" > "$STATE_FILE"; }

elapsed() {
  local now secs
  now=$(date +%s)
  secs=$(( now - START_TIME ))
  printf "%dh%02dm%02ds" $(( secs/3600 )) $(( (secs%3600)/60 )) $(( secs%60 ))
}

rate() {
  local now secs
  now=$(date +%s)
  secs=$(( now - START_TIME ))
  if (( secs > 0 && TOTAL_BLOCKS > 0 )); then
    printf "%.0f blocks/s" "$(echo "scale=2; $TOTAL_BLOCKS / $secs" | bc)"
  else
    echo "calculating..."
  fi
}

# Build probe flags based on mode
probe_flags() {
  local flags=()
  flags+=(-net="$NET")
  flags+=(-addr="$P2P_ADDR")
  flags+=(-rpc="$RPC_URL")
  flags+=(-rpcuser="$RPC_USER")
  flags+=(-rpcpass="$RPC_PASS")
  flags+=(-start="$CURRENT_START")
  flags+=(-end="$CHUNK_END")
  case "$MODE" in
    1) ;;                            # hash chain only
    2) flags+=(-verify) ;;           # + RPC cross-check
    3) flags+=(-verify) ;;           # chunk-level verify; reconstruction is separate
    4) flags+=(-verify) ;;           # same as 3 at chunk level; neutrino is per-block in recon
  esac
  printf '%s\n' "${flags[@]}"
}

# -- IBD loop -----------------------------------------------------------------

log_section "beginning chain walk -- heights $CURRENT_START to $TIP"
log "total blocks to scan: $(( TIP - CURRENT_START + 1 ))"
log "estimated chunks    : ~$(( (TIP - CURRENT_START) / CHUNK + 1 ))"
echo

trap 'log ""; log "interrupted -- state saved at height $CURRENT_START"; log "re-run to resume"; exit 130' INT TERM

while (( CURRENT_START <= TIP )); do
  CURRENT_TIP=$(rpc_result "getblockcount" 2>/dev/null) || {
    log "WARNING: lost RPC connection -- retrying in 5s..."
    sleep 5
    continue
  }

  CHUNK_END=$(( CURRENT_START + CHUNK - 1 ))
  if (( CHUNK_END > CURRENT_TIP )); then
    CHUNK_END="$CURRENT_TIP"
  fi

  if (( CURRENT_START > CURRENT_TIP )); then
    break
  fi

  CHUNK_SIZE=$(( CHUNK_END - CURRENT_START + 1 ))
  PCT=$(python3 -c "print(f'{($CURRENT_START / $CURRENT_TIP * 100):.2f}')")

  log "chunk $((TOTAL_CHUNKS+1)): heights $CURRENT_START-$CHUNK_END ($CHUNK_SIZE blocks) | ${PCT}% | $(elapsed) | $(rate)"

  # Read probe flags into array safely
  mapfile -t FLAGS < <(probe_flags)

  if "$PROBE_BIN" "${FLAGS[@]}" 2>&1; then
    TOTAL_CHUNKS=$(( TOTAL_CHUNKS + 1 ))
    TOTAL_BLOCKS=$(( TOTAL_BLOCKS + CHUNK_SIZE ))

    # -- Mode 3: block reconstruction on sampled heights ----------------------
    if [[ "$MODE" == "3" || "$MODE" == "4" ]]; then
      # Sample every SAMPLE_N blocks within this chunk
      h=$CURRENT_START
      while (( h <= CHUNK_END )); do
        # Align sample to SAMPLE_N boundaries for consistency across runs
        if (( h % SAMPLE_N == 0 )); then
          if reconstruct_verify "$h"; then
            RECON_PASS=$(( RECON_PASS + 1 ))
          else
            RECON_FAIL=$(( RECON_FAIL + 1 ))
            log "  RECONSTRUCTION FAILURE at height $h -- stopping for investigation"
            log "  To inspect manually:"
            log "    ./src/dogecoin-cli getblock \$(./src/dogecoin-cli getblockhash $h) 2"
            # Don't advance state — let the user investigate before continuing
            save_state "$CURRENT_START"
            exit 1
          fi
        fi
        h=$(( h + 1 ))
      done
    fi

    CURRENT_START=$(( CHUNK_END + 1 ))
    save_state "$CURRENT_START"

  else
    FAILED_CHUNKS=$(( FAILED_CHUNKS + 1 ))
    log "ERROR: chunk $CURRENT_START-$CHUNK_END failed (attempt will retry in 10s | failed so far: $FAILED_CHUNKS)"
    sleep 10
    continue
  fi

  if (( DELAY > 0 )); then sleep "$DELAY"; fi

  # Progress summary every 100 chunks
  if (( TOTAL_CHUNKS % 100 == 0 )); then
    log "--- progress summary ---"
    log "  chunks completed : $TOTAL_CHUNKS"
    log "  blocks scanned   : $TOTAL_BLOCKS"
    log "  failed chunks    : $FAILED_CHUNKS"
    log "  elapsed          : $(elapsed)"
    log "  rate             : $(rate)"
    log "  tip at           : $CURRENT_TIP"
    log "  next start       : $CURRENT_START"
    if [[ "$MODE" == "3" || "$MODE" == "4" ]]; then
      log "  recon pass       : $RECON_PASS"
      log "  recon fail       : $RECON_FAIL"
    fi
  fi
done

# -- Summary ------------------------------------------------------------------

log_section "chain walk complete"
log "mode             : $MODE"
log "chunks completed : $TOTAL_CHUNKS"
log "blocks scanned   : $TOTAL_BLOCKS"
log "failed chunks    : $FAILED_CHUNKS"
log "elapsed          : $(elapsed)"
log "rate             : $(rate)"
log "final tip        : $(rpc_result getblockcount 2>/dev/null || echo unknown)"
if [[ "$MODE" == "3" ]]; then
  log "recon pass       : $RECON_PASS"
  log "recon fail       : $RECON_FAIL"
  RECON_TOTAL=$(( RECON_PASS + RECON_FAIL ))
  if (( RECON_TOTAL > 0 )); then
    log "recon coverage   : $RECON_TOTAL blocks sampled (1 per $SAMPLE_N)"
  fi
fi
log "log file         : $LOG_FILE"

rm -f "$STATE_FILE"
log "state file cleared -- re-run will start from genesis"
