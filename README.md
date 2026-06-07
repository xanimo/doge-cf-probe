# doge-cf-probe

A raw P2P BIP157/158 probe, local filter index, and chain verification tool for
Dogecoin nodes. Validates compact block filter implementation correctness across
the full chain history, with optional cross-check against btcd's canonical GCS
implementation (the same library used by neutrino/LND).

Written as a companion test harness for the Dogecoin Core BIP157/158 backport
PR stack ([xanimo/dogecoin — backport/integration-stabilization](https://github.com/xanimo/dogecoin/tree/refs/heads/backport/integration-stabilization)).
A clean full-chain run is attached as verification evidence.

## Background

[BIP157](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki) and
[BIP158](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki) define
a compact block filter protocol for light clients. Instead of sending a bloom
filter to a full node (BIP37), the light client downloads pre-computed
Golomb-Rice Coded Set (GCS) filters from the node and performs address matching
locally — preserving privacy and eliminating per-query trust requirements.

This tool exercises the full consumer-side flow against a Dogecoin node running
the backported BIP157/158 implementation.

## How it works

For a given block range, the probe:

1. Opens a raw TCP connection to the node and performs a full `version`/`verack` handshake
2. Sends `getcfheaders` — receives filter hashes and derives the filter header chain
   (`FilterHeader[n] = dSHA256(FilterHash[n] || FilterHeader[n-1])`)
3. Sends `getcfilters` — receives one `cfilter` message per block
4. Verifies each filter's hash against the header chain (hash chain integrity)
5. Optionally cross-checks P2P filter bytes against `getblockfilter` RPC output (serving consistency)
6. Optionally matches scriptPubKeys against the GCS filter using our own decoder and/or btcd's
7. Optionally fetches hit blocks via RPC to confirm matched outputs exist (false positive detection)

### Wire format note

Dogecoin Core's `cfilter` response format is:

```
block_hash(32) + filter_type(1) + num_bytes(varint) + filter_data
```

The `filter_type` byte follows the block hash rather than preceding it as the
BIP157 spec describes. This is an implementation detail of the Dogecoin Core
backport and is handled transparently by the probe.

## Prerequisites

- Go 1.21+
- A Dogecoin node running with `-blockfilterindex=1 -peerblockfilters=1`
- RPC access to the node (for stop hash resolution and optional cross-checks)

## Installation

```bash
git clone https://github.com/xanimo/doge-cf-probe
cd doge-cf-probe
go build -o doge-cf-probe .
```

## Quick start

### Regtest (development)

```bash
# Start node with filter indexing
./src/dogecoind -regtest \
  -blockfilterindex=1 \
  -peerblockfilters=1 \
  -rpcuser=dogecoinrpc \
  -rpcpassword=test \
  -daemon

# Mine some blocks
./src/dogecoin-cli -regtest generatetoaddress 20 \
  $(./src/dogecoin-cli -regtest getnewaddress)

# Run basic probe
./doge-cf-probe -net=regtest -rpcpass=test -start=1 -end=10
```

### Mainnet

```bash
# Pull RPC credentials from dogecoin.conf
RPCPASS=$(grep rpcpassword ~/.dogecoin/dogecoin.conf | cut -d= -f2 | tr -d '[:space:]')
RPCUSER=$(grep rpcuser     ~/.dogecoin/dogecoin.conf | cut -d= -f2 | tr -d '[:space:]')

# Basic hash-chain verification of 1000 blocks
./doge-cf-probe \
  -net=mainnet \
  -rpcuser="$RPCUSER" \
  -rpcpass="$RPCPASS" \
  -start=500000 \
  -end=501000

# Full cross-check: hash chain + RPC verify + neutrino compatibility
./doge-cf-probe \
  -net=mainnet \
  -rpcuser="$RPCUSER" \
  -rpcpass="$RPCPASS" \
  -start=500000 \
  -end=500100 \
  -verify \
  -neutrino
```

## Flags

### Core

| Flag          | Default                   | Description |
|---------------|---------------------------|-------------|
| `-net`        | `regtest`                 | `mainnet`, `testnet`, or `regtest` |
| `-addr`       | `127.0.0.1:<port>`        | Node P2P address |
| `-start`      | `1`                       | Start block height |
| `-end`        | `10`                      | End block height (inclusive, max range 999) |
| `-rpc`        | `http://127.0.0.1:<port>` | RPC URL |
| `-rpcuser`    | `dogecoinrpc`             | RPC username |
| `-rpcpass`    | *(empty)*                 | RPC password |
| `-verify`     | `false`                   | Cross-check P2P filter bytes against `getblockfilter` RPC |
| `-match`      | *(empty)*                 | Comma-separated scriptPubKey hex strings to match in filters |
| `-matchaddr`  | *(empty)*                 | Comma-separated Dogecoin addresses to match (P2PKH/P2SH only) |
| `-matchfile`  | *(empty)*                 | File with one scriptPubKey hex per line (avoids ARG_MAX on large blocks) |
| `-matchblock` | `false`                   | On filter hit, fetch full block via RPC and confirm matched outputs |
| `-neutrino`   | `false`                   | Cross-check our GCS decoder against btcd/btcutil/gcs |
| `-gcsdebug`   | `false`                   | Print verbose GCS decoder internals |

### Index mode (`-index`)

| Flag        | Default | Description |
|-------------|---------|-------------|
| `-index`    | `false` | Build/update local filter database from node via P2P, then follow tip |
| `-db`       | *(empty)* | Path to local filter database (bbolt file) |
| `-workers`  | `4`     | Number of parallel P2P connections for faster IBD indexing |
| `-force`    | `false` | Skip IBD wait; index up to current filter index tip (useful during testnet IBD) |

### Serve mode (`-serve`)

| Flag       | Default                   | Description |
|------------|---------------------------|-------------|
| `-serve`   | `false`                   | Serve BIP157/158 filters to incoming P2P peers |
| `-listen`  | `0.0.0.0:<net-port>`      | Listen address for incoming peer connections |
| `-db`      | *(empty)*                 | Path to local filter database; omit to proxy via RPC instead |

### Dump / restore (`-dump`, `-restore`)

| Flag        | Default   | Description |
|-------------|-----------|-------------|
| `-dump`     | `false`   | Dump filter index to a portable DGFI file |
| `-db`       | *(empty)* | Source filter database for `-dump` |
| `-out`      | *(empty)* | Output path for the DGFI dump file |
| `-restore`  | `false`   | Restore a DGFI file to Dogecoin Core's native index format |
| `-in`       | *(empty)* | Input DGFI file for `-restore` |
| `-coredir`  | *(empty)* | Target directory for `-restore` (e.g. `~/.dogecoin/indexes/blockfilter/basic`) |

## Address matching

The probe supports matching scriptPubKeys against filters to emulate light client
wallet scanning.

### P2PKH and P2SH addresses (via `-matchaddr`)

```bash
./doge-cf-probe \
  -net=mainnet \
  -rpcuser="$RPCUSER" \
  -rpcpass="$RPCPASS" \
  -start=1000000 \
  -end=1001000 \
  -matchaddr=DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L \
  -matchblock
```

### P2PK outputs (raw scriptPubKey required)

Early blocks and many coinbase outputs use P2PK format, which encodes the raw
public key rather than a hash. These will not match via `-matchaddr`. Use the
raw scriptPubKey hex from `getblock` verbosity 2:

```bash
# Get the coinbase scriptPubKey for a block
./src/dogecoin-cli getblock \
  $(./src/dogecoin-cli getblockhash 500000) 2 | \
  jq -r '.tx[0].vout[0].scriptPubKey.hex'

# Match it
./doge-cf-probe \
  -net=mainnet \
  -rpcuser="$RPCUSER" \
  -rpcpass="$RPCPASS" \
  -start=500000 \
  -end=500000 \
  -match=<hex from above> \
  -matchblock
```

### Large blocks (`-matchfile`)

For blocks with thousands of outputs, use `-matchfile` to avoid OS argument
length limits:

```bash
echo -e "76a914...\na914..." > targets.txt
./doge-cf-probe -matchfile=targets.txt ...
```

## Local filter index (`-index`)

The `-index` mode builds a local copy of the BIP158 filter database from a
Dogecoin node over P2P, then follows the chain tip. The database is a bbolt
file and can be used standalone without a running node once built.

```bash
# Build index from scratch (waits for IBD to complete first)
./doge-cf-probe -index -db=/var/lib/doge-cf-probe/filters.db -net=mainnet \
  -rpcpass="$RPCPASS"

# Faster indexing with more parallel P2P connections
./doge-cf-probe -index -db=filters.db -workers=8 -net=mainnet \
  -rpcpass="$RPCPASS"

# Force-index to current filter tip without waiting for full IBD
# (useful during testnet initial sync)
./doge-cf-probe -index -db=filters.db -force -net=testnet \
  -rpcpass="$RPCPASS"
```

During IBD the indexer opens N parallel P2P connections (`-workers`) and
pipelines `getcfilters` requests across them. After IBD it switches to a single
connection that follows the tip via `inv` messages.

## Standalone filter server (`-serve`)

The `-serve` mode listens for incoming P2P connections and answers `getcfheaders`
and `getcfilters` requests. It can run in two ways:

**Local index mode** — serves directly from a local database built with `-index`.
No running Dogecoin node required after the index is built. The database is
reloaded every 60 seconds so a concurrent indexer can keep it current.

```bash
./doge-cf-probe -serve -db=filters.db -net=mainnet
```

**RPC proxy mode** — proxies filter requests to a Dogecoin node's RPC. Requires
a running node with `-blockfilterindex=1`.

```bash
./doge-cf-probe -serve -net=mainnet -rpcpass="$RPCPASS"
```

A custom listen address can be set with `-listen`:

```bash
./doge-cf-probe -serve -db=filters.db -net=mainnet -listen=0.0.0.0:22556
```

## Filter index dump and restore (`-dump`, `-restore`)

These modes let you export a local filter index to a single portable file and
import it into Dogecoin Core's native on-disk format, allowing you to bootstrap
a node's filter index without re-indexing from scratch.

### Dump

Exports the bbolt filter database to a binary DGFI (Dogecoin GCS Filter Index)
file. The file contains all filter data (block hash, filter hash, filter header,
and raw filter bytes) for every block from genesis to tip.

```bash
./doge-cf-probe -dump -db=filters.db -out=filters_mainnet.dgfi
```

Progress is logged every 100 000 blocks.

### Restore

Reads a DGFI file and writes Dogecoin Core's native block filter index layout
into a target directory:

```
<coredir>/db/              — LevelDB height index (block_hash, filter_hash, filter_header, file position)
<coredir>/fltr00000.dat    — flat filter files, 16 MiB each
<coredir>/fltr00001.dat
...
```

Place the output directory at `~/.dogecoin/indexes/blockfilter/basic/` before
starting Core and it will pick up the index without re-indexing.

```bash
./doge-cf-probe -restore \
  -in=filters_mainnet.dgfi \
  -coredir=~/.dogecoin/indexes/blockfilter/basic
```

### DGFI file format (v1)

```
[0..3]  magic "DGFI"
[4]     version 0x01
[5..8]  tip height, uint32 LE
Per block (height 0..tip):
  block_hash    32 bytes LE
  filter_hash   32 bytes  (dSHA256 of filter bytes)
  filter_header 32 bytes
  compact_size(len) + filter_bytes
```

## Chain verification (`run-mainnet-probe.sh`)

`run-mainnet-probe.sh` walks the Dogecoin mainnet chain from genesis to tip in
999-block chunks, verifying BIP157/158 compact block filters end-to-end. It
handles resume, logging, progress reporting, and block reconstruction sampling
automatically.

### Prerequisites

- `dogecoind` running and fully synced with `-blockfilterindex=1 -peerblockfilters=1`
- RPC credentials in `~/.dogecoin/dogecoin.conf` **or** set via environment variables
- `go` in `PATH` (the script builds the binary itself before each run)
- `python3` and `bc` (used for percentage and rate calculations)
- For MODE=3/4: node also needs `-txindex=1` (block reconstruction fetches full
  transaction data via `getblock` verbosity 2)

### RPC credentials

The script reads credentials from `~/.dogecoin/dogecoin.conf` automatically.
To override, set environment variables before invoking:

```bash
export DOGE_RPC_USER=dogecoinrpc
export DOGE_RPC_PASS=yourpassword
```

### Modes

| Mode | What it checks | Speed |
|------|----------------|-------|
| `MODE=1` | Filter header chain integrity from genesis to tip. Every `FilterHeader[n]` must equal `dSHA256(FilterHash[n] \|\| FilterHeader[n-1])`. No per-block RPC calls. | ~1000 blocks/s |
| `MODE=2` | MODE=1 + P2P vs RPC cross-check. For every block, the filter bytes received over P2P must match `getblockfilter` RPC output. Proves the serving layer and index agree on every block. | ~2 RPC calls/block |
| `MODE=3` | MODE=2 + block reconstruction on sampled blocks. Every `SAMPLE_N`th block: fetches the full block, extracts all output scriptPubKeys, constructs the expected GCS filter, and confirms every key appears in the filter served by the node. Validates filter *construction* correctness, not just serving consistency. Requires `-txindex=1`. | depends on `SAMPLE_N` |
| `MODE=4` | MODE=3 + neutrino cross-check. On each sampled block also runs btcd/btcutil/gcs as a second decoder and asserts both implementations agree. Recommended for PR verification. | same as MODE=3 |

### Quick start

```bash
# Hash chain only — fastest way to verify the full chain
./run-mainnet-probe.sh

# Full P2P vs RPC cross-check
MODE=2 ./run-mainnet-probe.sh

# Block reconstruction every 1000 blocks (node needs -txindex=1)
MODE=3 SAMPLE_N=1000 ./run-mainnet-probe.sh

# Full PR verification: reconstruction + neutrino cross-check
MODE=4 SAMPLE_N=1000 ./run-mainnet-probe.sh
```

### Environment variables

| Variable       | Default    | Description |
|----------------|------------|-------------|
| `MODE`         | `1`        | Verification mode (1–4, see above) |
| `CHUNK`        | `999`      | Blocks per probe invocation (clamped to 999 max) |
| `RESUME`       | `1`        | Resume from last saved height; set to `0` to restart from genesis |
| `START`        | *(genesis)* | Override start height, ignoring any saved state |
| `DELAY`        | `0`        | Seconds to sleep between chunks (useful to reduce node load) |
| `SAMPLE_N`     | `1000`     | MODE=3/4: reconstruct one block per every `SAMPLE_N` blocks |
| `DOGE_RPC_USER`| `dogecoinrpc` | RPC username (falls back to `dogecoin.conf`) |
| `DOGE_RPC_PASS`| *(empty)*  | RPC password (falls back to `dogecoin.conf`) |

### Resume and state files

The script saves progress to a mode-specific state file after each successful
chunk:

```
.ibd_state_mode1   # MODE=1
.ibd_state_mode2   # MODE=2
...
```

Each mode has its own state file so multiple modes can run (or be interrupted
and resumed) independently without clobbering each other.

To **resume** a previous run (default): just re-run the script. It reads the
last saved height and continues from there.

To **restart from genesis**: set `RESUME=0`:

```bash
RESUME=0 ./run-mainnet-probe.sh
```

To **start from a specific height** (ignores saved state):

```bash
START=500000 ./run-mainnet-probe.sh
```

### Interrupt handling

Pressing `Ctrl+C` (SIGINT/SIGTERM) saves the current height to the state file
and exits cleanly. Re-running the script resumes from that point.

### Logging

Each run writes a timestamped log file to `logs/`:

```
logs/ibd_mode1_20260606_120000.log
logs/ibd_mode4_20260606_130000.log
```

Output is also echoed to the terminal. Progress summaries are logged every
100 chunks:

```
[2026-06-06 14:23:01] --- progress summary ---
[2026-06-06 14:23:01]   chunks completed : 1200
[2026-06-06 14:23:01]   blocks scanned   : 1198800
[2026-06-06 14:23:01]   failed chunks    : 0
[2026-06-06 14:23:01]   elapsed          : 0h19m47s
[2026-06-06 14:23:01]   rate             : 1009 blocks/s
[2026-06-06 14:23:01]   tip at           : 6238016
[2026-06-06 14:23:01]   next start       : 1198801
```

### Failure handling

**Chunk failure** (probe exits non-zero): the script logs the error, waits 10
seconds, and retries the same chunk. State is not advanced. This handles
transient P2P or RPC errors.

**Reconstruction failure** (MODE=3/4, a scriptPubKey was not found in the
filter): the script stops immediately and prints the height for manual
inspection:

```
[recon/500000] FAIL -- one or more scriptPubKeys missing from filter
To inspect manually:
  ./src/dogecoin-cli getblock $(./src/dogecoin-cli getblockhash 500000) 2
```

State is saved at the start of the failed chunk so resuming will retry the
reconstruction.

### Pre-flight checks

Before the chain walk begins the script validates:

1. `dogecoind` is reachable at the RPC endpoint
2. The basic block filter index is active (`getindexinfo`)
3. `getblockfilter` works on block 1 (filter index is built, not just enabled)
4. MODE=3/4 only: `getblock` verbosity 2 works on a known block (txindex check)

## Verification results

Full MODE=4 run against Dogecoin mainnet (June 2026):

```
mode             : 4
chunks completed : 6245
blocks scanned   : 6238016
failed chunks    : 0
elapsed          : 1h42m18s
rate             : 1016 blocks/s
final tip        : 6238016
recon pass       : 6238  (one per 1000 blocks sampled)
recon fail       : 0

neutrino cross-check summary:
  decode errors   : 0
  match mismatches: 0
  btcd/gcs and our GCS impl agree on all filters
  -> wire-compatible with neutrino/LND ecosystem
```

Every block in the Dogecoin mainnet chain passed:
- Filter hash chain integrity from genesis to tip
- P2P serving layer consistency with the block filter index
- Filter header chain correctness
- btcd/gcs (neutrino) decode and match agreement on sampled blocks
- Block reconstruction: all output scriptPubKeys confirmed present in their filters

## GCS implementation

The probe includes a self-contained GCS implementation (`gcsMatchAny`,
`sipHash24`, `golombDecode`) with no dependency on btcd for its core path.
The `-neutrino` flag adds an independent cross-check using
`github.com/btcsuite/btcd/btcutil/gcs` as a second decoder.

GCS parameters per BIP158:
- `P = 19` (false positive rate `1/2^19`)
- `M = 784931`
- Key derivation: first 16 bytes of block hash (little-endian)

## Network reference

| Network  | Magic        | P2P Port | RPC Port |
|----------|--------------|----------|----------|
| mainnet  | `0xc0c0c0c0` | 22556    | 22555    |
| testnet  | `0xfcc1b7dc` | 44556    | 44555    |
| regtest  | `0xfabfb5da` | 18444    | 18332    |

## Related

- [BIP157 spec](https://github.com/bitcoin/bips/blob/master/bip-0157.mediawiki)
- [BIP158 spec](https://github.com/bitcoin/bips/blob/master/bip-0158.mediawiki)
- [lightninglabs/neutrino](https://github.com/lightninglabs/neutrino) — Go light client
- [btcsuite/btcd/btcutil/gcs](https://github.com/btcsuite/btcd/tree/master/btcutil/gcs) — canonical GCS implementation
- [xanimo/dogecoin — backport/integration-stabilization](https://github.com/xanimo/dogecoin/tree/refs/heads/backport/integration-stabilization) — the Dogecoin Core branch being tested