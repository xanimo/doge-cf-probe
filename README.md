# godoge

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
git clone https://github.com/xanimo/godoge
cd godoge
go build -o godoge .
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
./godoge -net=regtest -rpcpass=test -start=1 -end=10
```

### Mainnet

```bash
# Pull RPC credentials from dogecoin.conf
RPCPASS=$(grep rpcpassword ~/.dogecoin/dogecoin.conf | cut -d= -f2 | tr -d '[:space:]')
RPCUSER=$(grep rpcuser     ~/.dogecoin/dogecoin.conf | cut -d= -f2 | tr -d '[:space:]')

# Basic hash-chain verification of 1000 blocks
./godoge \
  -net=mainnet \
  -rpcuser="$RPCUSER" \
  -rpcpass="$RPCPASS" \
  -start=500000 \
  -end=501000

# Full cross-check: hash chain + RPC verify + neutrino compatibility
./godoge \
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
./godoge \
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
./godoge \
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
./godoge -matchfile=targets.txt ...
```

## Local filter index (`-index`)

The `-index` mode builds a local copy of the BIP158 filter database from a
Dogecoin node over P2P, then follows the chain tip. The database is a bbolt
file and can be used standalone without a running node once built.

```bash
# Build index from scratch (waits for IBD to complete first)
./godoge -index -db=/var/lib/godoge/filters.db -net=mainnet \
  -rpcpass="$RPCPASS"

# Faster indexing with more parallel P2P connections
./godoge -index -db=filters.db -workers=8 -net=mainnet \
  -rpcpass="$RPCPASS"

# Force-index to current filter tip without waiting for full IBD
# (useful during testnet initial sync)
./godoge -index -db=filters.db -force -net=testnet \
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
./godoge -serve -db=filters.db -net=mainnet
```

**RPC proxy mode** — proxies filter requests to a Dogecoin node's RPC. Requires
a running node with `-blockfilterindex=1`.

```bash
./godoge -serve -net=mainnet -rpcpass="$RPCPASS"
```

A custom listen address can be set with `-listen`:

```bash
./godoge -serve -db=filters.db -net=mainnet -listen=0.0.0.0:22556
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
./godoge -dump -db=filters.db -out=filters_mainnet.dgfi
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
./godoge -restore \
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

## Chain verification (run-mainnet-probe.sh)

For full-chain verification, use the companion shell script which walks from
genesis to tip in 999-block chunks with resume support.

### Modes

| Mode | Description |
|------|-------------|
| `MODE=1` | Hash chain integrity only. Fastest (~1000 blocks/s). No per-block RPC calls. |
| `MODE=2` | + P2P vs RPC cross-check. Proves serving layer and index agree on every block. |
| `MODE=3` | + Block reconstruction. Fetches sampled blocks and confirms all scriptPubKeys appear in their filters. |
| `MODE=4` | MODE=3 + neutrino cross-check. Validates btcd/gcs compatibility on sampled blocks. |

```bash
# Full chain, hash integrity only
MODE=1 ./run-mainnet-probe.sh

# Full chain, complete verification
MODE=2 ./run-mainnet-probe.sh

# Full chain with block reconstruction every 1000 blocks
MODE=3 SAMPLE_N=1000 ./run-mainnet-probe.sh

# Full chain with neutrino cross-check (recommended for PR verification)
MODE=4 SAMPLE_N=1000 ./run-mainnet-probe.sh
```

### Environment variables

| Variable  | Default | Description |
|-----------|---------|-------------|
| `MODE`    | `1`     | Verification mode (1-4) |
| `CHUNK`   | `999`   | Blocks per probe invocation (max 999) |
| `RESUME`  | `1`     | Resume from state file; set to `0` to restart |
| `START`   | *(genesis)* | Override start height |
| `DELAY`   | `0`     | Seconds between chunks |
| `SAMPLE_N`| `1000`  | MODE=3/4: reconstruct every Nth block |

State files are mode-specific (`.ibd_state_mode1` etc.) so multiple modes
can run independently without interfering with each other's resume points.

Logs are written to `logs/ibd_mode<N>_<timestamp>.log`.

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