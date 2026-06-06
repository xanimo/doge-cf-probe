# doge-cf-probe

Raw P2P BIP157/158 probe for Dogecoin nodes. No neutrino dependency — pure stdlib.

## What it does

1. TCP connects to your node
2. Performs a full version/verack handshake
3. Sends `getcfheaders` for a block range
4. Decodes the `cfheaders` response and derives the filter header chain
5. Sends `getcfilters` for the same range
6. Decodes each `cfilter` response, hashes the filter bytes, and verifies
   them against the header chain from step 4

## Prerequisites

- Your node running with `-blockfilterindex=1 -peerblockfilters=1`
- Go 1.21+

## Quick start (regtest)

```bash
# In your dogecoin repo, start the node:
./src/dogecoind -regtest -blockfilterindex=1 -peerblockfilters=1 \
  -rpcuser=dogecoinrpc -rpcpassword=test -daemon

# Mine a few blocks so there's something to query:
./src/dogecoin-cli -regtest generatetoaddress 20 $(./src/dogecoin-cli -regtest getnewaddress)

# Run the probe (defaults target regtest):
cd doge-cf-probe
go run . -net=regtest -rpcpass=test -start=1 -end=10
```

## Flags

| Flag       | Default                    | Description                        |
|------------|----------------------------|------------------------------------|
| `-net`     | `regtest`                  | `mainnet`, `testnet`, or `regtest` |
| `-addr`    | `127.0.0.1:<default port>` | Node P2P address                   |
| `-start`   | `1`                        | Start block height                 |
| `-end`     | `10`                       | End block height (inclusive)       |
| `-rpc`     | `http://127.0.0.1:<port>`  | RPC URL                            |
| `-rpcuser` | `dogecoinrpc`              | RPC username                       |
| `-rpcpass` | *(empty)*                  | RPC password                       |

## Example output

```
2024/01/01 00:00:00 fetching stop hash for height 10 via RPC...
2024/01/01 00:00:00 stop hash (LE): 3a4b...
2024/01/01 00:00:00 connecting to 127.0.0.1:18444 (regtest)
2024/01/01 00:00:00 → version sent
2024/01/01 00:00:00 ← received: "version"
2024/01/01 00:00:00 → verack sent
2024/01/01 00:00:00 ← received: "verack"
2024/01/01 00:00:00 ✓ handshake complete

2024/01/01 00:00:00 ── getcfheaders: heights 1–10 ──────────────────────────────
2024/01/01 00:00:00 → getcfheaders sent (filterType=0x00, startHeight=1)
2024/01/01 00:00:00 ← cfheaders received
2024/01/01 00:00:00   filterType : 0x00
2024/01/01 00:00:00   stopHash   : ...
2024/01/01 00:00:00   prevHeader : 0000...
2024/01/01 00:00:00   hashCount  : 10

2024/01/01 00:00:00 ── derived filter header chain ──────────────────────────────
2024/01/01 00:00:00   [1] filterHash=...
2024/01/01 00:00:00        filterHeader=...
...

2024/01/01 00:00:00 ── getcfilters: heights 1–10 ───────────────────────────────
2024/01/01 00:00:00 → getcfilters sent

2024/01/01 00:00:00 ── cfilter responses + hash verification ────────────────────
2024/01/01 00:00:00   [1] blockHash=abc... filterType=0x00 filterLen=9 ✓
2024/01/01 00:00:00        hash verified : def...
2024/01/01 00:00:00        filter hex    : 09027ace...
...
2024/01/01 00:00:00 ✓ all 10 filters verified against cfheader chain
```

## What "✓ all N filters verified" means

Each `cfilter` response's filter bytes are double-SHA256'd and compared to
the corresponding filter hash from the `cfheaders` response. If they all
match, your node's BIP157 server implementation is correctly building,
storing, and serving consistent filters. A mismatch indicates a bug in
the filter construction or index.

## Network magic reference

| Network  | Magic      | P2P Port | RPC Port |
|----------|------------|----------|----------|
| mainnet  | 0xc0c0c0c0 | 22556    | 22555    |
| testnet  | 0xfcc1b7dc | 44556    | 44555    |
| regtest  | 0xfabfb5da | 18444    | 18332    |
