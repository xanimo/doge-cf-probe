// doge-cf-probe: BIP157/158 probe, local filter indexer, and standalone server
// for Dogecoin nodes.
//
// Modes (mutually exclusive; default is probe mode):
//
//   Probe mode: connects to a node, fetches getcfheaders + getcfilters,
//   verifies the filter header chain.  -verify cross-checks against RPC;
//   -match/-matchaddr tests GCS filters against target scriptPubKeys.
//
//   Index mode (-index -db <file>): bulk-fetches all compact filters from
//   the node via P2P (999 blocks per batch, ~1000 blocks/s), stores them in
//   a local bbolt database, then follows the chain tip.  Resumable on restart.
//   Requires -addr (P2P) and -rpc/-rpcuser/-rpcpass (for block hashes).
//
//   Serve mode (-serve): listens for incoming BIP157 peers and serves
//   getcfheaders, getcfilters, and getcfcheckpt.
//     With -db: reads entirely from the local index (standalone — no node needed).
//     Without -db: proxies every request to the backing node's RPC.
//
// Flags:
//   -net       mainnet|testnet|regtest        (default: regtest)
//   -addr      upstream node P2P address      (default: 127.0.0.1:<net-port>)
//   -rpc       RPC endpoint                   (default: http://127.0.0.1:<net-port>)
//   -rpcuser   RPC username                   (default: dogecoinrpc)
//   -rpcpass   RPC password
//   -start     probe start block height       (default: 1)
//   -end       probe end block height         (default: 10)
//   -verify    cross-check P2P vs RPC
//   -match     comma-separated scriptPubKey hex to match
//   -matchaddr comma-separated Dogecoin addresses to match
//   -matchblock on hit, fetch block via RPC and confirm outputs
//   -neutrino  cross-check GCS impl against btcd/gcs
//   -gcsdebug  verbose GCS decoder output
//   -index     build/update local filter database
//   -serve     listen for BIP157 peers and serve filters
//   -db        path to local filter database (bbolt file)
//   -listen    serve listen address           (default: 0.0.0.0:<net-port>)

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/gcs"
	bbolt "go.etcd.io/bbolt"
)

// -- Dogecoin network magic bytes ---------------------------------------------

var magicByNet = map[string][4]byte{
	"mainnet": {0xc0, 0xc0, 0xc0, 0xc0},
	"testnet": {0xfc, 0xc1, 0xb7, 0xdc},
	"regtest": {0xfa, 0xbf, 0xb5, 0xda},
}

var p2pPortByNet = map[string]string{
	"mainnet": "22556",
	"testnet": "44556",
	"regtest": "18444",
}

var rpcPortByNet = map[string]string{
	"mainnet": "22555",
	"testnet": "44555",
	"regtest": "18332",
}

// Dogecoin address version bytes
const (
	addrVersionP2PKH         = 0x1e // mainnet P2PKH  "D..."
	addrVersionP2SH          = 0x16 // mainnet P2SH   "9..." or "A..."
	addrVersionTestnetP2PKH  = 0x71 // testnet P2PKH  "n..."
	addrVersionTestnetP2SH   = 0xc4 // testnet P2SH   "2..."
)

// -- Wire protocol constants --------------------------------------------------

const (
	cmdVersion      = "version"
	cmdVerack       = "verack"
	cmdGetCFHdrs    = "getcfheaders"
	cmdCFHdrs       = "cfheaders"
	cmdGetCFilts    = "getcfilters"
	cmdCFilter      = "cfilter"
	cmdGetCFCheckpt = "getcfcheckpt"
	cmdCFCheckpt    = "cfcheckpt"

	protocolVersion = 70015
	filterTypeBasic = uint8(0x00)
	headerSize      = 24
)

// -- BIP158 GCS parameters ---------------------------------------------------

const (
	gcsP uint8  = 19      // 1/2^19 false positive rate per element
	gcsM uint64 = 784931  // M value from BIP158
)

// -- Hash / crypto helpers ---------------------------------------------------

func dsha256(b []byte) []byte {
	h := sha256.Sum256(b)
	h2 := sha256.Sum256(h[:])
	return h2[:]
}

func ripemd160(b []byte) []byte {
	// RIPEMD-160 implemented per spec — used for P2PKH address derivation.
	// We only need Hash160 = RIPEMD160(SHA256(x)) for address->spk conversion.
	// Rather than ship ripemd160, we use the approach of decoding the address
	// directly (which already contains the hash160) rather than re-hashing.
	panic("should not be called — use decodeAddress instead")
}

func msgChecksum(payload []byte) [4]byte {
	h := dsha256(payload)
	var cs [4]byte
	copy(cs[:], h[:4])
	return cs
}

func reverseBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}

func deriveFilterHeader(fHash, prevHeader []byte) []byte {
	return dsha256(append(fHash, prevHeader...))
}

func filterHashFromBytes(filterBytes []byte) []byte {
	return dsha256(filterBytes)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// -- Base58Check decoder (no external deps) ----------------------------------

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Decode(s string) ([]byte, error) {
	n := big.NewInt(0)
	base := big.NewInt(58)
	for _, c := range s {
		idx := strings.IndexRune(base58Alphabet, c)
		if idx < 0 {
			return nil, fmt.Errorf("invalid base58 character %q", c)
		}
		n.Mul(n, base)
		n.Add(n, big.NewInt(int64(idx)))
	}
	// Count leading '1's → leading zero bytes
	leading := 0
	for _, c := range s {
		if c != '1' {
			break
		}
		leading++
	}
	decoded := n.Bytes()
	result := make([]byte, leading+len(decoded))
	copy(result[leading:], decoded)
	return result, nil
}

func base58CheckDecode(s string) ([]byte, error) {
	decoded, err := base58Decode(s)
	if err != nil {
		return nil, err
	}
	if len(decoded) < 5 {
		return nil, fmt.Errorf("base58check too short")
	}
	payload := decoded[:len(decoded)-4]
	checksum := decoded[len(decoded)-4:]
	h := dsha256(payload)
	if !bytes.Equal(h[:4], checksum) {
		return nil, fmt.Errorf("base58check checksum mismatch")
	}
	return payload, nil
}

// -- Address → scriptPubKey --------------------------------------------------

// addrToScriptPubKey converts a Dogecoin address to its scriptPubKey bytes.
// Supports P2PKH (mainnet "D", testnet "n") and P2SH (mainnet "9"/"A", testnet "2").
func addrToScriptPubKey(addr string) ([]byte, error) {
	payload, err := base58CheckDecode(addr)
	if err != nil {
		return nil, fmt.Errorf("decode address %q: %w", addr, err)
	}
	if len(payload) != 21 {
		return nil, fmt.Errorf("address payload wrong length: %d", len(payload))
	}
	version := payload[0]
	hash := payload[1:] // 20-byte hash160

	switch version {
	case addrVersionP2PKH, addrVersionTestnetP2PKH:
		// OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
		spk := make([]byte, 25)
		spk[0] = 0x76 // OP_DUP
		spk[1] = 0xa9 // OP_HASH160
		spk[2] = 0x14 // push 20 bytes
		copy(spk[3:23], hash)
		spk[23] = 0x88 // OP_EQUALVERIFY
		spk[24] = 0xac // OP_CHECKSIG
		return spk, nil

	case addrVersionP2SH, addrVersionTestnetP2SH:
		// OP_HASH160 <20 bytes> OP_EQUAL
		spk := make([]byte, 23)
		spk[0] = 0xa9 // OP_HASH160
		spk[1] = 0x14 // push 20 bytes
		copy(spk[2:22], hash)
		spk[22] = 0x87 // OP_EQUAL
		return spk, nil

	default:
		return nil, fmt.Errorf("unknown address version byte 0x%02x for %q", version, addr)
	}
}

// -- BIP158 GCS implementation -----------------------------------------------
//
// Golomb-Rice coded set per BIP158 §Golomb-Rice Coding.
// Key insight: the filter stores sorted hashed values; matching means
// hashing your target with the same SipHash key and checking membership.

// sipHash24 is the SipHash-2-4 implementation required by BIP158.
// Key is 16 bytes; returns a 64-bit hash.
func sipHash24(key []byte, data []byte) uint64 {
	// SipHash-2-4 constants
	v0 := uint64(0x736f6d6570736575)
	v1 := uint64(0x646f72616e646f6d)
	v2 := uint64(0x6c7967656e657261)
	v3 := uint64(0x7465646279746573)

	k0 := binary.LittleEndian.Uint64(key[0:8])
	k1 := binary.LittleEndian.Uint64(key[8:16])

	v0 ^= k0
	v1 ^= k1
	v2 ^= k0
	v3 ^= k1

	sipRound := func() {
		v0 += v1; v1 = v1<<13 | v1>>(64-13); v1 ^= v0; v0 = v0<<32 | v0>>(64-32)
		v2 += v3; v3 = v3<<16 | v3>>(64-16); v3 ^= v2
		v0 += v3; v3 = v3<<21 | v3>>(64-21); v3 ^= v0
		v2 += v1; v1 = v1<<17 | v1>>(64-17); v1 ^= v2; v2 = v2<<32 | v2>>(64-32)
	}

	// Process full 8-byte blocks
	length := len(data)
	blocks := length / 8
	for i := 0; i < blocks; i++ {
		m := binary.LittleEndian.Uint64(data[i*8 : i*8+8])
		v3 ^= m
		sipRound()
		sipRound()
		v0 ^= m
	}

	// Last block with length byte
	last := uint64(length) << 56
	tail := data[blocks*8:]
	for i, b := range tail {
		last |= uint64(b) << (uint(i) * 8)
	}
	v3 ^= last
	sipRound()
	sipRound()
	v0 ^= last

	// Finalization
	v2 ^= 0xff
	sipRound()
	sipRound()
	sipRound()
	sipRound()
	return v0 ^ v1 ^ v2 ^ v3
}

// gcsHashKey derives the SipHash key from the block hash (first 16 bytes of LE block hash).
func gcsHashKey(blockHashLE []byte) []byte {
	key := make([]byte, 16)
	copy(key, blockHashLE[:16])
	return key
}

// gcsHash maps data to [0, N*M) per BIP158 using SipHash + modular reduction.
// Formula: floor(SipHash(k, data) * (N*M) / 2^64)
func gcsHash(key []byte, M uint64, N uint64, data []byte) uint64 {
	h := sipHash24(key, data)
	// Must use big.Int for both N*M and the multiply to avoid uint64 overflow.
	hBig := new(big.Int).SetUint64(h)
	nBig := new(big.Int).SetUint64(N)
	mBig := new(big.Int).SetUint64(M)
	nmBig := new(big.Int).Mul(nBig, mBig) // N*M computed without overflow
	prod := new(big.Int).Mul(hBig, nmBig)
	result := new(big.Int).Rsh(prod, 64)
	return result.Uint64()
}

// bitReader reads individual bits from a byte slice.
type bitReader struct {
	data   []byte
	bytePos int
	bitPos  int // 0 = MSB
}

func newBitReader(data []byte) *bitReader {
	return &bitReader{data: data}
}

func (r *bitReader) readBit() (uint64, error) {
	if r.bytePos >= len(r.data) {
		return 0, io.EOF
	}
	bit := uint64((r.data[r.bytePos] >> (7 - uint(r.bitPos))) & 1)
	r.bitPos++
	if r.bitPos == 8 {
		r.bitPos = 0
		r.bytePos++
	}
	return bit, nil
}

func (r *bitReader) readBits(n int) (uint64, error) {
	var result uint64
	for i := 0; i < n; i++ {
		bit, err := r.readBit()
		if err != nil {
			return 0, err
		}
		result = (result << 1) | bit
	}
	return result, nil
}

// bitWriter writes individual bits MSB-first into a bytes.Buffer.
type bitWriter struct {
	buf     *bytes.Buffer
	current byte
	filled  uint
}

func newBitWriter(buf *bytes.Buffer) *bitWriter { return &bitWriter{buf: buf} }

func (w *bitWriter) writeBit(b uint64) {
	if b != 0 {
		w.current |= 1 << (7 - w.filled)
	}
	w.filled++
	if w.filled == 8 {
		w.buf.WriteByte(w.current)
		w.current = 0
		w.filled = 0
	}
}

func (w *bitWriter) flush() {
	if w.filled > 0 {
		w.buf.WriteByte(w.current)
		w.current = 0
		w.filled = 0
	}
}

// golombDecode reads one Golomb-Rice coded value with parameter P.
// The unary quotient is encoded as run of 1-bits terminated by a 0-bit,
// followed by P remainder bits (big-endian within the bit stream).
func golombDecode(br *bitReader, P uint8) (uint64, error) {
	// Unary quotient: count 1-bits until a 0-bit terminator
	var q uint64
	for {
		bit, err := br.readBit()
		if err != nil {
			// Padding bits at end of last byte can cause a spurious EOF
			// here. Return 0 so the caller's loop can finish cleanly.
			if err == io.EOF {
				return 0, io.EOF
			}
			return 0, err
		}
		if bit == 0 {
			break
		}
		q++
	}
	// Read P remainder bits
	r, err := br.readBits(int(P))
	if err != nil {
		if err == io.EOF {
			// Last element may be byte-padded; treat as remainder=0
			return q << P, nil
		}
		return 0, err
	}
	return q<<P | r, nil
}

// gcsMatchAny decodes a BIP158 GCS filter and returns true if any of the
// targets appear in the set. blockHashLE is the 32-byte little-endian block hash.
func gcsMatchAny(blockHashLE []byte, filterBytes []byte, targets [][]byte) (bool, error) {
	if len(filterBytes) == 0 {
		return false, nil // empty filter (coinbase-only block with no outputs)
	}

	key := gcsHashKey(blockHashLE)

	// Decode N (element count) as compact size from front of filter
	r := bytes.NewReader(filterBytes)
	N, err := readCompactSize(r)
	if err != nil {
		return false, fmt.Errorf("gcs: read N: %w", err)
	}
	if N == 0 {
		return false, nil
	}

	// Remaining bytes are the Golomb-Rice bitstream
	remaining, err := io.ReadAll(r)
	if err != nil {
		return false, fmt.Errorf("gcs: read bitstream: %w", err)
	}

	// Hash and sort targets into the same value space as the filter
	targetHashes := make([]uint64, len(targets))
	for i, t := range targets {
		targetHashes[i] = gcsHash(key, gcsM, N, t)
		if gcsDebug {
			log.Printf("  [gcs] target[%d] hash=%d key=%x data=%x", i, targetHashes[i], key, t)
		}
	}
	sortUint64s(targetHashes)

	// Decode filter values (delta-encoded) and check for any target match.
	// We must decode all N elements — do not stop early on EOF since the
	// bitstream is not byte-aligned and padding bits can look like data.
	br := newBitReader(remaining)
	var prev uint64
	ti := 0 // target index (into sorted targetHashes)
	var allVals []uint64 // collected only in debug mode

	for i := uint64(0); i < N; i++ {
		delta, err := golombDecode(br, gcsP)
		if err != nil {
			// Genuine decode error (not just end of stream after N elements)
			return false, fmt.Errorf("gcs: decode element %d/%d: %w", i, N, err)
		}
		val := prev + delta
		prev = val

		if gcsDebug {
			allVals = append(allVals, val)
		}

		// Only advance and check targets if we haven't exhausted them
		if ti < len(targetHashes) {
			for ti < len(targetHashes) && targetHashes[ti] < val {
				ti++
			}
			if ti < len(targetHashes) && targetHashes[ti] == val {
				if gcsDebug {
					log.Printf("  [gcs] HIT at element %d val=%d", i, val)
				}
				return true, nil
			}
		}
	}

	if gcsDebug {
		log.Printf("  [gcs] N=%d key=%x filterBytes=%x", N, key, filterBytes)
		log.Printf("  [gcs] decoded %d values: %v", len(allVals), allVals)
		log.Printf("  [gcs] target hashes: %v", targetHashes)
	}
	return false, nil
}

// gcsDebug enables verbose GCS decoder logging. Set via -gcsdebug flag.
var gcsDebug bool

// -- GCS encoder --------------------------------------------------------------

// gcsEncode builds a BIP158 basic filter from a slice of items (scriptPubKeys).
// blockHashLE is the 32-byte LE block hash that seeds the SipHash key.
// Items must be raw scriptPubKey bytes; duplicates are removed before encoding.
// Note: BIP158 basic filters also include the scriptPubKeys of spent UTXOs
// (input prevouts), which requires UTXO-set access. This encoder covers the
// output side only, which is sufficient when filter bytes are sourced from the
// node (via getblockfilter RPC or P2P) and stored locally.
func gcsEncode(blockHashLE []byte, items [][]byte) []byte {
	seen := make(map[string]bool, len(items))
	var unique [][]byte
	for _, item := range items {
		k := string(item)
		if !seen[k] {
			seen[k] = true
			unique = append(unique, item)
		}
	}

	N := uint64(len(unique))
	var buf bytes.Buffer
	writeCompactSize(&buf, N)
	if N == 0 {
		return buf.Bytes()
	}

	key := gcsHashKey(blockHashLE)
	hashes := make([]uint64, N)
	for i, item := range unique {
		hashes[i] = gcsHash(key, gcsM, N, item)
	}
	sort.Slice(hashes, func(i, j int) bool { return hashes[i] < hashes[j] })

	bw := newBitWriter(&buf)
	var prev uint64
	for _, h := range hashes {
		delta := h - prev
		prev = h
		q := delta >> gcsP
		for i := uint64(0); i < q; i++ {
			bw.writeBit(1)
		}
		bw.writeBit(0)
		r := delta & ((1 << gcsP) - 1)
		for i := int(gcsP) - 1; i >= 0; i-- {
			bw.writeBit((r >> uint(i)) & 1)
		}
	}
	bw.flush()
	return buf.Bytes()
}

// -- Neutrino (btcd/btcutil/gcs) cross-check ----------------------------------

// neutrinoMatchAny decodes the filter using btcd's canonical GCS implementation
// and optionally checks if any targets match. This cross-checks our hand-rolled
// GCS decoder against the neutrino library used by LND and Bitcoin light clients.
// Actual API: FromNBytes(P, M, filterBytes) — key is passed to MatchAny separately.
func neutrinoMatchAny(blockHashLE []byte, filterBytes []byte, targets [][]byte, doMatch bool) (bool, error) {
	if len(filterBytes) == 0 {
		return false, nil
	}

	// BIP158 key: first 16 bytes of block hash LE
	var key [gcs.KeySize]byte
	copy(key[:], blockHashLE[:16])

	// Parse filter — key is NOT passed to FromNBytes, only P and M
	// BIP158 constants: P=19, M=784931
	filter, err := gcs.FromNBytes(19, 784931, filterBytes)
	if err != nil {
		return false, fmt.Errorf("neutrino decode: %w", err)
	}

	if !doMatch || len(targets) == 0 {
		return false, nil
	}

	// MatchAny takes the key and the raw data slices (not pre-hashed)
	matched, err := filter.MatchAny(key, targets)
	if err != nil {
		return false, fmt.Errorf("neutrino MatchAny: %w", err)
	}
	return matched, nil
}

func sortUint64s(s []uint64) {
	// Simple insertion sort — target count is tiny (1-10 typically)
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && s[j] > key {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}

// -- Message framing ---------------------------------------------------------

func buildMsg(magic [4]byte, cmd string, payload []byte) []byte {
	var buf bytes.Buffer
	buf.Write(magic[:])
	var cmdBytes [12]byte
	copy(cmdBytes[:], []byte(cmd))
	buf.Write(cmdBytes[:])
	var lenBytes [4]byte
	binary.LittleEndian.PutUint32(lenBytes[:], uint32(len(payload)))
	buf.Write(lenBytes[:])
	cs := msgChecksum(payload)
	buf.Write(cs[:])
	buf.Write(payload)
	return buf.Bytes()
}

func readMsg(conn net.Conn, magic [4]byte) (cmd string, payload []byte, err error) {
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	hdr := make([]byte, headerSize)
	if _, err = io.ReadFull(conn, hdr); err != nil {
		return
	}
	if !bytes.Equal(hdr[:4], magic[:]) {
		err = fmt.Errorf("magic mismatch: got %x want %x", hdr[:4], magic[:])
		return
	}
	cmd = strings.TrimRight(string(hdr[4:16]), "\x00")
	length := binary.LittleEndian.Uint32(hdr[16:20])
	if length > 32*1024*1024 {
		err = fmt.Errorf("payload too large: %d", length)
		return
	}
	payload = make([]byte, length)
	if length > 0 {
		if _, err = io.ReadFull(conn, payload); err != nil {
			return
		}
		cs := msgChecksum(payload)
		if !bytes.Equal(cs[:], hdr[20:24]) {
			err = fmt.Errorf("checksum mismatch on %q", cmd)
			return
		}
	}
	return
}

// -- Version message ---------------------------------------------------------

func buildVersion(peerAddr string) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, int32(protocolVersion))
	binary.Write(&buf, binary.LittleEndian, uint64(1|1<<6))
	binary.Write(&buf, binary.LittleEndian, int64(time.Now().Unix()))
	writeNetAddr(&buf, peerAddr)
	writeNetAddr(&buf, "127.0.0.1:0")
	binary.Write(&buf, binary.LittleEndian, rand.Uint64())
	ua := "/doge-cf-probe:0.3/"
	buf.WriteByte(byte(len(ua)))
	buf.WriteString(ua)
	binary.Write(&buf, binary.LittleEndian, int32(0))
	buf.WriteByte(0x01)
	return buf.Bytes()
}

func writeNetAddr(buf *bytes.Buffer, addr string) {
	binary.Write(buf, binary.LittleEndian, uint64(1))
	host, portStr, _ := net.SplitHostPort(addr)
	ip := net.ParseIP(host).To16()
	if ip == nil {
		ip = make([]byte, 16)
	}
	buf.Write(ip)
	var port uint16
	fmt.Sscan(portStr, &port)
	binary.Write(buf, binary.BigEndian, port)
}

// -- Handshake ----------------------------------------------------------------

func handshake(conn net.Conn, magic [4]byte, peerAddr string) error {
	if _, err := conn.Write(buildMsg(magic, cmdVersion, buildVersion(peerAddr))); err != nil {
		return fmt.Errorf("send version: %w", err)
	}
	log.Printf("-> version sent")
	verackSent, versionReceived := false, false
	for !verackSent || !versionReceived {
		cmd, _, err := readMsg(conn, magic)
		if err != nil {
			return fmt.Errorf("handshake read: %w", err)
		}
		log.Printf("<- %q", cmd)
		switch cmd {
		case cmdVersion:
			versionReceived = true
			if _, err := conn.Write(buildMsg(magic, cmdVerack, nil)); err != nil {
				return fmt.Errorf("send verack: %w", err)
			}
			log.Printf("-> verack sent")
		case cmdVerack:
			verackSent = true
		}
	}
	log.Printf("handshake complete")
	return nil
}

// -- BIP157 wire messages ----------------------------------------------------

func buildGetCFHeaders(startHeight uint32, stopHash []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(filterTypeBasic)
	binary.Write(&buf, binary.LittleEndian, startHeight)
	buf.Write(stopHash)
	return buf.Bytes()
}

func buildGetCFilters(startHeight uint32, stopHash []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(filterTypeBasic)
	binary.Write(&buf, binary.LittleEndian, startHeight)
	buf.Write(stopHash)
	return buf.Bytes()
}

func parseCFHeaders(payload []byte) (uint8, []byte, []byte, [][]byte, error) {
	if len(payload) < 1+32+32+1 {
		return 0, nil, nil, nil, fmt.Errorf("cfheaders too short: %d", len(payload))
	}
	r := bytes.NewReader(payload)
	var ft uint8
	binary.Read(r, binary.LittleEndian, &ft)
	stopHash := make([]byte, 32)
	io.ReadFull(r, stopHash)
	prevHeader := make([]byte, 32)
	io.ReadFull(r, prevHeader)
	count, err := readCompactSize(r)
	if err != nil {
		return 0, nil, nil, nil, fmt.Errorf("cfheaders count: %w", err)
	}
	hashes := make([][]byte, count)
	for i := uint64(0); i < count; i++ {
		h := make([]byte, 32)
		if _, err := io.ReadFull(r, h); err != nil {
			return 0, nil, nil, nil, fmt.Errorf("cfheaders hash[%d]: %w", i, err)
		}
		hashes[i] = h
	}
	return ft, stopHash, prevHeader, hashes, nil
}

func parseCFilter(payload []byte) (uint8, []byte, []byte, error) {
	// This node's cfilter payload format:
	//   block_hash(32) + filter_type(1) + num_bytes(varint) + filter_data
	// NB: filter_type comes AFTER block_hash, unlike the BIP157 spec which
	// puts filter_type first. This matches the Dogecoin Core implementation.
	if len(payload) < 32+1+1 {
		return 0, nil, nil, fmt.Errorf("cfilter too short: %d", len(payload))
	}
	r := bytes.NewReader(payload)
	blockHash := make([]byte, 32)
	io.ReadFull(r, blockHash)
	var ft uint8
	binary.Read(r, binary.LittleEndian, &ft)
	numBytes, err := readCompactSize(r)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("cfilter numBytes: %w", err)
	}
	filterBytes := make([]byte, numBytes)
	if _, err := io.ReadFull(r, filterBytes); err != nil {
		return 0, nil, nil, fmt.Errorf("cfilter bytes: %w", err)
	}
	return ft, blockHash, filterBytes, nil
}

func readCompactSize(r io.Reader) (uint64, error) {
	var b [1]byte
	if _, err := r.Read(b[:]); err != nil {
		return 0, err
	}
	switch b[0] {
	case 0xfd:
		var v uint16
		binary.Read(r, binary.LittleEndian, &v)
		return uint64(v), nil
	case 0xfe:
		var v uint32
		binary.Read(r, binary.LittleEndian, &v)
		return uint64(v), nil
	case 0xff:
		var v uint64
		binary.Read(r, binary.LittleEndian, &v)
		return v, nil
	default:
		return uint64(b[0]), nil
	}
}

func writeCompactSize(buf *bytes.Buffer, n uint64) {
	switch {
	case n < 0xfd:
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(0xfd)
		binary.Write(buf, binary.LittleEndian, uint16(n))
	case n <= 0xffffffff:
		buf.WriteByte(0xfe)
		binary.Write(buf, binary.LittleEndian, uint32(n))
	default:
		buf.WriteByte(0xff)
		binary.Write(buf, binary.LittleEndian, n)
	}
}

// -- Local filter index (bbolt) ----------------------------------------------
//
// Schema (5 buckets, height keys are 4-byte big-endian for natural ordering):
//   "f"  height → filter bytes
//   "h"  height → filter header (32 bytes LE)
//   "b"  height → block hash    (32 bytes LE)
//   "hb" block hash LE → height (reverse lookup for stop-hash resolution)
//   "m"  meta: "tip" → height

var (
	bktFilters      = []byte("f")
	bktHeaders      = []byte("h")
	bktBlockHashes  = []byte("b")
	bktHashToHeight = []byte("hb")
	bktMeta         = []byte("m")
)

type filterEntry struct {
	height       int
	blockHashLE  []byte
	filterBytes  []byte
	filterHeader []byte
}

type filterDB struct{ db *bbolt.DB }

func openFilterDB(path string) (*filterDB, error) {
	db, err := bbolt.Open(path, 0600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bbolt.Tx) error {
		for _, bkt := range [][]byte{bktFilters, bktHeaders, bktBlockHashes, bktHashToHeight, bktMeta} {
			if _, err := tx.CreateBucketIfNotExists(bkt); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &filterDB{db: db}, nil
}

func (d *filterDB) close() { d.db.Close() }

func heightKey(h int) []byte {
	k := make([]byte, 4)
	binary.BigEndian.PutUint32(k, uint32(h))
	return k
}

func (d *filterDB) tip() int {
	h := -1
	d.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bktMeta).Get([]byte("tip"))
		if len(v) == 4 {
			h = int(binary.BigEndian.Uint32(v))
		}
		return nil
	})
	return h
}

func (d *filterDB) putBatch(entries []filterEntry) error {
	return d.db.Update(func(tx *bbolt.Tx) error {
		fb := tx.Bucket(bktFilters)
		fh := tx.Bucket(bktHeaders)
		bb := tx.Bucket(bktBlockHashes)
		hb := tx.Bucket(bktHashToHeight)
		m := tx.Bucket(bktMeta)
		for _, e := range entries {
			k := heightKey(e.height)
			fb.Put(k, e.filterBytes)
			fh.Put(k, e.filterHeader)
			bb.Put(k, e.blockHashLE)
			hb.Put(e.blockHashLE, k)
		}
		if len(entries) > 0 {
			m.Put([]byte("tip"), heightKey(entries[len(entries)-1].height))
		}
		return nil
	})
}

func (d *filterDB) getFilterBytes(height int) []byte {
	var v []byte
	d.db.View(func(tx *bbolt.Tx) error {
		raw := tx.Bucket(bktFilters).Get(heightKey(height))
		if raw != nil {
			v = append([]byte(nil), raw...)
		}
		return nil
	})
	return v
}

func (d *filterDB) getFilterHeader(height int) []byte {
	var v []byte
	d.db.View(func(tx *bbolt.Tx) error {
		raw := tx.Bucket(bktHeaders).Get(heightKey(height))
		if raw != nil {
			v = append([]byte(nil), raw...)
		}
		return nil
	})
	return v
}

func (d *filterDB) getBlockHashLE(height int) []byte {
	var v []byte
	d.db.View(func(tx *bbolt.Tx) error {
		raw := tx.Bucket(bktBlockHashes).Get(heightKey(height))
		if raw != nil {
			v = append([]byte(nil), raw...)
		}
		return nil
	})
	return v
}

func (d *filterDB) heightForHash(blockHashLE []byte) (int, bool) {
	h := -1
	d.db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket(bktHashToHeight).Get(blockHashLE)
		if len(v) == 4 {
			h = int(binary.BigEndian.Uint32(v))
		}
		return nil
	})
	return h, h >= 0
}

// -- RPC client --------------------------------------------------------------

type rpcClient struct {
	endpoint, user, pass string
}

func (c *rpcClient) call(method string, params []interface{}) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]interface{}{
		"jsonrpc": "1.1", "id": 1, "method": method, "params": params,
	})
	req, _ := http.NewRequest("POST", c.endpoint, bytes.NewReader(body))
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rpc http: %w", err)
	}
	defer resp.Body.Close()
	var result struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("rpc decode: %w", err)
	}
	if result.Error != nil {
		return nil, fmt.Errorf("rpc error: %s", result.Error.Message)
	}
	return result.Result, nil
}

func (c *rpcClient) getBlockHash(height int) ([]byte, error) {
	raw, err := c.call("getblockhash", []interface{}{height})
	if err != nil {
		return nil, err
	}
	var hashStr string
	if err := json.Unmarshal(raw, &hashStr); err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(hashStr)
	if err != nil {
		return nil, err
	}
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b, nil
}

func (c *rpcClient) getBlockHashStr(height int) (string, error) {
	raw, err := c.call("getblockhash", []interface{}{height})
	if err != nil {
		return "", err
	}
	var hashStr string
	if err := json.Unmarshal(raw, &hashStr); err != nil {
		return "", err
	}
	return hashStr, nil
}

type rpcBlockFilter struct {
	Filter string `json:"filter"`
	Header string `json:"header"`
}

// -- Block RPC types for -matchblock -----------------------------------------

type rpcScriptPubKey struct {
	Hex  string `json:"hex"`
	Type string `json:"type"`
}

type rpcVout struct {
	Value       float64         `json:"value"`
	N           int             `json:"n"`
	ScriptPubKey rpcScriptPubKey `json:"scriptPubKey"`
}

type rpcTx struct {
	Txid string    `json:"txid"`
	Vout []rpcVout `json:"vout"`
}

type rpcBlock struct {
	Hash string  `json:"hash"`
	Tx   []rpcTx `json:"tx"`
}

// getBlock fetches a full block with verbosity=2 (full tx data).
func (c *rpcClient) getBlock(blockHashHex string) (*rpcBlock, error) {
	raw, err := c.call("getblock", []interface{}{blockHashHex, 2})
	if err != nil {
		return nil, err
	}
	var block rpcBlock
	if err := json.Unmarshal(raw, &block); err != nil {
		return nil, fmt.Errorf("getblock decode: %w", err)
	}
	return &block, nil
}

func (c *rpcClient) getBlockFilter(blockHashHex string) (*rpcBlockFilter, error) {
	raw, err := c.call("getblockfilter", []interface{}{blockHashHex, "basic"})
	if err != nil {
		return nil, err
	}
	var bf rpcBlockFilter
	if err := json.Unmarshal(raw, &bf); err != nil {
		return nil, fmt.Errorf("getblockfilter decode: %w", err)
	}
	return &bf, nil
}

func (c *rpcClient) getBlockCount() (int, error) {
	raw, err := c.call("getblockcount", nil)
	if err != nil {
		return 0, err
	}
	var count int
	return count, json.Unmarshal(raw, &count)
}

func (c *rpcClient) isInitialBlockDownload() (bool, error) {
	raw, err := c.call("getblockchaininfo", nil)
	if err != nil {
		return false, err
	}
	var info struct {
		InitialBlockDownload bool `json:"initialblockdownload"`
	}
	return info.InitialBlockDownload, json.Unmarshal(raw, &info)
}

func (c *rpcClient) getBlockHeight(blockHashHex string) (int, error) {
	raw, err := c.call("getblockheader", []interface{}{blockHashHex, true})
	if err != nil {
		return 0, err
	}
	var hdr struct {
		Height int `json:"height"`
	}
	return hdr.Height, json.Unmarshal(raw, &hdr)
}

type rpcIndexEntry struct {
	Synced          bool `json:"synced"`
	BestBlockHeight int  `json:"best_block_height"`
}

func (c *rpcClient) getFilterIndexSynced() (bool, int, error) {
	raw, err := c.call("getindexinfo", nil)
	if err != nil {
		return false, 0, err
	}
	var info map[string]rpcIndexEntry
	if err := json.Unmarshal(raw, &info); err != nil {
		return false, 0, err
	}
	// Dogecoin Core uses "basic block filter index"; Bitcoin Core uses "blockfilterindex".
	for _, key := range []string{"basic block filter index", "blockfilterindex"} {
		if entry, ok := info[key]; ok {
			return entry.Synced, entry.BestBlockHeight, nil
		}
	}
	return false, 0, fmt.Errorf("blockfilterindex not in getindexinfo (is -blockfilterindex enabled?)")
}

// -- Verification result -----------------------------------------------------

type verifyResult struct {
	height        int
	p2pFilterHex  string
	p2pFilterHash string
	p2pFHdrHex    string
	rpcFilterHex  string
	rpcFHdrHex    string
	hashChainOK   bool
	filterMatchOK bool
	fHdrMatchOK   bool
	verifyEnabled bool

	// Match result
	matchEnabled bool
	matchHit     bool   // true if any target found in this filter
	matchErr     string // non-empty if GCS decode failed

	// Neutrino cross-check
	neutrinoEnabled  bool
	neutrinoDecodeOK bool   // btcd/gcs decoded the filter without error
	neutrinoHit      bool   // neutrino match result (only valid if matchEnabled)
	neutrinoMismatch bool   // our impl and neutrino disagreed
	neutrinoErr      string // non-empty if neutrino returned an error
}

func (r verifyResult) allOK() bool {
	if !r.hashChainOK {
		return false
	}
	if r.verifyEnabled && (!r.filterMatchOK || !r.fHdrMatchOK) {
		return false
	}
	if r.neutrinoEnabled && (r.neutrinoMismatch || r.neutrinoErr != "") {
		return false
	}
	return true
}

func (r verifyResult) print() {
	mark := func(ok bool) string {
		if ok {
			return "OK"
		}
		return "MISMATCH"
	}

	matchSuffix := ""
	if r.matchEnabled {
		if r.matchErr != "" {
			matchSuffix = fmt.Sprintf("  match=ERROR(%s)", r.matchErr)
		} else if r.matchHit {
			matchSuffix = "  match=HIT <-- ADDRESS FOUND"
		} else {
			matchSuffix = "  match=no"
		}
	}

	if r.verifyEnabled {
		log.Printf("  [%d] hash-chain=%-8s  filter-bytes=%-8s  fheader=%-8s%s",
			r.height, mark(r.hashChainOK), mark(r.filterMatchOK), mark(r.fHdrMatchOK), matchSuffix)
		if !r.filterMatchOK {
			log.Printf("       P2P filter : %s", truncate(r.p2pFilterHex, 64))
			log.Printf("       RPC filter : %s", truncate(r.rpcFilterHex, 64))
		}
		if !r.fHdrMatchOK {
			log.Printf("       P2P fheader: %s", r.p2pFHdrHex)
			log.Printf("       RPC fheader: %s", r.rpcFHdrHex)
		}
	} else {
		log.Printf("  [%d] hash-chain=%-8s%s", r.height, mark(r.hashChainOK), matchSuffix)
	}

	if !r.hashChainOK {
		log.Printf("       computed hash: %s", r.p2pFilterHash)
	}

	if r.neutrinoEnabled {
		if r.neutrinoErr != "" {
			log.Printf("       neutrino: ERROR -- %s", r.neutrinoErr)
		} else if r.neutrinoMismatch {
			log.Printf("       neutrino: MISMATCH -- our_impl=%v neutrino=%v",
				r.matchHit, r.neutrinoHit)
		} else {
			status := "decode=OK"
			if r.matchEnabled {
				if r.neutrinoHit {
					status = "decode=OK  match=HIT (agrees)"
				} else {
					status = "decode=OK  match=no  (agrees)"
				}
			}
			log.Printf("       neutrino: %s", status)
		}
	}
}

// -- P2P index builder --------------------------------------------------------
//
// fetchAndStoreBatch fetches one batch (up to 999 blocks) of filter headers
// and filters from the upstream node via P2P, verifies the hash chain, and
// writes all entries to the local database in a single transaction.

func fetchAndStoreBatch(db *filterDB, peerAddr string, magic [4]byte, from, count int, stopHash []byte) error {
	conn, err := net.DialTimeout("tcp", peerAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()

	if err := handshake(conn, magic, peerAddr); err != nil {
		return fmt.Errorf("handshake: %w", err)
	}

	// getcfheaders
	if _, err := conn.Write(buildMsg(magic, cmdGetCFHdrs, buildGetCFHeaders(uint32(from), stopHash))); err != nil {
		return fmt.Errorf("send getcfheaders: %w", err)
	}
	var filterHashes [][]byte
	var prevFHdr []byte
	for {
		cmd, payload, err := readMsg(conn, magic)
		if err != nil {
			return fmt.Errorf("read cfheaders: %w", err)
		}
		if cmd != cmdCFHdrs {
			continue
		}
		_, _, prevH, hashes, err := parseCFHeaders(payload)
		if err != nil {
			return fmt.Errorf("parse cfheaders: %w", err)
		}
		filterHashes = hashes
		prevFHdr = prevH
		break
	}
	if len(filterHashes) != count {
		return fmt.Errorf("expected %d hashes, got %d", count, len(filterHashes))
	}

	// Verify prevFHdr is consistent with what we already have stored.
	if from == 0 {
		for _, b := range prevFHdr {
			if b != 0 {
				return fmt.Errorf("genesis prevFHdr not all-zeros")
			}
		}
	} else if stored := db.getFilterHeader(from - 1); stored != nil && !bytes.Equal(stored, prevFHdr) {
		return fmt.Errorf("filter header chain break at height %d", from-1)
	}

	// Derive filter headers for this batch.
	derivedHeaders := make([][]byte, count)
	prev := prevFHdr
	for i, fh := range filterHashes {
		dh := deriveFilterHeader(fh, prev)
		derivedHeaders[i] = dh
		prev = dh
	}

	// getcfilters
	if _, err := conn.Write(buildMsg(magic, cmdGetCFilts, buildGetCFilters(uint32(from), stopHash))); err != nil {
		return fmt.Errorf("send getcfilters: %w", err)
	}
	entries := make([]filterEntry, count)
	received := 0
	for received < count {
		cmd, payload, err := readMsg(conn, magic)
		if err != nil {
			return fmt.Errorf("read cfilter[%d]: %w", received, err)
		}
		if cmd != cmdCFilter {
			continue
		}
		_, blockHashLE, filterBytes, err := parseCFilter(payload)
		if err != nil {
			return fmt.Errorf("parse cfilter[%d]: %w", received, err)
		}
		computed := filterHashFromBytes(filterBytes)
		if !bytes.Equal(computed, filterHashes[received]) {
			return fmt.Errorf("filter hash mismatch at height %d", from+received)
		}
		entries[received] = filterEntry{
			height:       from + received,
			blockHashLE:  append([]byte(nil), blockHashLE...),
			filterBytes:  append([]byte(nil), filterBytes...),
			filterHeader: derivedHeaders[received],
		}
		received++
	}
	return db.putBatch(entries)
}

// buildIndex syncs the local filter database from the node via P2P up to the
// current chain tip.  It is resumable: it picks up from db.tip()+1 on each call.
func buildIndex(db *filterDB, rpc *rpcClient, peerAddr string, magic [4]byte) error {
	chainTip, err := rpc.getBlockCount()
	if err != nil {
		return fmt.Errorf("getblockcount: %w", err)
	}
	from := db.tip() + 1
	if from > chainTip {
		log.Printf("index: already at chain tip (%d)", chainTip)
		return nil
	}
	log.Printf("index: syncing heights %d → %d (%d blocks)", from, chainTip, chainTip-from+1)

	for from <= chainTip {
		batchEnd := from + 999
		if batchEnd > chainTip {
			batchEnd = chainTip
		}
		count := batchEnd - from + 1

		stopHash, err := rpc.getBlockHash(batchEnd)
		if err != nil {
			return fmt.Errorf("getblockhash(%d): %w", batchEnd, err)
		}

		var fetchErr error
		for attempt := 1; attempt <= 3; attempt++ {
			fetchErr = fetchAndStoreBatch(db, peerAddr, magic, from, count, stopHash)
			if fetchErr == nil {
				break
			}
			log.Printf("index: batch %d-%d error (attempt %d/3): %v", from, batchEnd, attempt, fetchErr)
			if attempt < 3 {
				time.Sleep(5 * time.Second)
			}
		}
		if fetchErr != nil {
			return fmt.Errorf("batch %d-%d: %w", from, batchEnd, fetchErr)
		}

		if batchEnd%50000 < 1000 || batchEnd == chainTip {
			log.Printf("index: synced to %d/%d (%.1f%%)", batchEnd, chainTip,
				float64(batchEnd)/float64(chainTip)*100)
		}
		from = batchEnd + 1
	}
	log.Printf("index: sync complete at height %d", chainTip)
	return nil
}

// indexLoop runs buildIndex once, then follows the chain tip by polling every
// 60 seconds and indexing any new blocks that appear.
func indexLoop(db *filterDB, rpc *rpcClient, peerAddr string, magic [4]byte) {
	log.Printf("index: following tip (polling every 60s)")
	for {
		time.Sleep(60 * time.Second)
		if err := buildIndex(db, rpc, peerAddr, magic); err != nil {
			log.Printf("index: tip sync error: %v", err)
		}
	}
}

// -- Filter server (BIP157 serve mode) ----------------------------------------

func waitForIBD(rpc *rpcClient) {
	log.Printf("serve: waiting for IBD to finish and blockfilterindex to sync...")
	for {
		ibd, err := rpc.isInitialBlockDownload()
		if err != nil {
			log.Printf("serve: getblockchaininfo: %v (retry in 30s)", err)
			time.Sleep(30 * time.Second)
			continue
		}
		if ibd {
			tip, _ := rpc.getBlockCount()
			log.Printf("serve: IBD in progress (tip=%d), waiting...", tip)
			time.Sleep(30 * time.Second)
			continue
		}
		synced, filterHeight, err := rpc.getFilterIndexSynced()
		if err != nil {
			log.Printf("serve: getindexinfo: %v (retry in 30s)", err)
			time.Sleep(30 * time.Second)
			continue
		}
		tip, _ := rpc.getBlockCount()
		if !synced || filterHeight < tip {
			log.Printf("serve: blockfilterindex syncing (%d/%d), waiting...", filterHeight, tip)
			time.Sleep(30 * time.Second)
			continue
		}
		log.Printf("serve: ready — IBD complete, blockfilterindex synced at height %d", tip)
		return
	}
}

func serverHandshake(conn net.Conn, magic [4]byte) error {
	verackSent, verackReceived, versionSent := false, false, false
	for !verackSent || !verackReceived {
		cmd, _, err := readMsg(conn, magic)
		if err != nil {
			return fmt.Errorf("handshake read: %w", err)
		}
		switch cmd {
		case cmdVersion:
			if !versionSent {
				if _, err := conn.Write(buildMsg(magic, cmdVersion, buildVersion(conn.RemoteAddr().String()))); err != nil {
					return fmt.Errorf("send version: %w", err)
				}
				versionSent = true
			}
			if _, err := conn.Write(buildMsg(magic, cmdVerack, nil)); err != nil {
				return fmt.Errorf("send verack: %w", err)
			}
			verackSent = true
		case cmdVerack:
			verackReceived = true
		}
	}
	return nil
}

func parseGetCFRequest(payload []byte) (filterType uint8, startHeight uint32, stopHash []byte, err error) {
	if len(payload) < 1+4+32 {
		return 0, 0, nil, fmt.Errorf("request too short: %d bytes", len(payload))
	}
	filterType = payload[0]
	startHeight = binary.LittleEndian.Uint32(payload[1:5])
	stopHash = make([]byte, 32)
	copy(stopHash, payload[5:37])
	return
}

// handleGetCFCheckpoint serves a getcfcheckpt request (BIP157 §getcfcheckpt).
// Returns filter headers at heights 999, 1999, 2999, ... up to stopHeight.
// db / rpc semantics are the same as the other handlers.
func handleGetCFCheckpoint(conn net.Conn, magic [4]byte, rpc *rpcClient, db *filterDB, payload []byte, peerAddr string) error {
	if len(payload) < 1+32 {
		return fmt.Errorf("getcfcheckpt too short: %d bytes", len(payload))
	}
	ft := payload[0]
	if ft != filterTypeBasic {
		return fmt.Errorf("unsupported filter type 0x%02x", ft)
	}
	stopHashLE := append([]byte(nil), payload[1:33]...)

	var stopHeight int
	var err error
	if db != nil {
		h, ok := db.heightForHash(stopHashLE)
		if !ok {
			return fmt.Errorf("stop hash not in local index")
		}
		stopHeight = h
	} else {
		stopHashHex := hex.EncodeToString(reverseBytes(stopHashLE))
		stopHeight, err = rpc.getBlockHeight(stopHashHex)
		if err != nil {
			return fmt.Errorf("getblockheader: %w", err)
		}
	}

	log.Printf("serve: %s: getcfcheckpt stop=%d", peerAddr, stopHeight)

	// Checkpoint heights: 999, 1999, 2999, ... up to stopHeight.
	var checkpointHeights []int
	for h := 999; h <= stopHeight; h += 1000 {
		checkpointHeights = append(checkpointHeights, h)
	}

	headers := make([][]byte, len(checkpointHeights))
	for i, h := range checkpointHeights {
		if db != nil {
			fh := db.getFilterHeader(h)
			if fh == nil {
				return fmt.Errorf("missing filter header at height %d", h)
			}
			headers[i] = fh
		} else {
			hashStr, err := rpc.getBlockHashStr(h)
			if err != nil {
				return fmt.Errorf("getblockhash(%d): %w", h, err)
			}
			bf, err := rpc.getBlockFilter(hashStr)
			if err != nil {
				return fmt.Errorf("getblockfilter(%s): %w", hashStr, err)
			}
			hdrBytes, _ := hex.DecodeString(bf.Header)
			headers[i] = reverseBytes(hdrBytes)
		}
	}

	var buf bytes.Buffer
	buf.WriteByte(filterTypeBasic)
	buf.Write(stopHashLE)
	writeCompactSize(&buf, uint64(len(headers)))
	for _, h := range headers {
		buf.Write(h)
	}
	_, err = conn.Write(buildMsg(magic, cmdCFCheckpt, buf.Bytes()))
	return err
}

// handleGetCFHeaders serves a getcfheaders request.
// When db is non-nil, all data is read from the local index (standalone mode).
// When db is nil, data is fetched from the backing node via RPC (proxy mode).
func handleGetCFHeaders(conn net.Conn, magic [4]byte, rpc *rpcClient, db *filterDB, payload []byte, peerAddr string) error {
	ft, startHeight, stopHashLE, err := parseGetCFRequest(payload)
	if err != nil {
		return err
	}
	if ft != filterTypeBasic {
		return fmt.Errorf("unsupported filter type 0x%02x", ft)
	}

	var stopHeight int
	if db != nil {
		h, ok := db.heightForHash(stopHashLE)
		if !ok {
			return fmt.Errorf("stop hash not in local index")
		}
		stopHeight = h
	} else {
		stopHashHex := hex.EncodeToString(reverseBytes(stopHashLE))
		stopHeight, err = rpc.getBlockHeight(stopHashHex)
		if err != nil {
			return fmt.Errorf("getblockheader: %w", err)
		}
	}

	count := stopHeight - int(startHeight) + 1
	if count <= 0 {
		return fmt.Errorf("invalid range: start=%d stop=%d", startHeight, stopHeight)
	}
	if count > 1000 {
		count = 1000
		stopHeight = int(startHeight) + 999
	}

	log.Printf("serve: %s: getcfheaders %d-%d (%d blocks)", peerAddr, startHeight, stopHeight, count)

	var prevFHdr []byte
	if startHeight == 0 {
		prevFHdr = make([]byte, 32)
	} else if db != nil {
		prevFHdr = db.getFilterHeader(int(startHeight) - 1)
		if prevFHdr == nil {
			return fmt.Errorf("missing filter header at height %d", int(startHeight)-1)
		}
	} else {
		prevHashStr, err := rpc.getBlockHashStr(int(startHeight) - 1)
		if err != nil {
			return fmt.Errorf("getblockhash(%d): %w", int(startHeight)-1, err)
		}
		prevBF, err := rpc.getBlockFilter(prevHashStr)
		if err != nil {
			return fmt.Errorf("getblockfilter prev: %w", err)
		}
		hdrBytes, _ := hex.DecodeString(prevBF.Header)
		prevFHdr = reverseBytes(hdrBytes)
	}

	filterHashes := make([][]byte, count)
	for i := 0; i < count; i++ {
		h := int(startHeight) + i
		if db != nil {
			fb := db.getFilterBytes(h)
			if fb == nil {
				return fmt.Errorf("missing filter at height %d", h)
			}
			filterHashes[i] = filterHashFromBytes(fb)
		} else {
			hashStr, err := rpc.getBlockHashStr(h)
			if err != nil {
				return fmt.Errorf("getblockhash(%d): %w", h, err)
			}
			bf, err := rpc.getBlockFilter(hashStr)
			if err != nil {
				return fmt.Errorf("getblockfilter(%s): %w", hashStr, err)
			}
			fb, _ := hex.DecodeString(bf.Filter)
			filterHashes[i] = filterHashFromBytes(fb)
		}
	}

	var buf bytes.Buffer
	buf.WriteByte(filterTypeBasic)
	buf.Write(stopHashLE)
	buf.Write(prevFHdr)
	writeCompactSize(&buf, uint64(count))
	for _, fh := range filterHashes {
		buf.Write(fh)
	}
	_, err = conn.Write(buildMsg(magic, cmdCFHdrs, buf.Bytes()))
	return err
}

// handleGetCFilters serves a getcfilters request.
// db semantics are the same as handleGetCFHeaders.
func handleGetCFilters(conn net.Conn, magic [4]byte, rpc *rpcClient, db *filterDB, payload []byte, peerAddr string) error {
	ft, startHeight, stopHashLE, err := parseGetCFRequest(payload)
	if err != nil {
		return err
	}
	if ft != filterTypeBasic {
		return fmt.Errorf("unsupported filter type 0x%02x", ft)
	}

	var stopHeight int
	if db != nil {
		h, ok := db.heightForHash(stopHashLE)
		if !ok {
			return fmt.Errorf("stop hash not in local index")
		}
		stopHeight = h
	} else {
		stopHashHex := hex.EncodeToString(reverseBytes(stopHashLE))
		stopHeight, err = rpc.getBlockHeight(stopHashHex)
		if err != nil {
			return fmt.Errorf("getblockheader: %w", err)
		}
	}

	count := stopHeight - int(startHeight) + 1
	if count <= 0 {
		return fmt.Errorf("invalid range: start=%d stop=%d", startHeight, stopHeight)
	}
	if count > 1000 {
		count = 1000
		stopHeight = int(startHeight) + 999
	}

	log.Printf("serve: %s: getcfilters %d-%d (%d blocks)", peerAddr, startHeight, stopHeight, count)

	for i := 0; i < count; i++ {
		h := int(startHeight) + i
		var blockHashLE, filterBytes []byte
		if db != nil {
			blockHashLE = db.getBlockHashLE(h)
			filterBytes = db.getFilterBytes(h)
			if blockHashLE == nil || filterBytes == nil {
				return fmt.Errorf("missing data at height %d", h)
			}
		} else {
			hashStr, err := rpc.getBlockHashStr(h)
			if err != nil {
				return fmt.Errorf("getblockhash(%d): %w", h, err)
			}
			hb, _ := hex.DecodeString(hashStr)
			blockHashLE = reverseBytes(hb)
			bf, err := rpc.getBlockFilter(hashStr)
			if err != nil {
				return fmt.Errorf("getblockfilter(%s): %w", hashStr, err)
			}
			filterBytes, _ = hex.DecodeString(bf.Filter)
		}

		// Dogecoin cfilter wire format: block_hash(32) + filter_type(1) + varint + data
		var buf bytes.Buffer
		buf.Write(blockHashLE)
		buf.WriteByte(filterTypeBasic)
		writeCompactSize(&buf, uint64(len(filterBytes)))
		buf.Write(filterBytes)
		if _, err := conn.Write(buildMsg(magic, cmdCFilter, buf.Bytes())); err != nil {
			return fmt.Errorf("send cfilter[%d]: %w", h, err)
		}
	}
	return nil
}

func handlePeer(conn net.Conn, magic [4]byte, rpc *rpcClient, db *filterDB) {
	defer conn.Close()
	addr := conn.RemoteAddr().String()
	log.Printf("serve: peer connected: %s", addr)

	if err := serverHandshake(conn, magic); err != nil {
		log.Printf("serve: %s: handshake: %v", addr, err)
		return
	}
	log.Printf("serve: %s: handshake complete", addr)

	for {
		cmd, payload, err := readMsg(conn, magic)
		if err != nil {
			log.Printf("serve: %s: disconnected: %v", addr, err)
			return
		}
		switch cmd {
		case cmdGetCFHdrs:
			if err := handleGetCFHeaders(conn, magic, rpc, db, payload, addr); err != nil {
				log.Printf("serve: %s: getcfheaders error: %v", addr, err)
				return
			}
		case cmdGetCFilts:
			if err := handleGetCFilters(conn, magic, rpc, db, payload, addr); err != nil {
				log.Printf("serve: %s: getcfilters error: %v", addr, err)
				return
			}
		case cmdGetCFCheckpt:
			if err := handleGetCFCheckpoint(conn, magic, rpc, db, payload, addr); err != nil {
				log.Printf("serve: %s: getcfcheckpt error: %v", addr, err)
				return
			}
		case "ping":
			if len(payload) == 8 {
				conn.Write(buildMsg(magic, "pong", payload))
			}
		default:
			log.Printf("serve: %s: skip %q", addr, cmd)
		}
	}
}

func serveLoop(listenAddr string, magic [4]byte, rpc *rpcClient, db *filterDB) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("serve: listen %s: %v", listenAddr, err)
	}
	if db != nil {
		log.Printf("serve: listening on %s (standalone — local index, tip=%d)", listenAddr, db.tip())
	} else {
		log.Printf("serve: listening on %s (proxy — RPC backend)", listenAddr)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("serve: accept: %v", err)
			continue
		}
		go handlePeer(conn, magic, rpc, db)
	}
}

// -- Main --------------------------------------------------------------------

func main() {
	var (
		netName    = flag.String("net",       "regtest",     "mainnet|testnet|regtest")
		peerAddr   = flag.String("addr",      "",            "node P2P address (host:port)")
		start      = flag.Int("start",        1,             "start block height")
		end        = flag.Int("end",          10,            "end block height (inclusive)")
		rpcURL     = flag.String("rpc",       "",            "RPC URL")
		rpcUser    = flag.String("rpcuser",   "dogecoinrpc", "RPC username")
		rpcPass    = flag.String("rpcpass",   "",            "RPC password")
		verify     = flag.Bool("verify",      false,         "cross-check P2P filters against RPC getblockfilter")
		matchSPK   = flag.String("match",      "",            "comma-separated scriptPubKey hex strings to match in filters")
		matchAddr  = flag.String("matchaddr",  "",            "comma-separated Dogecoin addresses to match (P2PKH/P2SH)")
		matchBlock = flag.Bool("matchblock",  false,         "on filter hit, fetch full block via RPC and confirm matching outputs")
		matchFile  = flag.String("matchfile",  "",            "file containing one scriptPubKey hex per line (avoids ARG_MAX limits)")
		neutrinoF  = flag.Bool("neutrino",     false,         "cross-check our GCS impl against btcd/btcutil/gcs (neutrino) for each filter")
		gcsdebugF  = flag.Bool("gcsdebug",     false,         "print verbose GCS decoder internals for debugging")
		serverMode = flag.Bool("serve",   false, "serve BIP157/158 filters to incoming P2P peers")
		listenAddr = flag.String("listen", "",    "listen address for -serve mode (default: 0.0.0.0:<net-port>)")
		indexMode  = flag.Bool("index",   false, "build/update local filter database from node via P2P, then follow tip")
		dbPath     = flag.String("db",    "",    "path to local filter database (bbolt file; used by -index and -serve)")
	)
	flag.Parse()
	gcsDebug = *gcsdebugF

	magic, ok := magicByNet[*netName]
	if !ok {
		log.Fatalf("unknown network %q", *netName)
	}
	if *peerAddr == "" {
		*peerAddr = "127.0.0.1:" + p2pPortByNet[*netName]
	}
	if *rpcURL == "" {
		*rpcURL = "http://127.0.0.1:" + rpcPortByNet[*netName]
	}

	// -- Build target scriptPubKey set ----------------------------------------

	var targets [][]byte
	matchEnabled := false

	if *matchSPK != "" {
		for _, s := range strings.Split(*matchSPK, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			b, err := hex.DecodeString(s)
			if err != nil {
				log.Fatalf("invalid scriptPubKey hex %q: %v", s, err)
			}
			targets = append(targets, b)
			log.Printf("target scriptPubKey: %x", b)
		}
		matchEnabled = true
	}

	if *matchFile != "" {
		data, err := os.ReadFile(*matchFile)
		if err != nil {
			log.Fatalf("matchfile read: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			spk, err := hex.DecodeString(line)
			if err != nil {
				log.Fatalf("matchfile: invalid hex %q: %v", line, err)
			}
			targets = append(targets, spk)
		}
		if len(targets) > 0 {
			log.Printf("matchfile: loaded %d scriptPubKeys from %s", len(targets), *matchFile)
			matchEnabled = true
		}
	}

	if *matchAddr != "" {
		log.Printf("NOTE: -matchaddr matches P2PKH and P2SH outputs only.")
		log.Printf("      P2PK outputs (common in early blocks and coinbases) store the raw")
		log.Printf("      public key in the scriptPubKey, not the address hash. Those outputs")
		log.Printf("      will NOT match via -matchaddr. Use -match with the raw scriptPubKey")
		log.Printf("      hex from: dogecoin-cli getblock <hash> 2 | jq '.tx[].vout[].scriptPubKey.hex'")
		for _, addr := range strings.Split(*matchAddr, ",") {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			spk, err := addrToScriptPubKey(addr)
			if err != nil {
				log.Fatalf("address decode failed: %v", err)
			}
			// Detect and label the script type for the user
			scriptType := "P2PKH"
			if len(spk) == 23 && spk[0] == 0xa9 {
				scriptType = "P2SH"
			}
			targets = append(targets, spk)
			log.Printf("target [%s] %s -> scriptPubKey: %x", scriptType, addr, spk)
		}
		matchEnabled = true
	}

	if matchEnabled {
		log.Printf("matching %d target(s) against each filter", len(targets))
		if *matchBlock {
			log.Printf("matchblock ON -- hit blocks will be fetched and confirmed via RPC")
		}
	}
	if *verify {
		log.Printf("verify mode ON")
	}

	rpc := &rpcClient{endpoint: *rpcURL, user: *rpcUser, pass: *rpcPass}

	// -- Index mode ------------------------------------------------------------
	if *indexMode {
		if *dbPath == "" {
			log.Fatalf("-index requires -db <path>")
		}
		if *peerAddr == "" {
			*peerAddr = "127.0.0.1:" + p2pPortByNet[*netName]
		}
		db, err := openFilterDB(*dbPath)
		if err != nil {
			log.Fatalf("open db %s: %v", *dbPath, err)
		}
		defer db.close()
		log.Printf("index: database %s (tip=%d)", *dbPath, db.tip())
		waitForIBD(rpc)
		if err := buildIndex(db, rpc, *peerAddr, magic); err != nil {
			log.Fatalf("index: build failed: %v", err)
		}
		indexLoop(db, rpc, *peerAddr, magic)
		return
	}

	// -- Serve mode ------------------------------------------------------------
	if *serverMode {
		var db *filterDB
		if *dbPath != "" {
			var err error
			db, err = openFilterDB(*dbPath)
			if err != nil {
				log.Fatalf("open db %s: %v", *dbPath, err)
			}
			defer db.close()
			tip := db.tip()
			if tip < 0 {
				log.Fatalf("serve: local index at %s is empty — run -index first", *dbPath)
			}
			log.Printf("serve: local index (tip=%d) — standalone mode", tip)
		} else {
			// RPC proxy mode: wait for IBD before opening the listener.
			waitForIBD(rpc)
		}
		if *listenAddr == "" {
			*listenAddr = "0.0.0.0:" + p2pPortByNet[*netName]
		}
		serveLoop(*listenAddr, magic, rpc, db)
		return
	}

	// Fetch stop hash
	log.Printf("fetching stop hash for height %d...", *end)
	stopHash, err := rpc.getBlockHash(*end)
	if err != nil {
		log.Fatalf("getblockhash(%d): %v", *end, err)
	}
	log.Printf("stop hash (LE): %x", stopHash)

	// Connect + handshake
	log.Printf("connecting to %s (%s)", *peerAddr, *netName)
	conn, err := net.DialTimeout("tcp", *peerAddr, 10*time.Second)
	if err != nil {
		log.Fatalf("connect: %v", err)
	}
	defer conn.Close()

	if err := handshake(conn, magic, *peerAddr); err != nil {
		log.Fatalf("handshake: %v", err)
	}

	// -- getcfheaders ----------------------------------------------------------

	log.Printf("-- getcfheaders: heights %d-%d", *start, *end)
	if _, err := conn.Write(buildMsg(magic, cmdGetCFHdrs, buildGetCFHeaders(uint32(*start), stopHash))); err != nil {
		log.Fatalf("send getcfheaders: %v", err)
	}

	var filterHashes [][]byte
	var prevFHdr []byte
	for {
		cmd, payload, err := readMsg(conn, magic)
		if err != nil {
			log.Fatalf("read cfheaders: %v", err)
		}
		if cmd != cmdCFHdrs {
			log.Printf("  (skip: %q)", cmd)
			continue
		}
		ft, sh, prevH, hashes, err := parseCFHeaders(payload)
		if err != nil {
			log.Fatalf("parse cfheaders: %v", err)
		}
		log.Printf("<- cfheaders: filterType=0x%02x stopHash=%064x prevHeader=%x count=%d",
			ft, reverseBytes(sh), prevH, len(hashes))
		filterHashes = hashes
		prevFHdr = prevH
		break
	}

	derivedHeaders := make([][]byte, len(filterHashes))
	prev := prevFHdr
	for i, fh := range filterHashes {
		dh := deriveFilterHeader(fh, prev)
		derivedHeaders[i] = dh
		prev = dh
	}

	// -- getcfilters -----------------------------------------------------------

	log.Printf("-- getcfilters: heights %d-%d", *start, *end)
	if _, err := conn.Write(buildMsg(magic, cmdGetCFilts, buildGetCFilters(uint32(*start), stopHash))); err != nil {
		log.Fatalf("send getcfilters: %v", err)
	}

	expected := *end - *start + 1
	received := 0
	results := make([]verifyResult, expected)
	totalMismatches := 0
	var hitHeights []int

	log.Printf("-- processing %d filters", expected)

	for received < expected {
		cmd, payload, err := readMsg(conn, magic)
		if err != nil {
			log.Fatalf("read cfilter[%d]: %v", received, err)
		}
		if cmd != cmdCFilter {
			log.Printf("  (skip: %q)", cmd)
			continue
		}

		_, blockHash, fb, err := parseCFilter(payload)
		if err != nil {
			log.Fatalf("parse cfilter[%d]: %v", received, err)
		}

		height := *start + received
		if gcsDebug {
			log.Printf("  [parse] payload[0:4]=%x blockHash[0:4]=%x", payload[:4], blockHash[:4])
		}
		blockHashBE := fmt.Sprintf("%064x", reverseBytes(blockHash))

		computedFHash := filterHashFromBytes(fb)
		hashChainOK := bytes.Equal(computedFHash, filterHashes[received])

		res := verifyResult{
			height:        height,
			p2pFilterHex:  hex.EncodeToString(fb),
			p2pFilterHash: hex.EncodeToString(computedFHash),
			p2pFHdrHex:    hex.EncodeToString(derivedHeaders[received]),
			hashChainOK:   hashChainOK,
			verifyEnabled: *verify,
			filterMatchOK: true,
			fHdrMatchOK:   true,
			matchEnabled:  matchEnabled,
		}

		// -- RPC cross-check --------------------------------------------------
		if *verify {
			rpcHashStr, hashErr := rpc.getBlockHashStr(height)
			if hashErr != nil {
				log.Printf("  [%d] WARNING: getblockhash RPC failed: %v", height, hashErr)
				res.filterMatchOK = false
				res.fHdrMatchOK = false
			} else {
				rpcBF, err := rpc.getBlockFilter(rpcHashStr)
				if err != nil {
					log.Printf("  [%d] WARNING: getblockfilter RPC failed: %v (hash: %s)", height, err, rpcHashStr)
					res.filterMatchOK = false
					res.fHdrMatchOK = false
				} else {
					res.rpcFilterHex = rpcBF.Filter
					res.filterMatchOK = (res.p2pFilterHex == res.rpcFilterHex)
					rpcFHdrBytes, _ := hex.DecodeString(rpcBF.Header)
					rpcFHdrNorm := hex.EncodeToString(reverseBytes(rpcFHdrBytes))
					res.fHdrMatchOK = (res.p2pFHdrHex == rpcFHdrNorm)
					res.rpcFHdrHex = rpcFHdrNorm
				}
			}
		}

		// -- GCS match --------------------------------------------------------
		if matchEnabled && len(targets) > 0 {
			hit, err := gcsMatchAny(blockHash, fb, targets)
			if err != nil {
				res.matchErr = err.Error()
			} else {
				res.matchHit = hit
				if hit {
					hitHeights = append(hitHeights, height)
				}
			}
		}

		// -- Neutrino cross-check ---------------------------------------------
		if *neutrinoF {
			res.neutrinoEnabled = true
			neutrinoHit, err := neutrinoMatchAny(blockHash, fb, targets, matchEnabled && len(targets) > 0)
			if err != nil {
				res.neutrinoErr = err.Error()
			} else {
				res.neutrinoDecodeOK = true
				res.neutrinoHit = neutrinoHit
				if matchEnabled && len(targets) > 0 {
					res.neutrinoMismatch = (neutrinoHit != res.matchHit)
				}
			}
		}

		res.print()

		if !res.allOK() {
			totalMismatches++
			log.Printf("  [%d] FAIL -- block %s", height, blockHashBE)
		}

		results[received] = res
		received++
	}

	// -- Summary --------------------------------------------------------------

	fmt.Println()
	log.Printf("================================================================")
	passed := expected - totalMismatches
	log.Printf("results: %d/%d passed", passed, expected)

	if *verify {
		hashFails, filterFails, fhdrFails := 0, 0, 0
		for _, r := range results {
			if !r.hashChainOK { hashFails++ }
			if !r.filterMatchOK { filterFails++ }
			if !r.fHdrMatchOK { fhdrFails++ }
		}
		if hashFails > 0 {
			log.Printf("  hash-chain failures  : %d", hashFails)
			log.Printf("  -> P2P filter bytes don't hash to cfheaders value")
		}
		if filterFails > 0 {
			log.Printf("  filter byte failures : %d", filterFails)
			log.Printf("  -> serving layer and index are inconsistent")
		}
		if fhdrFails > 0 {
			log.Printf("  fheader failures     : %d", fhdrFails)
			log.Printf("  -> filter header chain math mismatch")
		}
	}

	if *neutrinoF {
		neutrinoErrs, neutrinoMismatches := 0, 0
		for _, r := range results {
			if r.neutrinoErr != "" { neutrinoErrs++ }
			if r.neutrinoMismatch { neutrinoMismatches++ }
		}
		fmt.Println()
		log.Printf("-- neutrino cross-check summary ---------------------------------")
		log.Printf("  filters checked : %d", len(results))
		log.Printf("  decode errors   : %d", neutrinoErrs)
		log.Printf("  match mismatches: %d", neutrinoMismatches)
		if neutrinoErrs == 0 && neutrinoMismatches == 0 {
			log.Printf("  btcd/gcs and our GCS impl agree on all %d filters", len(results))
			log.Printf("  -> wire-compatible with neutrino/LND ecosystem")
		} else {
			if neutrinoErrs > 0 {
				log.Printf("  -> neutrino failed to decode some filters (encoding bug)")
			}
			if neutrinoMismatches > 0 {
				log.Printf("  -> our impl and neutrino disagree on match results")
				log.Printf("     this indicates a SipHash key or GCS parameter mismatch")
			}
		}
	}

	if matchEnabled {
		fmt.Println()
		log.Printf("-- match summary (%d target(s)) --------------------------------", len(targets))
		if len(hitHeights) == 0 {
			log.Printf("  no hits in heights %d-%d", *start, *end)
			log.Printf("  (this may be a false negative if the range doesn't cover the address activity)")
		} else {
			log.Printf("  HIT heights (%d blocks):", len(hitHeights))
			for _, h := range hitHeights {
				log.Printf("    %d", h)
			}

			if *matchBlock {
				fmt.Println()
				log.Printf("-- matchblock: fetching hit blocks for confirmation ---------------")
				targetHexSet := make(map[string]bool)
				for _, t := range targets {
					targetHexSet[hex.EncodeToString(t)] = true
				}

				for _, h := range hitHeights {
					hashStr, err := rpc.getBlockHashStr(h)
					if err != nil {
						log.Printf("  [%d] ERROR fetching block hash: %v", h, err)
						continue
					}
					block, err := rpc.getBlock(hashStr)
					if err != nil {
						log.Printf("  [%d] ERROR fetching block: %v", h, err)
						continue
					}
					log.Printf("  [%d] block %s — %d tx", h, hashStr, len(block.Tx))

					confirmed := false
					for _, tx := range block.Tx {
						for _, vout := range tx.Vout {
							spkHex := strings.ToLower(vout.ScriptPubKey.Hex)
							if targetHexSet[spkHex] {
								confirmed = true
								log.Printf("    CONFIRMED tx=%s vout=%d value=%.8f type=%s spk=%s",
									tx.Txid, vout.N, vout.Value,
									vout.ScriptPubKey.Type, spkHex)
							}
						}
					}
					if !confirmed {
						log.Printf("    FALSE POSITIVE -- no matching output found in block (filter fp rate ~1/784931)")
					}
				}
			} else {
				fmt.Println()
				log.Printf("  tip: re-run with -matchblock to fetch hit blocks and confirm outputs")
				log.Printf("  or manually: ./src/dogecoin-cli getblock $(./src/dogecoin-cli getblockhash %d) 2", hitHeights[0])
			}
		}
	}

	if totalMismatches > 0 {
		log.Printf("FAIL: %d mismatches", totalMismatches)
		os.Exit(1)
	}
	log.Printf("OK")
}
