// qa_test.go exercises multi-component pipelines end-to-end without requiring
// a live Dogecoin node. These tests cross the boundaries between individual
// units to catch integration-level regressions.
package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

// TestFilterHashChainConsistency builds a sequence of filter headers using
// deriveFilterHeader and verifies the chain is deterministic and progressive.
func TestFilterHashChainConsistency(t *testing.T) {
	const chainLen = 10
	blockHashes := make([][]byte, chainLen)
	filterBytesSlice := make([][]byte, chainLen)
	for i := range blockHashes {
		bh := make([]byte, 32)
		bh[0] = byte(i + 1)
		blockHashes[i] = bh
		filterBytesSlice[i] = gcsEncode(bh, [][]byte{{byte(i), 0xAA, 0xBB}})
	}

	headers := make([][]byte, chainLen)
	prev := make([]byte, 32) // genesis prev header is all zeros
	for i := 0; i < chainLen; i++ {
		fhash := filterHashFromBytes(filterBytesSlice[i])
		headers[i] = deriveFilterHeader(fhash, prev)
		prev = headers[i]
	}

	// Each header must be distinct and 32 bytes.
	for i, h := range headers {
		if len(h) != 32 {
			t.Errorf("header[%d] length = %d, want 32", i, len(h))
		}
		for j := i + 1; j < chainLen; j++ {
			if bytes.Equal(h, headers[j]) {
				t.Errorf("headers[%d] == headers[%d]: duplicate in chain", i, j)
			}
		}
	}

	// Re-deriving from the same inputs must produce identical headers.
	prev = make([]byte, 32)
	for i := 0; i < chainLen; i++ {
		fhash := filterHashFromBytes(filterBytesSlice[i])
		got := deriveFilterHeader(fhash, prev)
		if !bytes.Equal(got, headers[i]) {
			t.Errorf("header[%d] not reproducible", i)
		}
		prev = got
	}
}

// TestEncodeStoreRetrieveMatchPipeline exercises the full path:
// GCS encode → store in DB → retrieve from DB → GCS match.
func TestEncodeStoreRetrieveMatchPipeline(t *testing.T) {
	dir := t.TempDir()
	db, err := openFilterDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.close()

	blockHashLE := make([]byte, 32)
	blockHashLE[0] = 0xDE
	blockHashLE[1] = 0xAD

	addrs := []string{
		makeAddr(addrVersionP2PKH, bytes.Repeat([]byte{0x11}, 20)),
		makeAddr(addrVersionP2SH, bytes.Repeat([]byte{0x22}, 20)),
	}
	var scriptPubKeys [][]byte
	for _, addr := range addrs {
		spk, err := addrToScriptPubKey(addr)
		if err != nil {
			t.Fatalf("addrToScriptPubKey: %v", err)
		}
		scriptPubKeys = append(scriptPubKeys, spk)
	}

	filterBytes := gcsEncode(blockHashLE, scriptPubKeys)
	fhash := filterHashFromBytes(filterBytes)
	fhdr := deriveFilterHeader(fhash, make([]byte, 32))

	entry := filterEntry{
		height:       100,
		blockHashLE:  blockHashLE,
		filterBytes:  filterBytes,
		filterHeader: fhdr,
	}
	if err := db.putBatch([]filterEntry{entry}); err != nil {
		t.Fatal(err)
	}

	stored := db.getFilterBytes(100)
	if !bytes.Equal(stored, filterBytes) {
		t.Fatal("stored filter bytes do not match original")
	}
	storedHeader := db.getFilterHeader(100)
	if !bytes.Equal(storedHeader, fhdr) {
		t.Fatal("stored filter header does not match original")
	}

	for i, spk := range scriptPubKeys {
		matched, err := gcsMatchAny(blockHashLE, stored, [][]byte{spk})
		if err != nil {
			t.Fatalf("spk[%d] match error: %v", i, err)
		}
		if !matched {
			t.Errorf("spk[%d] not found in retrieved filter", i)
		}
	}
}

// TestOurDecoderVsNeutrinoOnStoredFilter stores a GCS filter in the DB, retrieves
// it, and verifies that our decoder and btcd/neutrino agree on every target.
func TestOurDecoderVsNeutrinoOnStoredFilter(t *testing.T) {
	dir := t.TempDir()
	db, err := openFilterDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.close()

	blockHashLE := dsha256([]byte("test block hash"))

	items := [][]byte{
		bytes.Repeat([]byte{0xCA}, 25),
		bytes.Repeat([]byte{0xFE}, 25),
		bytes.Repeat([]byte{0xBA}, 25),
		bytes.Repeat([]byte{0xBE}, 25),
	}
	fb := gcsEncode(blockHashLE, items)
	db.putBatch([]filterEntry{{
		height:       1,
		blockHashLE:  blockHashLE,
		filterBytes:  fb,
		filterHeader: deriveFilterHeader(filterHashFromBytes(fb), make([]byte, 32)),
	}})

	stored := db.getFilterBytes(1)
	for i, item := range items {
		ours, err := gcsMatchAny(blockHashLE, stored, [][]byte{item})
		if err != nil {
			t.Fatalf("ours[%d]: %v", i, err)
		}
		theirs, err := neutrinoMatchAny(blockHashLE, stored, [][]byte{item}, true)
		if err != nil {
			t.Fatalf("neutrino[%d]: %v", i, err)
		}
		if ours != theirs {
			t.Errorf("item[%d]: ours=%v neutrino=%v — decoder mismatch on stored filter", i, ours, theirs)
		}
		if !ours {
			t.Errorf("item[%d]: not found in its own stored filter", i)
		}
	}
}

// TestWireRoundtripWithRealFilter builds a cfilter message with a real GCS
// payload, parses the wire bytes, and verifies the decoded filter still matches
// the original scriptPubKeys.
func TestWireRoundtripWithRealFilter(t *testing.T) {
	blockHashLE := make([]byte, 32)
	blockHashLE[3] = 0x42

	spks := [][]byte{
		bytes.Repeat([]byte{0xDE}, 20),
		bytes.Repeat([]byte{0xAD}, 20),
	}
	filterBytes := gcsEncode(blockHashLE, spks)

	var payload bytes.Buffer
	payload.Write(blockHashLE)
	payload.WriteByte(filterTypeBasic)
	writeCompactSize(&payload, uint64(len(filterBytes)))
	payload.Write(filterBytes)

	magic := magicByNet["mainnet"]
	msg := buildMsg(magic, cmdCFilter, payload.Bytes())

	ft, gotHash, gotFilter, err := parseCFilter(msg[headerSize:]) // strip 24-byte header
	if err != nil {
		t.Fatalf("parseCFilter: %v", err)
	}
	if ft != filterTypeBasic {
		t.Errorf("filter type = %d, want %d", ft, filterTypeBasic)
	}
	if !bytes.Equal(gotHash, blockHashLE) {
		t.Error("block hash mismatch")
	}

	for i, spk := range spks {
		matched, err := gcsMatchAny(gotHash, gotFilter, [][]byte{spk})
		if err != nil {
			t.Fatalf("spk[%d]: %v", i, err)
		}
		if !matched {
			t.Errorf("spk[%d] not found after wire roundtrip", i)
		}
	}
}

// TestDBRefServesStaleAndFreshData verifies that reload() successfully swaps the
// underlying db connection and the new handle remains consistent. Writing while
// a read-only handle is open is not tested here because bbolt's LOCK_EX and
// LOCK_SH are mutually exclusive within the same process on Linux.
func TestDBRefServesStaleAndFreshData(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "serve.db")

	// Write all blocks before creating the read-only dbRef.
	rw, err := openFilterDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var batch []filterEntry
	for h := 1; h <= 5; h++ {
		batch = append(batch, makeTestEntry(h, byte(h), byte(h), byte(h)))
	}
	rw.putBatch(batch)
	rw.close()

	ro, err := openFilterDBReadOnly(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ref := newDBRef(ro, dbPath)
	defer func() { ref.get().close() }()

	if ref.get().tip() != 5 {
		t.Fatalf("initial tip = %d, want 5", ref.get().tip())
	}

	// reload() opens a new LOCK_SH (compatible with the existing one), replaces
	// the pointer, and closes the old handle.
	ref.reload()

	if ref.get().tip() != 5 {
		t.Errorf("tip after reload = %d, want 5", ref.get().tip())
	}
}
