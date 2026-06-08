package main

import (
	"bytes"
	"path/filepath"
	"testing"
)

func makeTestEntry(height int, hashSeed, filterSeed, headerSeed byte) filterEntry {
	bh := make([]byte, 32)
	bh[0] = hashSeed
	bh[1] = byte(height >> 8)
	bh[2] = byte(height)
	return filterEntry{
		height:       height,
		blockHashLE:  bh,
		filterBytes:  []byte{filterSeed, byte(height)},
		filterHeader: bytes.Repeat([]byte{headerSeed}, 32),
	}
}

func TestFilterDBOpenClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := openFilterDB(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	db.close()
}

func TestFilterDBTipEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := openFilterDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.close()
	if tip := db.tip(); tip != -1 {
		t.Errorf("tip of empty db = %d, want -1", tip)
	}
}

func TestFilterDBPutBatchAndLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := openFilterDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.close()

	entries := []filterEntry{
		makeTestEntry(1, 0x01, 0xAA, 0x11),
		makeTestEntry(2, 0x02, 0xBB, 0x22),
		makeTestEntry(3, 0x03, 0xCC, 0x33),
	}
	if err := db.putBatch(entries); err != nil {
		t.Fatalf("putBatch: %v", err)
	}
	if tip := db.tip(); tip != 3 {
		t.Errorf("tip = %d, want 3", tip)
	}

	for _, e := range entries {
		fb := db.getFilterBytes(e.height)
		if !bytes.Equal(fb, e.filterBytes) {
			t.Errorf("height %d: filterBytes = %x, want %x", e.height, fb, e.filterBytes)
		}
		fh := db.getFilterHeader(e.height)
		if !bytes.Equal(fh, e.filterHeader) {
			t.Errorf("height %d: filterHeader mismatch", e.height)
		}
		bh := db.getBlockHashLE(e.height)
		if !bytes.Equal(bh, e.blockHashLE) {
			t.Errorf("height %d: blockHashLE mismatch", e.height)
		}
		h, ok := db.heightForHash(e.blockHashLE)
		if !ok {
			t.Errorf("height %d: heightForHash returned not-found", e.height)
		}
		if h != e.height {
			t.Errorf("heightForHash = %d, want %d", h, e.height)
		}
	}
}

func TestFilterDBMissingHeight(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := openFilterDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.close()

	if v := db.getFilterBytes(99); v != nil {
		t.Errorf("expected nil for missing height, got %x", v)
	}
	if v := db.getFilterHeader(99); v != nil {
		t.Errorf("expected nil for missing header, got %x", v)
	}
	if v := db.getBlockHashLE(99); v != nil {
		t.Errorf("expected nil for missing block hash, got %x", v)
	}
	_, ok := db.heightForHash(make([]byte, 32))
	if ok {
		t.Error("expected not-found for unknown hash")
	}
}

func TestFilterDBTipAdvancesWithBatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := openFilterDB(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.close()

	for h := 1; h <= 5; h++ {
		if err := db.putBatch([]filterEntry{makeTestEntry(h, byte(h), byte(h), byte(h))}); err != nil {
			t.Fatalf("putBatch(%d): %v", h, err)
		}
		if tip := db.tip(); tip != h {
			t.Errorf("after height %d: tip = %d, want %d", h, tip, h)
		}
	}
}

func TestFilterDBHeightKeyOrdering(t *testing.T) {
	// Verify that big-endian height keys sort correctly for bbolt range scans.
	cases := []struct{ h int }{
		{0}, {1}, {255}, {256}, {65535}, {65536},
	}
	for _, c := range cases {
		k := heightKey(c.h)
		if len(k) != 4 {
			t.Errorf("heightKey(%d) length = %d, want 4", c.h, len(k))
		}
	}
	// Higher height must produce lexicographically greater key.
	k1 := heightKey(100)
	k2 := heightKey(200)
	if bytes.Compare(k1, k2) >= 0 {
		t.Error("heightKey(100) >= heightKey(200): wrong ordering")
	}
}

func TestFilterDBOpenReadOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	rw, err := openFilterDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := rw.putBatch([]filterEntry{makeTestEntry(1, 0xAA, 0x01, 0x01)}); err != nil {
		t.Fatal(err)
	}
	rw.close()

	ro, err := openFilterDBReadOnly(path)
	if err != nil {
		t.Fatalf("openReadOnly: %v", err)
	}
	defer ro.close()

	if tip := ro.tip(); tip != 1 {
		t.Errorf("read-only tip = %d, want 1", tip)
	}
}

func TestDBRefGetAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	// Write all data before opening any read-only connection: bbolt's LOCK_EX
	// and LOCK_SH are mutually exclusive, so read-write and read-only handles
	// cannot be open simultaneously from the same process.
	rw, err := openFilterDB(path)
	if err != nil {
		t.Fatal(err)
	}
	rw.putBatch([]filterEntry{makeTestEntry(1, 0x01, 0xAA, 0x11)})
	rw.putBatch([]filterEntry{makeTestEntry(2, 0x02, 0xBB, 0x22)})
	rw.close()

	ro, err := openFilterDBReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	ref := newDBRef(ro, path)
	defer func() { ref.get().close() }()

	if tip := ref.get().tip(); tip != 2 {
		t.Errorf("initial tip = %d, want 2", tip)
	}

	// reload() opens a second LOCK_SH (compatible with the existing one), swaps
	// the db pointer, and closes the old connection.
	ref.reload()

	if tip := ref.get().tip(); tip != 2 {
		t.Errorf("tip after reload = %d, want 2", tip)
	}
}

func TestDBRefGetConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	rw, err := openFilterDB(path)
	if err != nil {
		t.Fatal(err)
	}
	rw.putBatch([]filterEntry{makeTestEntry(1, 0x01, 0x01, 0x01)})
	rw.close()

	ro, err := openFilterDBReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	ref := newDBRef(ro, path)
	defer func() { ref.get().close() }()

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			db := ref.get()
			if db == nil {
				t.Error("get() returned nil")
			}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}
