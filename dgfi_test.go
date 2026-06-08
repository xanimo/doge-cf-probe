package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteBitcoinVarInt(t *testing.T) {
	cases := []struct {
		n    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{127, []byte{0x7f}},
		{128, []byte{0x80, 0x00}},
		{255, []byte{0xff, 0x00}},
		{16383, []byte{0xff, 0x7e}},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		writeBitcoinVarInt(&buf, c.n)
		if !bytes.Equal(buf.Bytes(), c.want) {
			t.Errorf("writeBitcoinVarInt(%d) = %x, want %x", c.n, buf.Bytes(), c.want)
		}
	}
}

func TestCoreDBVal(t *testing.T) {
	bh := bytes.Repeat([]byte{0xAA}, 32)
	fh := bytes.Repeat([]byte{0xBB}, 32)
	fhdr := bytes.Repeat([]byte{0xCC}, 32)

	val := coreDBVal(bh, fh, fhdr, 0, 100)
	if len(val) < 96 {
		t.Fatalf("length = %d, want >= 96", len(val))
	}
	if !bytes.Equal(val[:32], bh) {
		t.Error("block hash mismatch in coreDBVal")
	}
	if !bytes.Equal(val[32:64], fh) {
		t.Error("filter hash mismatch in coreDBVal")
	}
	if !bytes.Equal(val[64:96], fhdr) {
		t.Error("filter header mismatch in coreDBVal")
	}
	// Two distinct nFile values must produce distinct values.
	val2 := coreDBVal(bh, fh, fhdr, 1, 100)
	if bytes.Equal(val, val2) {
		t.Error("nFile=0 and nFile=1 produced identical coreDBVal")
	}
}

func makeDumpEntries(n int) []filterEntry {
	entries := make([]filterEntry, n)
	prev := make([]byte, 32)
	for h := 0; h < n; h++ {
		bh := make([]byte, 32)
		bh[0] = byte(h + 1)
		bh[1] = byte((h + 1) >> 8)
		fb := gcsEncode(bh, [][]byte{{byte(h), 0xFF}})
		fhash := filterHashFromBytes(fb)
		fhdr := deriveFilterHeader(fhash, prev)
		entries[h] = filterEntry{
			height:       h,
			blockHashLE:  bh,
			filterBytes:  fb,
			filterHeader: fhdr,
		}
		prev = fhdr
	}
	return entries
}

func TestDumpFilterIndexHeader(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "filters.db")
	dumpPath := filepath.Join(dir, "filters.dgfi")

	db, err := openFilterDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.putBatch(makeDumpEntries(4)); err != nil {
		t.Fatal(err)
	}
	if err := dumpFilterIndex(db, dumpPath); err != nil {
		t.Fatal(err)
	}
	db.close()

	data, err := os.ReadFile(dumpPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data[:4]) != dumpMagic {
		t.Errorf("magic = %q, want %q", data[:4], dumpMagic)
	}
	if data[4] != dumpVersion {
		t.Errorf("version = %d, want %d", data[4], dumpVersion)
	}
	tip := binary.LittleEndian.Uint32(data[5:9])
	if tip != 3 { // heights 0..3 → tip = 3
		t.Errorf("tip in header = %d, want 3", tip)
	}
}

func TestDumpFilterIndexFirstEntry(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "filters.db")
	dumpPath := filepath.Join(dir, "filters.dgfi")

	entries := makeDumpEntries(2)
	db, err := openFilterDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.putBatch(entries); err != nil {
		t.Fatal(err)
	}
	if err := dumpFilterIndex(db, dumpPath); err != nil {
		t.Fatal(err)
	}
	db.close()

	f, err := os.Open(dumpPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// Skip 9-byte header (4 magic + 1 version + 4 tip).
	f.Seek(9, io.SeekStart)

	blockHash := make([]byte, 32)
	io.ReadFull(f, blockHash)
	if !bytes.Equal(blockHash, entries[0].blockHashLE) {
		t.Errorf("block hash = %x, want %x", blockHash, entries[0].blockHashLE)
	}

	filterHash := make([]byte, 32)
	io.ReadFull(f, filterHash)
	if !bytes.Equal(filterHash, filterHashFromBytes(entries[0].filterBytes)) {
		t.Error("filter hash mismatch in first DGFI entry")
	}

	filterHeader := make([]byte, 32)
	io.ReadFull(f, filterHeader)
	if !bytes.Equal(filterHeader, entries[0].filterHeader) {
		t.Error("filter header mismatch in first DGFI entry")
	}

	// compact_size + filter bytes
	n, _ := readCompactSize(f)
	fb := make([]byte, n)
	io.ReadFull(f, fb)
	if !bytes.Equal(fb, entries[0].filterBytes) {
		t.Errorf("filter bytes = %x, want %x", fb, entries[0].filterBytes)
	}
}

func TestDumpFilterIndexEmptyDB(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "filters.db")

	db, err := openFilterDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.close()

	err = dumpFilterIndex(db, filepath.Join(dir, "out.dgfi"))
	if err == nil {
		t.Error("expected error when dumping empty database")
	}
}
