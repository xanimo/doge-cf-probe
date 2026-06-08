package main

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestCompactSizeRoundtrip(t *testing.T) {
	cases := []uint64{0, 1, 0xfc, 0xfd, 0xffff, 0x10000, 0xffffffff, 0x100000000}
	for _, v := range cases {
		var buf bytes.Buffer
		writeCompactSize(&buf, v)
		got, err := readCompactSize(&buf)
		if err != nil {
			t.Fatalf("readCompactSize(%d): %v", v, err)
		}
		if got != v {
			t.Errorf("roundtrip(%d) = %d", v, got)
		}
	}
}

func TestCompactSizeEncoding(t *testing.T) {
	cases := []struct {
		n         uint64
		firstByte byte
		totalLen  int
	}{
		{0, 0x00, 1},
		{0xfc, 0xfc, 1},    // max single-byte value
		{0xfd, 0xfd, 3},    // fd prefix + uint16 LE
		{0xffff, 0xfd, 3},
		{0x10000, 0xfe, 5}, // fe prefix + uint32 LE
		{0x100000000, 0xff, 9}, // ff prefix + uint64 LE
	}
	for _, c := range cases {
		var buf bytes.Buffer
		writeCompactSize(&buf, c.n)
		b := buf.Bytes()
		if b[0] != c.firstByte {
			t.Errorf("n=%d: first byte = %02x, want %02x", c.n, b[0], c.firstByte)
		}
		if len(b) != c.totalLen {
			t.Errorf("n=%d: encoded length = %d, want %d", c.n, len(b), c.totalLen)
		}
	}
}

func TestBuildMsgReadMsgRoundtrip(t *testing.T) {
	magic := magicByNet["regtest"]
	cases := []struct {
		cmd     string
		payload []byte
	}{
		{cmdVerack, nil},
		{cmdVersion, []byte("version payload data")},
		{cmdGetCFHdrs, make([]byte, 37)},
		{cmdCFHdrs, bytes.Repeat([]byte{0xAB}, 100)},
	}

	for _, c := range cases {
		server, client := net.Pipe()
		go func(cmd string, payload []byte) {
			defer server.Close()
			server.Write(buildMsg(magic, cmd, payload))
		}(c.cmd, c.payload)

		cmd, payload, err := readMsg(client, magic)
		client.Close()
		if err != nil {
			t.Fatalf("cmd=%q: readMsg: %v", c.cmd, err)
		}
		if cmd != c.cmd {
			t.Errorf("cmd: got %q, want %q", cmd, c.cmd)
		}
		if !bytes.Equal(payload, c.payload) {
			t.Errorf("cmd=%q: payload mismatch (len got=%d want=%d)", c.cmd, len(payload), len(c.payload))
		}
	}
}

func TestReadMsgMagicMismatch(t *testing.T) {
	mainnet := magicByNet["mainnet"]
	testnet := magicByNet["testnet"]

	server, client := net.Pipe()
	go func() {
		defer server.Close()
		server.Write(buildMsg(testnet, cmdVerack, nil))
	}()

	_, _, err := readMsg(client, mainnet)
	client.Close()
	if err == nil {
		t.Error("expected magic mismatch error")
	}
}

func TestReadMsgChecksumMismatch(t *testing.T) {
	magic := magicByNet["regtest"]
	msg := buildMsg(magic, cmdVersion, []byte("payload"))
	// Corrupt one byte of the checksum (bytes 20-23 in the 24-byte header).
	msg[20] ^= 0xFF

	server, client := net.Pipe()
	go func() {
		defer server.Close()
		server.Write(msg)
	}()

	_, _, err := readMsg(client, magic)
	client.Close()
	if err == nil {
		t.Error("expected checksum mismatch error")
	}
}

func TestBuildGetCFHeaders(t *testing.T) {
	startHeight := uint32(12345)
	stopHash := make([]byte, 32)
	stopHash[0] = 0xAB
	stopHash[31] = 0xCD

	payload := buildGetCFHeaders(startHeight, stopHash)

	// 1 (filter_type) + 4 (start_height LE) + 32 (stop_hash) = 37 bytes
	if len(payload) != 37 {
		t.Fatalf("length = %d, want 37", len(payload))
	}
	if payload[0] != filterTypeBasic {
		t.Errorf("filter type = %d, want %d", payload[0], filterTypeBasic)
	}
	if h := binary.LittleEndian.Uint32(payload[1:5]); h != startHeight {
		t.Errorf("start height = %d, want %d", h, startHeight)
	}
	if !bytes.Equal(payload[5:37], stopHash) {
		t.Errorf("stop hash mismatch")
	}
}

func TestBuildGetCFilters(t *testing.T) {
	startHeight := uint32(500)
	stopHash := make([]byte, 32)
	stopHash[0] = 0xFF

	payload := buildGetCFilters(startHeight, stopHash)

	if len(payload) != 37 {
		t.Fatalf("length = %d, want 37", len(payload))
	}
	if payload[0] != filterTypeBasic {
		t.Errorf("filter type = %d, want %d", payload[0], filterTypeBasic)
	}
	if h := binary.LittleEndian.Uint32(payload[1:5]); h != startHeight {
		t.Errorf("start height = %d, want %d", h, startHeight)
	}
	if !bytes.Equal(payload[5:37], stopHash) {
		t.Errorf("stop hash mismatch")
	}
}

func TestParseCFilter(t *testing.T) {
	blockHash := make([]byte, 32)
	blockHash[0] = 0xAA
	filterData := []byte{0x01, 0x02, 0x03, 0x04}

	var payload bytes.Buffer
	payload.Write(blockHash)
	payload.WriteByte(filterTypeBasic)
	writeCompactSize(&payload, uint64(len(filterData)))
	payload.Write(filterData)

	ft, gotHash, gotFilter, err := parseCFilter(payload.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ft != filterTypeBasic {
		t.Errorf("filter type = %d, want %d", ft, filterTypeBasic)
	}
	if !bytes.Equal(gotHash, blockHash) {
		t.Errorf("block hash = %x, want %x", gotHash, blockHash)
	}
	if !bytes.Equal(gotFilter, filterData) {
		t.Errorf("filter data = %x, want %x", gotFilter, filterData)
	}
}

func TestParseCFilterTooShort(t *testing.T) {
	_, _, _, err := parseCFilter(make([]byte, 10))
	if err == nil {
		t.Error("expected error for too-short payload")
	}
}

func TestParseCFilterEmptyFilterData(t *testing.T) {
	blockHash := make([]byte, 32)
	var payload bytes.Buffer
	payload.Write(blockHash)
	payload.WriteByte(filterTypeBasic)
	writeCompactSize(&payload, 0) // zero-length filter

	ft, gotHash, gotFilter, err := parseCFilter(payload.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ft != filterTypeBasic {
		t.Errorf("filter type = %d, want %d", ft, filterTypeBasic)
	}
	if !bytes.Equal(gotHash, blockHash) {
		t.Error("block hash mismatch")
	}
	if len(gotFilter) != 0 {
		t.Errorf("filter data length = %d, want 0", len(gotFilter))
	}
}

func TestParseCFHeaders(t *testing.T) {
	stopHash := bytes.Repeat([]byte{0xAA}, 32)
	prevHeader := bytes.Repeat([]byte{0xBB}, 32)
	hashes := [][]byte{
		bytes.Repeat([]byte{0x01}, 32),
		bytes.Repeat([]byte{0x02}, 32),
		bytes.Repeat([]byte{0x03}, 32),
	}

	var payload bytes.Buffer
	payload.WriteByte(filterTypeBasic)
	payload.Write(stopHash)
	payload.Write(prevHeader)
	writeCompactSize(&payload, uint64(len(hashes)))
	for _, h := range hashes {
		payload.Write(h)
	}

	ft, gotStop, gotPrev, gotHashes, err := parseCFHeaders(payload.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ft != filterTypeBasic {
		t.Errorf("filter type = %d, want %d", ft, filterTypeBasic)
	}
	if !bytes.Equal(gotStop, stopHash) {
		t.Error("stop hash mismatch")
	}
	if !bytes.Equal(gotPrev, prevHeader) {
		t.Error("prev header mismatch")
	}
	if len(gotHashes) != len(hashes) {
		t.Fatalf("hash count = %d, want %d", len(gotHashes), len(hashes))
	}
	for i, h := range hashes {
		if !bytes.Equal(gotHashes[i], h) {
			t.Errorf("hash[%d] mismatch", i)
		}
	}
}

func TestParseCFHeadersTooShort(t *testing.T) {
	_, _, _, _, err := parseCFHeaders(make([]byte, 10))
	if err == nil {
		t.Error("expected error for too-short payload")
	}
}
