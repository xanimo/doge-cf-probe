package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestSipHash24ReferenceVector uses the official test vector from the SipHash-2-4
// paper (Aumasson & Bernstein): key=000102...0f, msg=000102...0e (15 bytes) → 0xa129ca6149be45e5.
func TestSipHash24ReferenceVector(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	msg, _ := hex.DecodeString("000102030405060708090a0b0c0d0e")
	const want = uint64(0xa129ca6149be45e5)
	if got := sipHash24(key, msg); got != want {
		t.Errorf("sipHash24 = %016x, want %016x", got, want)
	}
}

func TestSipHash24Deterministic(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 16)
	msg := []byte("hello doge")
	if sipHash24(key, msg) != sipHash24(key, msg) {
		t.Error("not deterministic")
	}
}

func TestSipHash24KeySensitive(t *testing.T) {
	msg := []byte("same message")
	key1 := bytes.Repeat([]byte{0x00}, 16)
	key2 := bytes.Repeat([]byte{0xFF}, 16)
	if sipHash24(key1, msg) == sipHash24(key2, msg) {
		t.Error("different keys produced same hash (collision)")
	}
}

func TestSipHash24DataSensitive(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16)
	if sipHash24(key, []byte("a")) == sipHash24(key, []byte("b")) {
		t.Error("different messages produced same hash (collision)")
	}
}

func TestGcsHashKey(t *testing.T) {
	blockHashLE := make([]byte, 32)
	for i := range blockHashLE {
		blockHashLE[i] = byte(i)
	}
	key := gcsHashKey(blockHashLE)
	if len(key) != 16 {
		t.Fatalf("key length = %d, want 16", len(key))
	}
	if !bytes.Equal(key, blockHashLE[:16]) {
		t.Errorf("key = %x, want %x", key, blockHashLE[:16])
	}
}

func TestBitReaderWriterRoundtrip(t *testing.T) {
	bits := []uint64{1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1}
	var buf bytes.Buffer
	bw := newBitWriter(&buf)
	for _, b := range bits {
		bw.writeBit(b)
	}
	bw.flush()

	br := newBitReader(buf.Bytes())
	for i, want := range bits {
		got, err := br.readBit()
		if err != nil {
			t.Fatalf("readBit[%d]: %v", i, err)
		}
		if got != want {
			t.Errorf("bit[%d] = %d, want %d", i, got, want)
		}
	}
}

func TestBitReaderReadBits(t *testing.T) {
	// Write 0b10110011, read back as two 4-bit nibbles.
	var buf bytes.Buffer
	bw := newBitWriter(&buf)
	for _, b := range []uint64{1, 0, 1, 1, 0, 0, 1, 1} {
		bw.writeBit(b)
	}
	bw.flush()

	br := newBitReader(buf.Bytes())
	high, err := br.readBits(4)
	if err != nil {
		t.Fatal(err)
	}
	low, err := br.readBits(4)
	if err != nil {
		t.Fatal(err)
	}
	if high != 0b1011 {
		t.Errorf("high nibble = %04b, want 1011", high)
	}
	if low != 0b0011 {
		t.Errorf("low nibble = %04b, want 0011", low)
	}
}

func TestGolombDecodeRoundtrip(t *testing.T) {
	values := []uint64{0, 1, 5, 15, 100, 1000, (1 << 19) - 1}
	P := uint8(19)

	var buf bytes.Buffer
	bw := newBitWriter(&buf)
	for _, v := range values {
		q := v >> P
		for i := uint64(0); i < q; i++ {
			bw.writeBit(1)
		}
		bw.writeBit(0)
		r := v & ((1 << P) - 1)
		for i := int(P) - 1; i >= 0; i-- {
			bw.writeBit((r >> uint(i)) & 1)
		}
	}
	bw.flush()

	br := newBitReader(buf.Bytes())
	for i, want := range values {
		got, err := golombDecode(br, P)
		if err != nil {
			t.Fatalf("value[%d]: %v", i, err)
		}
		if got != want {
			t.Errorf("value[%d] = %d, want %d", i, got, want)
		}
	}
}

func TestGcsEncodeMatchAnyRoundtrip(t *testing.T) {
	blockHashLE := make([]byte, 32)
	blockHashLE[0] = 0xDE
	blockHashLE[1] = 0xAD

	items := [][]byte{
		{0x76, 0xa9, 0x14, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE},
		{0x76, 0xa9, 0x14, 0x11, 0x22, 0x33, 0x44, 0x55},
		{0xa9, 0x14, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAB},
	}

	encoded := gcsEncode(blockHashLE, items)
	if len(encoded) == 0 {
		t.Fatal("gcsEncode returned empty")
	}

	for i, item := range items {
		matched, err := gcsMatchAny(blockHashLE, encoded, [][]byte{item})
		if err != nil {
			t.Fatalf("item[%d] match error: %v", i, err)
		}
		if !matched {
			t.Errorf("item[%d] not found in its own filter", i)
		}
	}
}

func TestGcsEncodeDeduplication(t *testing.T) {
	blockHashLE := make([]byte, 32)
	item := []byte{0x01, 0x02, 0x03, 0x04}

	once := gcsEncode(blockHashLE, [][]byte{item})
	thrice := gcsEncode(blockHashLE, [][]byte{item, item, item})
	if !bytes.Equal(once, thrice) {
		t.Error("gcsEncode failed to deduplicate items: different filters for same unique set")
	}
}

func TestGcsMatchAnyEmptyFilterBytes(t *testing.T) {
	matched, err := gcsMatchAny(make([]byte, 32), nil, [][]byte{{0x01}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("nil filter should never match")
	}
}

func TestGcsMatchAnyZeroNFilter(t *testing.T) {
	bh := make([]byte, 32)
	emptyFilter := gcsEncode(bh, nil) // encodes N=0
	matched, err := gcsMatchAny(bh, emptyFilter, [][]byte{{0x01}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("zero-element filter should not match")
	}
}

func TestGcsMatchAnyNilTargets(t *testing.T) {
	bh := make([]byte, 32)
	filter := gcsEncode(bh, [][]byte{{0x01, 0x02}})
	matched, err := gcsMatchAny(bh, filter, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("nil targets should never match")
	}
}

func TestNeutrinoMatchAnyAgreesWithOwnDecoder(t *testing.T) {
	blockHashLE := make([]byte, 32)
	blockHashLE[5] = 0x42

	items := [][]byte{
		bytes.Repeat([]byte{0xAA}, 20),
		bytes.Repeat([]byte{0xBB}, 20),
		bytes.Repeat([]byte{0xCC}, 20),
	}

	filter := gcsEncode(blockHashLE, items)

	for i, item := range items {
		ours, err := gcsMatchAny(blockHashLE, filter, [][]byte{item})
		if err != nil {
			t.Fatalf("ours[%d]: %v", i, err)
		}
		theirs, err := neutrinoMatchAny(blockHashLE, filter, [][]byte{item}, true)
		if err != nil {
			t.Fatalf("neutrino[%d]: %v", i, err)
		}
		if ours != theirs {
			t.Errorf("item[%d]: ours=%v neutrino=%v — decoder disagreement", i, ours, theirs)
		}
	}
}

func TestNeutrinoMatchAnyEmptyFilter(t *testing.T) {
	matched, err := neutrinoMatchAny(make([]byte, 32), nil, [][]byte{{0x01}}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if matched {
		t.Error("nil filter should not match")
	}
}

func TestSortUint64s(t *testing.T) {
	cases := []struct {
		in   []uint64
		want []uint64
	}{
		{[]uint64{3, 1, 2}, []uint64{1, 2, 3}},
		{[]uint64{5}, []uint64{5}},
		{[]uint64{}, []uint64{}},
		{[]uint64{0, 0, 1}, []uint64{0, 0, 1}},
		{[]uint64{100, 50, 200, 25}, []uint64{25, 50, 100, 200}},
		{[]uint64{9, 8, 7, 6, 5, 4, 3, 2, 1, 0}, []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
	}
	for _, c := range cases {
		sortUint64s(c.in)
		for i, v := range c.in {
			if v != c.want[i] {
				t.Errorf("after sort: got %v, want %v", c.in, c.want)
				break
			}
		}
	}
}
