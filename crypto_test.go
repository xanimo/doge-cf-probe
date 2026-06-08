package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestDsha256KnownVector(t *testing.T) {
	// double-SHA256 of empty input: established Bitcoin/Dogecoin protocol constant
	got := dsha256(nil)
	want, _ := hex.DecodeString("5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456")
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}

func TestDsha256Length(t *testing.T) {
	if n := len(dsha256([]byte("test"))); n != 32 {
		t.Errorf("length = %d, want 32", n)
	}
}

func TestDsha256Deterministic(t *testing.T) {
	in := []byte("dogecoin")
	if !bytes.Equal(dsha256(in), dsha256(in)) {
		t.Error("not deterministic")
	}
}

func TestDsha256Distinct(t *testing.T) {
	if bytes.Equal(dsha256([]byte("a")), dsha256([]byte("b"))) {
		t.Error("collision on distinct inputs")
	}
}

func TestMsgChecksumMatchesDsha256Prefix(t *testing.T) {
	payload := []byte("test payload")
	cs := msgChecksum(payload)
	h := dsha256(payload)
	if !bytes.Equal(cs[:], h[:4]) {
		t.Errorf("got %x, want %x", cs[:], h[:4])
	}
}

func TestMsgChecksumNilDeterministic(t *testing.T) {
	cs1 := msgChecksum(nil)
	cs2 := msgChecksum(nil)
	if cs1 != cs2 {
		t.Error("non-deterministic for nil payload")
	}
}

func TestReverseBytes(t *testing.T) {
	cases := []struct{ in, want []byte }{
		{[]byte{1, 2, 3, 4}, []byte{4, 3, 2, 1}},
		{[]byte{0xAB, 0xCD}, []byte{0xCD, 0xAB}},
		{[]byte{42}, []byte{42}},
		{[]byte{}, []byte{}},
	}
	for _, c := range cases {
		original := append([]byte(nil), c.in...)
		got := reverseBytes(c.in)
		if !bytes.Equal(got, c.want) {
			t.Errorf("reverseBytes(%x) = %x, want %x", original, got, c.want)
		}
		if !bytes.Equal(c.in, original) {
			t.Errorf("reverseBytes mutated input: %x", c.in)
		}
	}
}

func TestDeriveFilterHeader(t *testing.T) {
	fHash := make([]byte, 32)
	fHash[0] = 0xAA
	prev := make([]byte, 32)
	prev[0] = 0xBB

	got := deriveFilterHeader(fHash, prev)
	want := dsha256(append(fHash, prev...))
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
	if len(got) != 32 {
		t.Errorf("length = %d, want 32", len(got))
	}
}

func TestDeriveFilterHeaderChain(t *testing.T) {
	// Verify that the header chain is deterministic and progressive.
	prev := make([]byte, 32)
	for i := 0; i < 5; i++ {
		fHash := dsha256([]byte{byte(i)})
		hdr := deriveFilterHeader(fHash, prev)
		if bytes.Equal(hdr, prev) {
			t.Errorf("header[%d] == prev (unexpected collision)", i)
		}
		prev = hdr
	}
}

func TestFilterHashFromBytes(t *testing.T) {
	data := []byte("BIP158 filter bytes")
	got := filterHashFromBytes(data)
	want := dsha256(data)
	if !bytes.Equal(got, want) {
		t.Errorf("got %x, want %x", got, want)
	}
}
