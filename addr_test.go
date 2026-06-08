package main

import (
	"bytes"
	"math/big"
	"testing"
)

// base58Encode is a test-only helper (production code only decodes).
func base58Encode(b []byte) string {
	n := new(big.Int).SetBytes(b)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var result []byte
	for n.Cmp(zero) > 0 {
		n.DivMod(n, base, mod)
		result = append(result, base58Alphabet[mod.Int64()])
	}
	for _, v := range b {
		if v != 0 {
			break
		}
		result = append(result, '1')
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return string(result)
}

// makeAddr builds a base58check address from a version byte and 20-byte hash160.
func makeAddr(version byte, hash160 []byte) string {
	payload := append([]byte{version}, hash160...)
	cs := dsha256(payload)
	return base58Encode(append(payload, cs[:4]...))
}

func TestBase58DecodeLeadingZeros(t *testing.T) {
	got, err := base58Decode("111")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) < 3 {
		t.Fatalf("length = %d, want >= 3", len(got))
	}
	for i := 0; i < 3; i++ {
		if got[i] != 0 {
			t.Errorf("byte[%d] = %x, want 0x00", i, got[i])
		}
	}
}

func TestBase58DecodeInvalidChars(t *testing.T) {
	for _, bad := range []string{"0abc", "Oabc", "Iabc", "labc"} {
		if _, err := base58Decode(bad); err == nil {
			t.Errorf("expected error for %q (contains invalid base58 char)", bad)
		}
	}
}

func TestBase58CheckDecodeTooShort(t *testing.T) {
	_, err := base58CheckDecode("1234") // < 5 decoded bytes
	if err == nil {
		t.Error("expected error for too-short input")
	}
}

func TestBase58CheckDecodeChecksumMismatch(t *testing.T) {
	hash160 := bytes.Repeat([]byte{0xAB}, 20)
	payload := append([]byte{addrVersionP2PKH}, hash160...)
	// Use 0xFF bytes as checksum instead of the correct hash.
	bogus := base58Encode(append(payload, 0xFF, 0xFF, 0xFF, 0xFF))
	_, err := base58CheckDecode(bogus)
	if err == nil {
		t.Error("expected checksum mismatch error")
	}
}

func TestAddrToScriptPubKeyP2PKH(t *testing.T) {
	hash160 := bytes.Repeat([]byte{0xAB}, 20)
	addr := makeAddr(addrVersionP2PKH, hash160)

	spk, err := addrToScriptPubKey(addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spk) != 25 {
		t.Fatalf("length = %d, want 25", len(spk))
	}
	// OP_DUP OP_HASH160 <push 20> hash160 OP_EQUALVERIFY OP_CHECKSIG
	if spk[0] != 0x76 || spk[1] != 0xa9 || spk[2] != 0x14 {
		t.Errorf("P2PKH prefix = %x, want 76 a9 14", spk[:3])
	}
	if !bytes.Equal(spk[3:23], hash160) {
		t.Errorf("hash160 = %x, want %x", spk[3:23], hash160)
	}
	if spk[23] != 0x88 || spk[24] != 0xac {
		t.Errorf("P2PKH suffix = %x, want 88 ac", spk[23:])
	}
}

func TestAddrToScriptPubKeyP2SH(t *testing.T) {
	hash160 := bytes.Repeat([]byte{0xCD}, 20)
	addr := makeAddr(addrVersionP2SH, hash160)

	spk, err := addrToScriptPubKey(addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spk) != 23 {
		t.Fatalf("length = %d, want 23", len(spk))
	}
	// OP_HASH160 <push 20> hash160 OP_EQUAL
	if spk[0] != 0xa9 || spk[1] != 0x14 {
		t.Errorf("P2SH prefix = %x, want a9 14", spk[:2])
	}
	if !bytes.Equal(spk[2:22], hash160) {
		t.Errorf("hash160 = %x, want %x", spk[2:22], hash160)
	}
	if spk[22] != 0x87 {
		t.Errorf("P2SH suffix = %x, want 87", spk[22])
	}
}

func TestAddrToScriptPubKeyTestnetP2PKH(t *testing.T) {
	hash160 := bytes.Repeat([]byte{0xEF}, 20)
	addr := makeAddr(addrVersionTestnetP2PKH, hash160)

	spk, err := addrToScriptPubKey(addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spk) != 25 {
		t.Fatalf("length = %d, want 25", len(spk))
	}
	if !bytes.Equal(spk[3:23], hash160) {
		t.Errorf("hash160 mismatch: %x", spk[3:23])
	}
}

func TestAddrToScriptPubKeyTestnetP2SH(t *testing.T) {
	hash160 := bytes.Repeat([]byte{0x11}, 20)
	addr := makeAddr(addrVersionTestnetP2SH, hash160)

	spk, err := addrToScriptPubKey(addr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spk) != 23 {
		t.Fatalf("length = %d, want 23", len(spk))
	}
	if !bytes.Equal(spk[2:22], hash160) {
		t.Errorf("hash160 mismatch: %x", spk[2:22])
	}
}

func TestAddrToScriptPubKeyUnknownVersion(t *testing.T) {
	addr := makeAddr(0xFF, bytes.Repeat([]byte{0x00}, 20))
	_, err := addrToScriptPubKey(addr)
	if err == nil {
		t.Error("expected error for unknown version byte 0xFF")
	}
}

func TestAddrToScriptPubKeyInvalidInput(t *testing.T) {
	_, err := addrToScriptPubKey("not-an-address")
	if err == nil {
		t.Error("expected error for garbage input")
	}
}

// TestAddrToScriptPubKeyKnownMainnet checks the well-known address from the README.
func TestAddrToScriptPubKeyKnownMainnet(t *testing.T) {
	spk, err := addrToScriptPubKey("DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(spk) != 25 {
		t.Fatalf("length = %d, want 25", len(spk))
	}
	if spk[0] != 0x76 || spk[1] != 0xa9 || spk[2] != 0x14 || spk[23] != 0x88 || spk[24] != 0xac {
		t.Errorf("not a valid P2PKH script: %x", spk)
	}
}
