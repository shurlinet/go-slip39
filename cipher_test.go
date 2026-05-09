// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

package slip39

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// TestFeistelRoundTrip verifies encrypt then decrypt recovers the original
// for various secret sizes and parameters.
func TestFeistelRoundTrip(t *testing.T) {
	testCases := []struct {
		name      string
		secret    string // hex
		pass      string
		iterExp   int
		id        int
		extendable bool
	}{
		{"128-bit", "bb54aac4b89dc868ba37d9cc21b2cece", "TREZOR", 0, 7945, false},
		{"256-bit", "bb54aac4b89dc868ba37d9cc21b2cecebb54aac4b89dc868ba37d9cc21b2cece", "TREZOR", 0, 7945, false},
		{"128-bit ext", "bb54aac4b89dc868ba37d9cc21b2cece", "TREZOR", 0, 7945, true},
		{"128-bit e=1", "bb54aac4b89dc868ba37d9cc21b2cece", "TREZOR", 1, 7945, false},
		{"128-bit empty pass", "bb54aac4b89dc868ba37d9cc21b2cece", "", 0, 7945, false},
		{"128-bit id=0", "bb54aac4b89dc868ba37d9cc21b2cece", "TREZOR", 0, 0, false},
		{"all zeros 128", "00000000000000000000000000000000", "TREZOR", 0, 7945, false},
		{"all FF 128", "ffffffffffffffffffffffffffffffff", "TREZOR", 0, 7945, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			secret, err := hex.DecodeString(tc.secret)
			if err != nil {
				t.Fatal(err)
			}
			enc := encrypt(secret, []byte(tc.pass), tc.iterExp, tc.id, tc.extendable)
			dec := decrypt(enc, []byte(tc.pass), tc.iterExp, tc.id, tc.extendable)
			if !bytes.Equal(dec, secret) {
				t.Fatalf("round-trip failed:\n  got:  %x\n  want: %x", dec, secret)
			}
			ZeroBytes(enc)
			ZeroBytes(dec)
		})
	}
}

// TestFeistelPreservesLength verifies len(encrypt(s)) == len(s) (F53).
func TestFeistelPreservesLength(t *testing.T) {
	for _, n := range []int{16, 18, 20, 24, 32, 48, 64} {
		secret := make([]byte, n)
		for i := range secret {
			secret[i] = byte(i)
		}
		enc := encrypt(secret, []byte("TREZOR"), 0, 7945, false)
		if len(enc) != n {
			t.Fatalf("encrypt(%d bytes) returned %d bytes", n, len(enc))
		}
		ZeroBytes(enc)
	}
}

// TestFeistelPythonVectors verifies against Python-generated intermediate vectors (F195).
// Generated from trezor/python-shamir-mnemonic.
func TestFeistelPythonVectors(t *testing.T) {
	vectors := []struct {
		name       string
		plaintext  string
		passphrase string
		iterExp    int
		id         int
		extendable bool
		ciphertext string
	}{
		{
			"V1: 128-bit e=0 id=7945 ext=false",
			"bb54aac4b89dc868ba37d9cc21b2cece",
			"TREZOR", 0, 7945, false,
			"11bc609d21747c49ba78c0701293e417",
		},
		{
			"V2: 256-bit e=0 id=7945 ext=false",
			"bb54aac4b89dc868ba37d9cc21b2cecebb54aac4b89dc868ba37d9cc21b2cece",
			"TREZOR", 0, 7945, false,
			"bb55f4da1ca8a768605a379439c08827e02c5c8b3c99c4a1dbd2a3a1f30e0880",
		},
		{
			"V3: 128-bit e=0 id=7945 ext=true",
			"bb54aac4b89dc868ba37d9cc21b2cece",
			"TREZOR", 0, 7945, true,
			"4ed5aafca6faf2cbf90519a4d6f41191",
		},
		{
			"V4: 128-bit e=1 id=7945 ext=false",
			"bb54aac4b89dc868ba37d9cc21b2cece",
			"TREZOR", 1, 7945, false,
			"0399f6fbffcaab71479d89c53fb416a3",
		},
		{
			"V5: 128-bit empty passphrase",
			"bb54aac4b89dc868ba37d9cc21b2cece",
			"", 0, 7945, false,
			"d0815038ea5f892f45ca1591a669e8f9",
		},
		{
			"V6: 128-bit id=0",
			"bb54aac4b89dc868ba37d9cc21b2cece",
			"TREZOR", 0, 0, false,
			"2c7ce65b815b774dee4aad05877a016c",
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			plaintext, _ := hex.DecodeString(v.plaintext)
			expectedCT, _ := hex.DecodeString(v.ciphertext)

			ct := encrypt(plaintext, []byte(v.passphrase), v.iterExp, v.id, v.extendable)
			if !bytes.Equal(ct, expectedCT) {
				t.Fatalf("encrypt mismatch:\n  got:  %x\n  want: %x", ct, expectedCT)
			}

			// Verify round-trip.
			pt := decrypt(ct, []byte(v.passphrase), v.iterExp, v.id, v.extendable)
			if !bytes.Equal(pt, plaintext) {
				t.Fatalf("decrypt mismatch:\n  got:  %x\n  want: %x", pt, plaintext)
			}
		})
	}
}

// TestGetSaltAntiTamper verifies getSalt output against Python-generated values (F223).
func TestGetSaltAntiTamper(t *testing.T) {
	tests := []struct {
		id         int
		extendable bool
		expected   string // hex
	}{
		{7945, false, "7368616d69721f09"},
		{7945, true, ""},
		{0, false, "7368616d69720000"},
	}
	for _, tc := range tests {
		salt := getSalt(tc.id, tc.extendable)
		got := hex.EncodeToString(salt)
		if got != tc.expected {
			t.Fatalf("getSalt(%d, %v): got %s, want %s", tc.id, tc.extendable, got, tc.expected)
		}
	}
}

// TestPBKDF2SHA256KnownVectors verifies x/crypto/pbkdf2 with HMAC-SHA256
// against Python hashlib.pbkdf2_hmac output (F184). Pins our dependency behavior.
func TestPBKDF2SHA256KnownVectors(t *testing.T) {
	vectors := []struct {
		password   string
		salt       string
		iterations int
		dkLen      int
		expected   string
	}{
		{"password", "salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{"password", "salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	}

	for _, v := range vectors {
		dk := pbkdf2.Key([]byte(v.password), []byte(v.salt), v.iterations, v.dkLen, sha256.New)
		expected, _ := hex.DecodeString(v.expected)
		if !bytes.Equal(dk, expected) {
			t.Fatalf("PBKDF2-SHA256(%q, %q, %d, %d):\n  got:  %x\n  want: %x",
				v.password, v.salt, v.iterations, v.dkLen, dk, expected)
		}
	}
}

// TestHMACArgumentOrderAntiTamper verifies the HMAC argument order in createDigest (F60, F83).
// key=randomPart, msg=sharedSecret. Swapping them produces a different digest.
func TestHMACArgumentOrderAntiTamper(t *testing.T) {
	randomPart := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	secret := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}

	// Correct order: key=randomPart, msg=secret.
	digest := createDigest(randomPart, secret)

	// Swapped order: key=secret, msg=randomPart.
	swappedDigest := createDigest(secret, randomPart)

	if bytes.Equal(digest, swappedDigest) {
		t.Fatal("HMAC argument order doesn't matter for these inputs - test is invalid")
	}

	// F50: verify against independent HMAC computation using stdlib.
	// This proves createDigest uses HMAC-SHA256(key=randomPart, msg=secret)[:4]
	// and not the swapped argument order.
	h := hmac.New(sha256.New, randomPart) // key = randomPart (explicit)
	h.Write(secret)                        // msg = secret (explicit)
	independentFull := h.Sum(nil)
	if !bytes.Equal(digest, independentFull[:digestLengthBytes]) {
		t.Fatalf("createDigest does not match independent HMAC computation:\n  got:  %x\n  want: %x", digest, independentFull[:digestLengthBytes])
	}
}

// TestFeistelCiphertextNotPlaintext verifies encrypt produces different output (F85).
func TestFeistelCiphertextNotPlaintext(t *testing.T) {
	secret := make([]byte, 16)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	ct := encrypt(secret, []byte("TREZOR"), 0, 7945, false)
	if bytes.Equal(ct, secret) {
		t.Fatal("ciphertext equals plaintext")
	}
}

// TestFeistelWrongPassphraseDifferentResult verifies that different passphrases
// produce different ciphertexts (F178: plausible deniability by design).
func TestFeistelWrongPassphraseDifferentResult(t *testing.T) {
	secret, _ := hex.DecodeString("bb54aac4b89dc868ba37d9cc21b2cece")
	ct1 := encrypt(secret, []byte("TREZOR"), 0, 7945, false)
	ct2 := encrypt(secret, []byte("wrong"), 0, 7945, false)
	if bytes.Equal(ct1, ct2) {
		t.Fatal("different passphrases produced same ciphertext")
	}
}

// TestFeistelNilPassphrase verifies nil passphrase behaves identically
// to empty passphrase (F275 normalization).
func TestFeistelNilPassphrase(t *testing.T) {
	secret, _ := hex.DecodeString("bb54aac4b89dc868ba37d9cc21b2cece")
	ctNil := encrypt(secret, nil, 0, 7945, false)
	ctEmpty := encrypt(secret, []byte{}, 0, 7945, false)
	if !bytes.Equal(ctNil, ctEmpty) {
		t.Fatalf("nil vs empty passphrase differ:\n  nil:   %x\n  empty: %x", ctNil, ctEmpty)
	}
	// Verify decrypt also works with nil.
	dec := decrypt(ctNil, nil, 0, 7945, false)
	if !bytes.Equal(dec, secret) {
		t.Fatalf("decrypt with nil passphrase failed:\n  got:  %x\n  want: %x", dec, secret)
	}
}
