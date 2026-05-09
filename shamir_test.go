// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

package slip39

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

// TestShamirSplitRecoverRoundTrip verifies the end-to-end wiring between
// splitSecret and recoverSecret for various threshold/shareCount combinations.
func TestShamirSplitRecoverRoundTrip(t *testing.T) {
	secret := []byte{
		0xBB, 0x54, 0xAA, 0xC4, 0xB8, 0x9D, 0xC8, 0x68,
		0xBA, 0x37, 0xD9, 0xCC, 0x21, 0xB2, 0xCE, 0xCE,
	}

	testCases := []struct {
		name       string
		threshold  int
		shareCount int
	}{
		{"1-of-1", 1, 1},
		{"1-of-3", 1, 3},
		{"2-of-3", 2, 3},
		{"3-of-5", 3, 5},
		{"2-of-2", 2, 2},
		{"5-of-5", 5, 5},
		{"16-of-16", 16, 16},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			shares, err := splitSecret(tc.threshold, tc.shareCount, secret, rand.Reader)
			if err != nil {
				t.Fatalf("splitSecret: %v", err)
			}
			if len(shares) != tc.shareCount {
				t.Fatalf("got %d shares, want %d", len(shares), tc.shareCount)
			}

			// Recover using exactly threshold shares.
			recovered, err := recoverSecret(tc.threshold, shares[:tc.threshold])
			if err != nil {
				t.Fatalf("recoverSecret: %v", err)
			}
			if !bytes.Equal(recovered, secret) {
				t.Fatalf("recovered secret mismatch:\n  got:  %x\n  want: %x", recovered, secret)
			}
			ZeroBytes(recovered)

			// Cleanup shares.
			for _, s := range shares {
				ZeroBytes(s.data)
			}
		})
	}
}

// TestShamirSplitRecoverRoundTrip256 verifies round-trip with a 256-bit secret.
func TestShamirSplitRecoverRoundTrip256(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i * 7)
	}

	shares, err := splitSecret(3, 5, secret, rand.Reader)
	if err != nil {
		t.Fatalf("splitSecret: %v", err)
	}

	recovered, err := recoverSecret(3, shares[:3])
	if err != nil {
		t.Fatalf("recoverSecret: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Fatalf("256-bit round-trip failed")
	}
	ZeroBytes(recovered)
	for _, s := range shares {
		ZeroBytes(s.data)
	}
}

// TestShamirRecoverWrongThreshold verifies that recovering with the wrong
// threshold produces a digest mismatch error, not a silent wrong result.
func TestShamirRecoverWrongThreshold(t *testing.T) {
	secret := make([]byte, 16)
	for i := range secret {
		secret[i] = byte(i + 1)
	}

	shares, err := splitSecret(3, 5, secret, rand.Reader)
	if err != nil {
		t.Fatalf("splitSecret: %v", err)
	}

	// Use threshold=2 with shares generated for threshold=3.
	// The polynomial is degree 2 (3 base points), so interpolation with
	// 2 points reconstructs a different (degree-1) polynomial. The digest
	// check must catch this.
	_, err = recoverSecret(2, shares[:2])
	if err == nil {
		t.Fatal("expected error for wrong threshold, got nil")
	}
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch, got: %v", err)
	}

	for _, s := range shares {
		ZeroBytes(s.data)
	}
}

// TestShamirThreshold1AllSharesIdentical verifies that with threshold=1,
// all shares contain identical data (copies of the secret).
func TestShamirThreshold1AllSharesIdentical(t *testing.T) {
	secret := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33,
		0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB}

	shares, err := splitSecret(1, 5, secret, rand.Reader)
	if err != nil {
		t.Fatalf("splitSecret: %v", err)
	}

	for i, s := range shares {
		if !bytes.Equal(s.data, secret) {
			t.Fatalf("share %d != secret for threshold=1", i)
		}
	}
	for _, s := range shares {
		ZeroBytes(s.data)
	}
}

// TestShamirSplitDoesNotModifyInput verifies that splitSecret does not
// mutate the caller's secret slice.
func TestShamirSplitDoesNotModifyInput(t *testing.T) {
	original := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	secret := make([]byte, len(original))
	copy(secret, original)

	shares, err := splitSecret(3, 5, secret, rand.Reader)
	if err != nil {
		t.Fatalf("splitSecret: %v", err)
	}

	if !bytes.Equal(secret, original) {
		t.Fatal("splitSecret modified the input secret slice")
	}

	for _, s := range shares {
		ZeroBytes(s.data)
	}
}

// TestShamirSharesAreDistinct verifies that all shares from a split
// have different data (entropy verification).
func TestShamirSharesAreDistinct(t *testing.T) {
	secret := make([]byte, 16)
	for i := range secret {
		secret[i] = byte(i)
	}

	shares, err := splitSecret(3, 5, secret, rand.Reader)
	if err != nil {
		t.Fatalf("splitSecret: %v", err)
	}

	for i := 0; i < len(shares); i++ {
		for j := i + 1; j < len(shares); j++ {
			if bytes.Equal(shares[i].data, shares[j].data) {
				t.Fatalf("shares %d and %d are identical", i, j)
			}
		}
	}

	for _, s := range shares {
		ZeroBytes(s.data)
	}
}

// TestShamirRecoverWithDifferentShareSubsets verifies that any threshold-sized
// subset of shares recovers the same secret.
func TestShamirRecoverWithDifferentShareSubsets(t *testing.T) {
	secret := make([]byte, 16)
	for i := range secret {
		secret[i] = byte(i * 3)
	}

	shares, err := splitSecret(2, 4, secret, rand.Reader)
	if err != nil {
		t.Fatalf("splitSecret: %v", err)
	}

	// Try all C(4,2) = 6 subsets.
	subsets := [][2]int{{0, 1}, {0, 2}, {0, 3}, {1, 2}, {1, 3}, {2, 3}}
	for _, pair := range subsets {
		subset := []share{shares[pair[0]], shares[pair[1]]}
		recovered, err := recoverSecret(2, subset)
		if err != nil {
			t.Fatalf("recoverSecret with shares [%d,%d]: %v", pair[0], pair[1], err)
		}
		if !bytes.Equal(recovered, secret) {
			t.Fatalf("shares [%d,%d] recovered wrong secret", pair[0], pair[1])
		}
		ZeroBytes(recovered)
	}

	for _, s := range shares {
		ZeroBytes(s.data)
	}
}

// TestShamirSplitInvalidInputs verifies error handling for bad splitSecret inputs.
func TestShamirSplitInvalidInputs(t *testing.T) {
	secret16 := make([]byte, 16)

	tests := []struct {
		name       string
		threshold  int
		shareCount int
		secret     []byte
	}{
		{"threshold 0", 0, 3, secret16},
		{"threshold > count", 4, 3, secret16},
		{"count > 16", 2, 17, secret16},
		{"secret too short", 2, 3, make([]byte, 14)},
		{"secret too long", 2, 3, make([]byte, 66)},
		{"secret odd length", 2, 3, make([]byte, 17)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := splitSecret(tc.threshold, tc.shareCount, tc.secret, rand.Reader)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

// TestShamirRecoverInvalidInputs verifies error handling for bad recoverSecret inputs.
func TestShamirRecoverInvalidInputs(t *testing.T) {
	data16 := make([]byte, 16)
	validShares := []share{
		{x: 0, data: data16},
		{x: 1, data: data16},
	}

	t.Run("threshold 0", func(t *testing.T) {
		_, err := recoverSecret(0, validShares)
		if err == nil {
			t.Fatal("expected error for threshold=0")
		}
		if !errors.Is(err, ErrInvalidShares) {
			t.Fatalf("expected ErrInvalidShares, got: %v", err)
		}
	})

	t.Run("threshold negative", func(t *testing.T) {
		_, err := recoverSecret(-1, validShares)
		if err == nil {
			t.Fatal("expected error for threshold=-1")
		}
	})

	t.Run("not enough shares", func(t *testing.T) {
		_, err := recoverSecret(3, validShares[:1])
		if err == nil {
			t.Fatal("expected error for insufficient shares")
		}
		if !errors.Is(err, ErrInvalidShares) {
			t.Fatalf("expected ErrInvalidShares, got: %v", err)
		}
	})
}

// TestInterpolateXMatchEarlyReturn verifies the special case:
// when resultIndex matches a share's x-coordinate, that share's value
// is returned directly without full polynomial evaluation.
func TestInterpolateXMatchEarlyReturn(t *testing.T) {
	// Create shares with known data at specific x-coordinates.
	shares := []share{
		{x: 0, data: []byte{0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xA0, 0xB0, 0xC0}},
		{x: 1, data: []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00}},
		{x: 2, data: []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0}},
	}

	// Interpolate at x=1, which matches shares[1].
	result := make([]byte, 16)
	err := interpolate(result, 1, shares)
	if err != nil {
		t.Fatalf("interpolate at x=1: %v", err)
	}
	if !bytes.Equal(result, shares[1].data) {
		t.Fatalf("interpolate at x=1 (match):\n  got:  %x\n  want: %x", result, shares[1].data)
	}

	// Interpolate at x=0, which matches shares[0].
	err = interpolate(result, 0, shares)
	if err != nil {
		t.Fatalf("interpolate at x=0: %v", err)
	}
	if !bytes.Equal(result, shares[0].data) {
		t.Fatalf("interpolate at x=0 (match):\n  got:  %x\n  want: %x", result, shares[0].data)
	}
}

// TestShamirSplitRecover64Byte verifies round-trip with a 512-bit (64-byte) secret.
// This is the maximum size per spec "128-512 bits".
func TestShamirSplitRecover64Byte(t *testing.T) {
	secret := make([]byte, 64)
	for i := range secret {
		secret[i] = byte(i)
	}

	shares, err := splitSecret(3, 5, secret, rand.Reader)
	if err != nil {
		t.Fatalf("splitSecret 64-byte: %v", err)
	}

	recovered, err := recoverSecret(3, shares[:3])
	if err != nil {
		t.Fatalf("recoverSecret 64-byte: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Fatal("64-byte round-trip failed")
	}
	ZeroBytes(recovered)
	for _, s := range shares {
		ZeroBytes(s.data)
	}
}

// TestShamirDuplicateShareIndices verifies that interpolation with duplicate
// x-coordinates is detected and returns an error.
func TestShamirDuplicateShareIndices(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}
	// Two shares with same x-coordinate.
	shares := []share{
		{x: 0, data: data},
		{x: 0, data: data},
		{x: 1, data: data},
	}
	result := make([]byte, 16)
	err := interpolate(result, 5, shares)
	if err == nil {
		t.Fatal("expected error for duplicate share indices, got nil")
	}
}

// TestShamirMismatchedShareLengths verifies that shares with different data
// lengths are rejected (VP1-1).
func TestShamirMismatchedShareLengths(t *testing.T) {
	shares := []share{
		{x: 0, data: make([]byte, 16)},
		{x: 1, data: make([]byte, 32)}, // different length
	}
	result := make([]byte, 16)
	err := interpolate(result, 5, shares)
	if err == nil {
		t.Fatal("expected error for mismatched share lengths, got nil")
	}
}

// TestErrorSentinelsWithErrorsIs verifies that all error paths produce
// errors matchable with errors.Is.
func TestErrorSentinelsWithErrorsIs(t *testing.T) {
	// ErrInvalidShares: from splitSecret with bad threshold.
	_, err := splitSecret(0, 3, make([]byte, 16), rand.Reader)
	if !errors.Is(err, ErrInvalidShares) {
		t.Fatalf("splitSecret threshold=0: expected ErrInvalidShares, got %v", err)
	}

	// ErrInvalidSecret: from splitSecret with bad secret length.
	_, err = splitSecret(2, 3, make([]byte, 15), rand.Reader)
	if !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("splitSecret len=15: expected ErrInvalidSecret, got %v", err)
	}

	// ErrDigestMismatch: from recoverSecret with wrong threshold.
	secret := make([]byte, 16)
	for i := range secret {
		secret[i] = byte(i)
	}
	shares, err := splitSecret(3, 5, secret, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = recoverSecret(2, shares[:2])
	if !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("recoverSecret wrong threshold: expected ErrDigestMismatch, got %v", err)
	}
	for _, s := range shares {
		ZeroBytes(s.data)
	}
}
