// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

package slip39

import (
	"bytes"
	"strings"
	"testing"
)

// FuzzCombine feeds arbitrary byte sequences as mnemonic strings to Combine.
// Catches panics, hangs, and memory corruption on malformed input.
func FuzzCombine(f *testing.F) {
	// Seed with real spec vector mnemonics and garbage.
	f.Add("duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard")
	f.Add("shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed")
	f.Add("")
	f.Add("not a valid mnemonic at all")
	f.Add(strings.Repeat("academic ", 20))

	f.Fuzz(func(t *testing.T, mnemonic string) {
		// Must never panic regardless of input.
		result, err := Combine([]string{mnemonic}, nil)
		if err == nil && result != nil {
			ZeroBytes(result)
		}
	})
}

// FuzzRoundTrip splits a constrained valid secret and verifies recovery.
// Input is used as the secret (after length/parity adjustment).
func FuzzRoundTrip(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x42}, 16))
	f.Add(bytes.Repeat([]byte{0xFF}, 32))
	f.Add(bytes.Repeat([]byte{0x00}, 16))
	f.Add(bytes.Repeat([]byte{0xAB}, 64))

	f.Fuzz(func(t *testing.T, secret []byte) {
		// Constrain to valid secret: 16-64 bytes, even length.
		if len(secret) < 16 {
			return
		}
		if len(secret) > 64 {
			secret = secret[:64]
		}
		if len(secret)%2 != 0 {
			secret = secret[:len(secret)-1]
			if len(secret) < 16 {
				return // even-length truncation dropped below minimum
			}
		}

		groups, err := Split(secret, nil, WithIterationExponent(0))
		if err != nil {
			t.Fatal(err)
		}

		recovered, err := Combine(groups[0], nil)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(recovered, secret) {
			t.Fatalf("round-trip mismatch:\n  got:  %x\n  want: %x", recovered, secret)
		}
		ZeroBytes(recovered)
	})
}

// FuzzInterpolate feeds arbitrary share data to the interpolation function.
// Catches panics and out-of-bounds on malformed share payloads.
func FuzzInterpolate(f *testing.F) {
	f.Add([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}, byte(0), byte(1))
	f.Add(bytes.Repeat([]byte{0xFF}, 16), byte(5), byte(10))

	f.Fuzz(func(t *testing.T, data []byte, x0, x1 byte) {
		if len(data) < 16 || len(data) > 64 {
			return
		}
		if x0 == x1 {
			return // duplicate indices
		}
		// Create two shares with independent copies of the fuzzed data.
		shares := []share{
			{x: x0, data: append([]byte{}, data...)},
			{x: x1, data: append([]byte{}, data...)},
		}
		result := make([]byte, len(data))
		// Must not panic.
		_ = interpolate(result, 255, shares)
		ZeroBytes(result)
	})
}

// FuzzBitStream writes arbitrary bytes through the BitStream writer/reader
// and verifies byte-level round-trip.
func FuzzBitStream(f *testing.F) {
	f.Add([]byte{0x00, 0xFF, 0xA5, 0x5A})
	f.Add([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return
		}
		if len(data) > 128 {
			data = data[:128]
		}

		totalBits := len(data) * 8
		w := newBitStreamWriter(totalBits)
		for _, b := range data {
			w.Write(uint64(b), 8)
		}

		r := newBitStreamReader(w.Bytes(), totalBits)
		for i, expected := range data {
			got, err := r.Read(8)
			if err != nil {
				t.Fatalf("byte %d: %v", i, err)
			}
			if byte(got) != expected {
				t.Fatalf("byte %d: got 0x%02x, want 0x%02x", i, got, expected)
			}
		}
	})
}

// FuzzFeistel fuzzes the Feistel encrypt/decrypt round-trip.
// Uses constrained iterExp (0-1) for speed.
func FuzzFeistel(f *testing.F) {
	f.Add(bytes.Repeat([]byte{0x42}, 16), []byte("TREZOR"), 0, 7945, false)
	f.Add(bytes.Repeat([]byte{0xFF}, 32), []byte(""), 0, 0, true)
	f.Add(bytes.Repeat([]byte{0x00}, 16), []byte("pass"), 1, 32767, false)

	f.Fuzz(func(t *testing.T, secret, passphrase []byte, iterExpRaw, idRaw int, extendable bool) {
		// Constrain secret: 16-64, even.
		if len(secret) < 16 {
			return
		}
		if len(secret) > 64 {
			secret = secret[:64]
		}
		if len(secret)%2 != 0 {
			secret = secret[:len(secret)-1]
			if len(secret) < 16 {
				return
			}
		}
		// Constrain passphrase to printable ASCII.
		clean := make([]byte, 0, len(passphrase))
		for _, b := range passphrase {
			if b >= 32 && b <= 126 {
				clean = append(clean, b)
			}
		}
		if len(clean) > 32 {
			clean = clean[:32]
		}
		// Constrain iterExp for speed, identifier to 15-bit range.
		iterExp := iterExpRaw & 1
		identifier := idRaw & ((1 << 15) - 1)

		ct := encrypt(secret, clean, iterExp, identifier, extendable)
		pt := decrypt(ct, clean, iterExp, identifier, extendable)

		if !bytes.Equal(pt, secret) {
			t.Fatalf("Feistel round-trip failed:\n  got:  %x\n  want: %x", pt, secret)
		}
		ZeroBytes(ct)
		ZeroBytes(pt)
		ZeroBytes(clean)
	})
}
