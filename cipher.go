// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

// 4-round Feistel cipher using PBKDF2-HMAC-SHA256 as the round function.
// Encrypts and decrypts the master secret as specified by SLIP-0039.

package slip39

import (
	"crypto/sha256"
	"encoding/binary"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// baseIterationsPerRound is the base PBKDF2 iteration count per Feistel round.
	// Spec formula: iterations = 2500 << iterationExponent.
	baseIterationsPerRound = 2500

	// roundCount is the number of Feistel rounds.
	roundCount = 4

	// customizationStringOriginal is the salt prefix for non-extendable backups.
	customizationStringOriginal = "shamir"

	// customizationStringExtendable is the salt prefix for extendable backups.
	customizationStringExtendable = "shamir_extendable"
)

// getSalt constructs the Feistel cipher salt prefix.
// For non-extendable: "shamir" + identifier (2 bytes big-endian).
// For extendable: empty (the identifier is not included).
func getSalt(identifier int, extendable bool) []byte {
	if extendable {
		return []byte{} // Empty, not nil.
	}
	cs := []byte(customizationStringOriginal)
	salt := make([]byte, len(cs)+2)
	copy(salt, cs)
	binary.BigEndian.PutUint16(salt[len(cs):], uint16(identifier)) // Big-endian.
	return salt
}

// encrypt applies the 4-round Feistel cipher to produce the Encrypted Master Secret.
//
// All intermediate buffers are pre-allocated and zeroed on exit.
// The result is constructed via explicit make+copy to avoid append aliasing.
func encrypt(secret, passphrase []byte, iterationExponent, identifier int, extendable bool) []byte {
	if len(secret) == 0 || len(secret)%2 != 0 {
		panic("slip39: encrypt requires non-empty even-length secret")
	}
	if iterationExponent < 0 || iterationExponent > 15 {
		panic("slip39: iteration exponent must be in [0, 15]")
	}
	// Normalize nil passphrase to empty for consistent PBKDF2 behavior.
	if passphrase == nil {
		passphrase = []byte{}
	}
	half := len(secret) / 2
	iterations := baseIterationsPerRound << iterationExponent

	// Split into halves.
	l := make([]byte, half)
	r := make([]byte, half)
	copy(l, secret[:half])
	copy(r, secret[half:])

	// Pre-allocate password and salt buffers.
	// Password = round_byte + passphrase.
	password := make([]byte, 1+len(passphrase))
	copy(password[1:], passphrase)
	defer ZeroBytes(password)

	// Salt = getSalt prefix + R (updated each round).
	saltPrefix := getSalt(identifier, extendable)
	salt := make([]byte, len(saltPrefix)+half)
	copy(salt, saltPrefix)
	defer ZeroBytes(salt)

	for i := 0; i < roundCount; i++ {
		password[0] = byte(i) // Round byte, no collision with passphrase range.
		copy(salt[len(saltPrefix):], r)

		// Assert PBKDF2 output length.
		f := pbkdf2.Key(password, salt, iterations, half, sha256.New)
		if len(f) != half {
			panic("slip39: pbkdf2.Key returned unexpected length")
		}

		// XOR l with f in-place.
		xorBytes(l, l, f)
		ZeroBytes(f) // Zero each round.

		// Swap l and r for next round.
		l, r = r, l
	}

	// Explicit allocation, no append aliasing.
	// After 4 rounds with final swap, result is r||l (Feistel convention).
	result := make([]byte, len(secret))
	copy(result, r)
	copy(result[half:], l)

	ZeroBytes(l)
	ZeroBytes(r)

	return result
}

// decrypt reverses the Feistel cipher to recover the master secret.
func decrypt(ems, passphrase []byte, iterationExponent, identifier int, extendable bool) []byte {
	if len(ems) == 0 || len(ems)%2 != 0 {
		panic("slip39: decrypt requires non-empty even-length input")
	}
	if iterationExponent < 0 || iterationExponent > 15 {
		panic("slip39: iteration exponent must be in [0, 15]")
	}
	// Normalize nil passphrase to empty for consistent PBKDF2 behavior.
	if passphrase == nil {
		passphrase = []byte{}
	}
	half := len(ems) / 2
	iterations := baseIterationsPerRound << iterationExponent

	// Split into halves.
	l := make([]byte, half)
	r := make([]byte, half)
	copy(l, ems[:half])
	copy(r, ems[half:])

	// Pre-allocate password and salt buffers.
	password := make([]byte, 1+len(passphrase))
	copy(password[1:], passphrase)
	defer ZeroBytes(password)

	saltPrefix := getSalt(identifier, extendable)
	salt := make([]byte, len(saltPrefix)+half)
	copy(salt, saltPrefix)
	defer ZeroBytes(salt)

	// Reverse round order. Same structure as encrypt: l, r = r, xor(l, f).
	// Output is r + l (same as encrypt). The reversal is only in round indices.
	for i := roundCount - 1; i >= 0; i-- {
		password[0] = byte(i)
		copy(salt[len(saltPrefix):], r)

		f := pbkdf2.Key(password, salt, iterations, half, sha256.New)
		if len(f) != half {
			panic("slip39: pbkdf2.Key returned unexpected length")
		}

		// l, r = r, xor(l, f) - same as encrypt.
		xorBytes(l, l, f)
		ZeroBytes(f)
		l, r = r, l
	}

	// Explicit allocation, output is r||l.
	result := make([]byte, len(ems))
	copy(result, r)
	copy(result[half:], l)

	ZeroBytes(l)
	ZeroBytes(r)

	return result
}

// xorBytes XORs a and b into dst. All three must have the same length.
func xorBytes(dst, a, b []byte) {
	if len(a) != len(dst) || len(b) != len(dst) {
		panic("slip39: xorBytes length mismatch")
	}
	for i := range dst {
		dst[i] = a[i] ^ b[i]
	}
}
