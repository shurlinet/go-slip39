// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT
//
// RS1024 error-detecting code (BCH code over GF(1024)).
// Used for SLIP-0039 mnemonic checksum validation.
// All values are public data (word indices); no constant-time requirement (F177).

package slip39

const (
	checksumLengthWords = 3
)

// rs1024Polymod computes the BCH polynomial modulus for the given values.
// Each value is a 10-bit word index.
//
// The generator polynomial coefficients are inlined as constants rather than
// stored in a mutable package-level variable. This prevents accidental or
// malicious modification at runtime.
func rs1024Polymod(values []int) uint32 {
	// BCH generator polynomial coefficients.
	// Verified against the SLIP-0039 spec and all reference implementations (F182, F217).
	gen := [10]uint32{
		0xE0E040,
		0x1C1C080,
		0x3838100,
		0x7070200,
		0xE0E0009,
		0x1C0C2412,
		0x38086C24,
		0x3090FC48,
		0x21B1F890,
		0x3F3F120,
	}
	chk := uint32(1)
	for _, v := range values {
		b := chk >> 20
		chk = (chk & 0xFFFFF) << 10 ^ uint32(v)
		for i := 0; i < 10; i++ {
			if (b>>i)&1 != 0 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// rs1024CreateChecksum computes the 3-word RS1024 checksum for the given data
// with the specified customization string.
func rs1024CreateChecksum(data []int, customizationString []byte) [checksumLengthWords]int {
	values := make([]int, 0, len(customizationString)+len(data)+checksumLengthWords)
	for _, b := range customizationString {
		values = append(values, int(b))
	}
	values = append(values, data...)
	for i := 0; i < checksumLengthWords; i++ {
		values = append(values, 0)
	}

	polymod := rs1024Polymod(values) ^ 1
	var result [checksumLengthWords]int
	for i := 0; i < checksumLengthWords; i++ {
		result[i] = int((polymod >> (10 * (checksumLengthWords - 1 - i))) & 1023)
	}
	return result
}

// rs1024VerifyChecksum returns true if the data (including checksum words)
// is valid according to the RS1024 code.
func rs1024VerifyChecksum(data []int, customizationString []byte) bool {
	values := make([]int, 0, len(customizationString)+len(data))
	for _, b := range customizationString {
		values = append(values, int(b))
	}
	values = append(values, data...)
	return rs1024Polymod(values) == 1
}
