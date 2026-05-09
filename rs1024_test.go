// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

package slip39

import "testing"

// TestRS1024SpecVector1 verifies RS1024 against actual spec vector 1.
// Word indices verified by parsing the real mnemonic through Python reference:
// "duckling enlarge academic academic agency result length solution fridge
//
//	kidney coal piece deal husband erode duke ajar critical decision keyboard"
//
// Customization string "shamir" (non-extendable, vector 1 has ext=false).
func TestRS1024SpecVector1(t *testing.T) {
	// All 20 word indices from spec vector 1, verified against Python shamir_mnemonic.
	allWords := []int{
		248, 288, 0, 0, 17, 753, 521, 840, 372, 497,
		155, 670, 192, 448, 297, 249, 23, 173, 196, 496,
	}
	cs := []byte("shamir")

	// The full 20-word codeword (17 data + 3 checksum) must verify.
	if !rs1024VerifyChecksum(allWords, cs) {
		t.Fatal("rs1024VerifyChecksum failed on spec vector 1")
	}

	// Also verify our createChecksum matches the spec's checksum words.
	data := allWords[:17]
	checksum := rs1024CreateChecksum(data, cs)
	expectedChecksum := [3]int{173, 196, 496}
	if checksum != expectedChecksum {
		t.Fatalf("checksum mismatch: got %v, want %v", checksum, expectedChecksum)
	}
}

// TestRS1024CreateVerifyRoundTrip tests create then verify for several inputs.
func TestRS1024CreateVerifyRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		data []int
		cs   []byte
	}{
		{"empty data", []int{}, []byte("shamir")},
		{"single word", []int{42}, []byte("shamir")},
		{"extendable", []int{100, 200, 300}, []byte("shamir_extendable")},
		{"zeros", []int{0, 0, 0, 0, 0}, []byte("shamir")},
		{"max values", []int{1023, 1023, 1023}, []byte("shamir")},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			checksum := rs1024CreateChecksum(tc.data, tc.cs)
			full := make([]int, len(tc.data)+checksumLengthWords)
			copy(full, tc.data)
			for i := 0; i < checksumLengthWords; i++ {
				full[len(tc.data)+i] = checksum[i]
			}
			if !rs1024VerifyChecksum(full, tc.cs) {
				t.Fatalf("verify failed for %s", tc.name)
			}
		})
	}
}

// TestRS1024InvalidChecksum verifies that a modified checksum fails verification.
func TestRS1024InvalidChecksum(t *testing.T) {
	data := []int{42, 100, 200}
	cs := []byte("shamir")
	checksum := rs1024CreateChecksum(data, cs)

	full := make([]int, len(data)+checksumLengthWords)
	copy(full, data)
	for i := 0; i < checksumLengthWords; i++ {
		full[len(data)+i] = checksum[i]
	}

	// Flip one checksum word.
	full[len(data)] ^= 1
	if rs1024VerifyChecksum(full, cs) {
		t.Fatal("verify should fail with modified checksum")
	}
}

// TestRS1024ExhaustiveSingleErrorDetection verifies that flipping any single
// word in a valid codeword to any other value is detected (F256).
// Uses spec vector 1 (20 words). Tests 20 * 1023 = 20,460 cases.
func TestRS1024ExhaustiveSingleErrorDetection(t *testing.T) {
	// Spec vector 1: all 20 word indices (verified against Python reference).
	codeword := []int{
		248, 288, 0, 0, 17, 753, 521, 840, 372, 497,
		155, 670, 192, 448, 297, 249, 23, 173, 196, 496,
	}
	cs := []byte("shamir")

	// Sanity: original is valid.
	if !rs1024VerifyChecksum(codeword, cs) {
		t.Fatal("original codeword fails verification")
	}

	errorsDetected := 0
	for pos := 0; pos < len(codeword); pos++ {
		original := codeword[pos]
		for alt := 0; alt < 1024; alt++ {
			if alt == original {
				continue
			}
			codeword[pos] = alt
			if rs1024VerifyChecksum(codeword, cs) {
				t.Fatalf("single-error NOT detected at position %d: original=%d, modified=%d", pos, original, alt)
			}
			errorsDetected++
		}
		codeword[pos] = original // restore
	}

	expected := len(codeword) * 1023
	if errorsDetected != expected {
		t.Fatalf("tested %d cases, expected %d", errorsDetected, expected)
	}
}

// TestRS1024WrongCustomizationString verifies that the wrong customization
// string causes verification failure.
func TestRS1024WrongCustomizationString(t *testing.T) {
	data := []int{42, 100, 200}
	cs := []byte("shamir")
	checksum := rs1024CreateChecksum(data, cs)

	full := make([]int, len(data)+checksumLengthWords)
	copy(full, data)
	for i := 0; i < checksumLengthWords; i++ {
		full[len(data)+i] = checksum[i]
	}

	// Verify with wrong customization string.
	if rs1024VerifyChecksum(full, []byte("shamir_extendable")) {
		t.Fatal("verify should fail with wrong customization string")
	}
}

// TestRS1024CustomizationStringAntiTamper verifies the byte values of
// customization strings (F266).
func TestRS1024CustomizationStringAntiTamper(t *testing.T) {
	expected := []byte{0x73, 0x68, 0x61, 0x6D, 0x69, 0x72} // "shamir"
	actual := []byte(customizationStringOriginal)
	if len(actual) != len(expected) {
		t.Fatalf("customization string length: got %d, want %d", len(actual), len(expected))
	}
	for i := range expected {
		if actual[i] != expected[i] {
			t.Fatalf("customization string byte %d: got 0x%02X, want 0x%02X", i, actual[i], expected[i])
		}
	}

	expectedExt := []byte{0x73, 0x68, 0x61, 0x6D, 0x69, 0x72, 0x5F, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x64, 0x61, 0x62, 0x6C, 0x65}
	actualExt := []byte(customizationStringExtendable)
	if len(actualExt) != len(expectedExt) {
		t.Fatalf("extendable customization string length: got %d, want %d", len(actualExt), len(expectedExt))
	}
	for i := range expectedExt {
		if actualExt[i] != expectedExt[i] {
			t.Fatalf("extendable customization string byte %d: got 0x%02X, want 0x%02X", i, actualExt[i], expectedExt[i])
		}
	}
}
