// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

package slip39

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// --- Spec Vector Tests (GATE) ---

// vectorEntry represents one entry from testdata/vectors.json.
// Format: [description, [mnemonics...], masterSecretHex, xprv]
type vectorEntry struct {
	Description string
	Mnemonics   []string
	MasterHex   string // empty = expected failure
}

func loadVectors(t *testing.T) []vectorEntry {
	t.Helper()
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("reading vectors.json: %v", err)
	}

	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parsing vectors.json: %v", err)
	}

	vectors := make([]vectorEntry, len(raw))
	for i, r := range raw {
		var fields []json.RawMessage
		if err := json.Unmarshal(r, &fields); err != nil {
			t.Fatalf("parsing vector %d: %v", i, err)
		}
		if len(fields) != 4 {
			t.Fatalf("vector %d: expected 4 fields, got %d", i, len(fields))
		}

		var desc string
		if err := json.Unmarshal(fields[0], &desc); err != nil {
			t.Fatalf("vector %d description: %v", i, err)
		}

		var mnemonics []string
		if err := json.Unmarshal(fields[1], &mnemonics); err != nil {
			t.Fatalf("vector %d mnemonics: %v", i, err)
		}

		var masterHex string
		if err := json.Unmarshal(fields[2], &masterHex); err != nil {
			t.Fatalf("vector %d masterHex: %v", i, err)
		}

		vectors[i] = vectorEntry{
			Description: desc,
			Mnemonics:   mnemonics,
			MasterHex:   masterHex,
		}
	}
	return vectors
}

// vectorErrorMap maps vector indices (1-based) to expected error sentinels (F198).
// Empty masterHex means expected failure. Each failure maps to a specific error type.
var vectorErrorMap = map[int]error{
	2:  ErrInvalidChecksum,  // invalid checksum
	3:  ErrInvalidMnemonic,  // invalid padding
	5:  ErrInvalidShares,    // insufficient shares (1 of 2-of-3)
	6:  ErrInvalidShares,    // different identifiers
	7:  ErrInvalidShares,    // different iteration exponents
	8:  ErrInvalidShares,    // mismatching group thresholds
	9:  ErrInvalidShares,    // mismatching group counts
	10: ErrInvalidMnemonic,  // greater group threshold than group counts (caught in decode)
	11: ErrInvalidShares,    // duplicate member indices
	12: ErrInvalidShares,    // mismatching member thresholds
	13: ErrDigestMismatch,   // invalid digest
	14: ErrInvalidShares,    // insufficient groups (1 of 2 needed)
	15: ErrInvalidShares,    // insufficient groups (2 of 3 needed)
	16: ErrInvalidShares,    // insufficient members in one group
	21: ErrInvalidChecksum,  // invalid checksum (256 bits)
	22: ErrInvalidMnemonic,  // invalid padding (256 bits)
	24: ErrInvalidShares,    // insufficient shares (256 bits)
	25: ErrInvalidShares,    // different identifiers (256 bits)
	26: ErrInvalidShares,    // different iteration exponents (256 bits)
	27: ErrInvalidShares,    // mismatching group thresholds (256 bits)
	28: ErrInvalidShares,    // mismatching group counts (256 bits)
	29: ErrInvalidMnemonic,  // greater group threshold than group counts (256 bits, caught in decode)
	30: ErrInvalidShares,    // duplicate member indices (256 bits)
	31: ErrInvalidShares,    // mismatching member thresholds (256 bits)
	32: ErrDigestMismatch,   // invalid digest (256 bits)
	33: ErrInvalidShares,    // insufficient groups (256 bits, case 1)
	34: ErrInvalidShares,    // insufficient groups (256 bits, case 2)
	35: ErrInvalidShares,    // insufficient members (256 bits)
	39: ErrInvalidMnemonic,  // insufficient mnemonic length
	40: ErrInvalidMnemonic,  // invalid master secret length
}

// TestSpecVectors is the GATE test. ALL 45 spec vectors must pass.
func TestSpecVectors(t *testing.T) {
	vectors := loadVectors(t)
	if len(vectors) != 45 {
		t.Fatalf("expected 45 vectors, got %d", len(vectors))
	}

	passphrase := []byte("TREZOR") // F105: all spec vectors use "TREZOR"

	for i, v := range vectors {
		vecNum := i + 1 // 1-based
		t.Run(v.Description, func(t *testing.T) {
			result, err := Combine(v.Mnemonics, passphrase)

			if v.MasterHex == "" {
				// Expected failure.
				if err == nil {
					t.Fatalf("expected error, got success with result %x", result)
				}
				// Verify specific error type (F198).
				expectedErr, ok := vectorErrorMap[vecNum]
				if ok && !errors.Is(err, expectedErr) {
					t.Errorf("expected error wrapping %v, got: %v", expectedErr, err)
				}
				return
			}

			// Expected success.
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			expectedSecret, err := hex.DecodeString(v.MasterHex)
			if err != nil {
				t.Fatalf("invalid hex in vector: %v", err)
			}

			if !bytes.Equal(result, expectedSecret) {
				t.Errorf("master secret mismatch:\ngot:  %x\nwant: %x", result, expectedSecret)
			}
		})
	}
}

// TestSpecVectorEncodeRoundTrip verifies that every decodable spec vector mnemonic
// round-trips through encode(decode(m)) == m. Proves our encoder is byte-compatible
// with the Python reference encoder that produced these vectors.
func TestSpecVectorEncodeRoundTrip(t *testing.T) {
	vectors := loadVectors(t)
	roundTripped := 0
	for _, v := range vectors {
		for _, m := range v.Mnemonics {
			sd, err := decodeMnemonic(m)
			if err != nil {
				continue // negative vectors may fail to decode
			}
			reencoded := encodeShare(sd)
			if reencoded != m {
				t.Errorf("encode round-trip mismatch for %q:\n  got:  %s\n  want: %s", v.Description, reencoded, m)
			}
			roundTripped++
		}
	}
	if roundTripped == 0 {
		t.Fatal("no mnemonics were round-tripped")
	}
	t.Logf("round-tripped %d spec vector mnemonics through decode+encode", roundTripped)
}

// TestSpecVectorExtendableModes verifies correct extendable mode mapping.
// Vectors 1-41: extendable=false. Vectors 42-45: extendable=true.
func TestSpecVectorExtendableModes(t *testing.T) {
	vectors := loadVectors(t)

	for i, v := range vectors {
		vecNum := i + 1
		if len(v.Mnemonics) == 0 {
			continue
		}
		sd, err := decodeMnemonic(v.Mnemonics[0])
		if err != nil {
			continue // negative vectors may fail to decode
		}

		if vecNum <= 41 {
			if sd.extendable {
				t.Errorf("vector %d: expected extendable=false, got true", vecNum)
			}
		} else {
			if !sd.extendable {
				t.Errorf("vector %d: expected extendable=true, got false", vecNum)
			}
		}
	}
}

// --- Round-Trip Tests ---

func TestRoundTrip128Bit(t *testing.T) {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	groups, err := Split(secret, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || len(groups[0]) != 1 {
		t.Fatalf("expected 1 group with 1 mnemonic, got %d groups", len(groups))
	}

	recovered, err := Combine(groups[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)

	if !bytes.Equal(recovered, secret) {
		t.Errorf("round-trip failed:\ngot:  %x\nwant: %x", recovered, secret)
	}
}

func TestRoundTrip256Bit(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	groups, err := Split(secret, []byte("test passphrase"))
	if err != nil {
		t.Fatal(err)
	}

	recovered, err := Combine(groups[0], []byte("test passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)

	if !bytes.Equal(recovered, secret) {
		t.Errorf("round-trip failed:\ngot:  %x\nwant: %x", recovered, secret)
	}
}

// F273: test both spec-mandated lengths explicitly.
func TestSplit128BitSecret(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 16)
	groups, err := Split(secret, nil, WithIterationExponent(0))
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := Combine(groups[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)
	if !bytes.Equal(recovered, secret) {
		t.Error("128-bit round-trip failed")
	}
}

func TestSplit256BitSecret(t *testing.T) {
	secret := bytes.Repeat([]byte{0xCD}, 32)
	groups, err := Split(secret, nil, WithIterationExponent(0))
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := Combine(groups[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)
	if !bytes.Equal(recovered, secret) {
		t.Error("256-bit round-trip failed")
	}
}

func TestRoundTripMultiGroup(t *testing.T) {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	groups, err := Split(secret, nil,
		WithGroupThreshold(2),
		WithGroups([]Group{
			{Threshold: 2, Count: 3},
			{Threshold: 2, Count: 3},
			{Threshold: 1, Count: 1},
		}),
		WithIterationExponent(0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 3 {
		t.Fatalf("expected 3 groups, got %d", len(groups))
	}

	// Use shares from group 0 (2 of 3) and group 2 (1 of 1).
	combined := []string{groups[0][0], groups[0][1], groups[2][0]}
	recovered, err := Combine(combined, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)

	if !bytes.Equal(recovered, secret) {
		t.Error("multi-group round-trip failed")
	}
}

func TestRoundTripAllSecretLengths(t *testing.T) {
	// Test all valid even lengths from 16 to 64.
	for length := 16; length <= 64; length += 2 {
		t.Run(strconv.Itoa(length), func(t *testing.T) {
			secret := make([]byte, length)
			if _, err := rand.Read(secret); err != nil {
				t.Fatal(err)
			}
			groups, err := Split(secret, nil, WithIterationExponent(0))
			if err != nil {
				t.Fatalf("Split failed for length %d: %v", length, err)
			}
			recovered, err := Combine(groups[0], nil)
			if err != nil {
				t.Fatalf("Combine failed for length %d: %v", length, err)
			}
			defer ZeroBytes(recovered)
			if !bytes.Equal(recovered, secret) {
				t.Errorf("round-trip failed for length %d", length)
			}
		})
	}
}

// --- Input Validation Tests ---

func TestSplitValidation(t *testing.T) {
	secret16 := bytes.Repeat([]byte{0x42}, 16)

	tests := []struct {
		name    string
		secret  []byte
		pass    []byte
		opts    []Option
		wantErr error
	}{
		{"secret too short", bytes.Repeat([]byte{1}, 14), nil, nil, ErrInvalidSecret},
		{"secret odd length", bytes.Repeat([]byte{1}, 17), nil, nil, ErrInvalidSecret},
		{"secret too long", bytes.Repeat([]byte{1}, 66), nil, nil, ErrInvalidSecret},
		{"passphrase non-ASCII", secret16, []byte{0x7F}, nil, ErrInvalidPassphrase},    // F165: DEL
		{"passphrase control char", secret16, []byte{0x01}, nil, ErrInvalidPassphrase},
		{"passphrase UTF-8 multi", secret16, []byte{0xC0, 0x80}, nil, ErrInvalidPassphrase}, // F207
		{"iteration exponent negative", secret16, nil, []Option{WithIterationExponent(-1)}, ErrInvalidShares},
		{"iteration exponent too high", secret16, nil, []Option{WithIterationExponent(16)}, ErrInvalidShares},
		{"no groups", secret16, nil, []Option{WithGroups(nil)}, ErrInvalidShares},
		{"too many groups", secret16, nil, []Option{WithGroups(make([]Group, 17))}, ErrInvalidShares},
		{"group threshold 0", secret16, nil, []Option{WithGroupThreshold(0)}, ErrInvalidShares},
		{"group threshold exceeds count", secret16, nil, []Option{
			WithGroupThreshold(3),
			WithGroups([]Group{{1, 1}, {1, 1}}),
		}, ErrInvalidShares},
		{"member threshold 0", secret16, nil, []Option{
			WithGroups([]Group{{0, 1}}),
		}, ErrInvalidShares},
		{"member threshold > count", secret16, nil, []Option{
			WithGroups([]Group{{3, 2}}),
		}, ErrInvalidShares},
		{"member count > 16", secret16, nil, []Option{
			WithGroups([]Group{{2, 17}}),
		}, ErrInvalidShares},
		{"threshold 1 count > 1", secret16, nil, []Option{
			WithGroups([]Group{{1, 3}}),
		}, ErrInvalidShares}, // F16
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Split(tt.secret, tt.pass, tt.opts...)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestCombineValidation(t *testing.T) {
	t.Run("empty mnemonics", func(t *testing.T) {
		_, err := Combine(nil, nil)
		if !errors.Is(err, ErrInvalidMnemonic) {
			t.Errorf("expected ErrInvalidMnemonic, got %v", err)
		}
	})

	t.Run("invalid passphrase", func(t *testing.T) {
		// Need at least one valid mnemonic to get past nil check.
		secret := bytes.Repeat([]byte{0x42}, 16)
		groups, err := Split(secret, nil, WithIterationExponent(0))
		if err != nil {
			t.Fatal(err)
		}
		_, err = Combine(groups[0], []byte{0x00})
		if !errors.Is(err, ErrInvalidPassphrase) {
			t.Errorf("expected ErrInvalidPassphrase, got %v", err)
		}
	})
}

// --- Entropy Verification Tests ---

func TestSplitNonDeterministic(t *testing.T) {
	// F208: each Split call produces different shares.
	secret := bytes.Repeat([]byte{0x42}, 16)

	groups1, err := Split(secret, nil, WithIterationExponent(0))
	if err != nil {
		t.Fatal(err)
	}
	groups2, err := Split(secret, nil, WithIterationExponent(0))
	if err != nil {
		t.Fatal(err)
	}

	if groups1[0][0] == groups2[0][0] {
		t.Error("two Split calls produced identical mnemonics; expected different due to random identifier")
	}
}

func TestSplitDoesNotModifySecret(t *testing.T) {
	// F191: Split must not modify the caller's secret slice.
	secret := bytes.Repeat([]byte{0x42}, 16)
	original := make([]byte, len(secret))
	copy(original, secret)

	_, err := Split(secret, nil, WithIterationExponent(0))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secret, original) {
		t.Error("Split modified the input secret")
	}
}

// --- Concurrent Safety Tests (F189, F190) ---

func TestConcurrentSplit(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 16)
	var wg sync.WaitGroup
	errCh := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			groups, err := Split(secret, nil, WithIterationExponent(0))
			if err != nil {
				errCh <- err
				return
			}
			recovered, err := Combine(groups[0], nil)
			if err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(recovered, secret) {
				errCh <- errors.New("round-trip mismatch in concurrent test")
			}
			ZeroBytes(recovered)
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// --- Encode/Decode Round-Trip Tests ---

// F210: every share produced by Split round-trips through encode/decode.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	groups, err := Split(secret, nil,
		WithGroupThreshold(2),
		WithGroups([]Group{
			{Threshold: 2, Count: 3},
			{Threshold: 1, Count: 1},
		}),
		WithIterationExponent(0),
	)
	if err != nil {
		t.Fatal(err)
	}

	for gi, group := range groups {
		for mi, mnemonic := range group {
			sd, err := decodeMnemonic(mnemonic)
			if err != nil {
				t.Fatalf("group %d share %d: decode failed: %v", gi, mi, err)
			}
			reencoded := encodeShare(sd)
			if reencoded != mnemonic {
				t.Errorf("group %d share %d: encode/decode round-trip mismatch", gi, mi)
			}
		}
	}
}

// F201: identifier encoding round-trip.
func TestIdentifierRoundTrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 16)

	// Run multiple times to test different random identifiers.
	for i := 0; i < 20; i++ {
		groups, err := Split(secret, nil, WithIterationExponent(0))
		if err != nil {
			t.Fatal(err)
		}

		sd, err := decodeMnemonic(groups[0][0])
		if err != nil {
			t.Fatal(err)
		}

		if sd.identifier < 0 || sd.identifier >= (1<<idLengthBits) {
			t.Errorf("identifier %d out of 15-bit range", sd.identifier)
		}
	}
}

// --- Shuffled Order Test (F202) ---

func TestShuffledMnemonicOrder(t *testing.T) {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	groups, err := Split(secret, nil,
		WithGroups([]Group{{Threshold: 3, Count: 5}}),
		WithIterationExponent(0),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Take first 3 shares and reverse their order.
	reversed := []string{groups[0][2], groups[0][1], groups[0][0]}
	recovered, err := Combine(reversed, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)

	if !bytes.Equal(recovered, secret) {
		t.Error("shuffled order recovery failed")
	}
}

// --- Max Configuration Test (F200) ---

func TestMaxConfiguration16of16(t *testing.T) {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	// 1 group of 16-of-16.
	groups, err := Split(secret, nil,
		WithGroups([]Group{{Threshold: 16, Count: 16}}),
		WithIterationExponent(0),
	)
	if err != nil {
		t.Fatal(err)
	}

	if len(groups[0]) != 16 {
		t.Fatalf("expected 16 mnemonics, got %d", len(groups[0]))
	}

	recovered, err := Combine(groups[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)

	if !bytes.Equal(recovered, secret) {
		t.Error("16-of-16 round-trip failed")
	}
}

// --- First Two Words Property (F274) ---

func TestFirstTwoWordsSame(t *testing.T) {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	groups, err := Split(secret, nil,
		WithGroups([]Group{{Threshold: 3, Count: 5}}),
		WithIterationExponent(0),
	)
	if err != nil {
		t.Fatal(err)
	}

	// All shares from one group should have the same first two words.
	firstTwo := strings.Join(strings.Fields(groups[0][0])[:2], " ")
	for i := 1; i < len(groups[0]); i++ {
		ft := strings.Join(strings.Fields(groups[0][i])[:2], " ")
		if ft != firstTwo {
			t.Errorf("share %d has different first two words: %q vs %q", i, ft, firstTwo)
		}
	}
}

// --- Wordlist Tests (F278) ---

func TestWordlistProperties(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		if len(wordList) != 1024 {
			t.Errorf("wordlist has %d entries, expected 1024", len(wordList))
		}
	})

	t.Run("sorted", func(t *testing.T) {
		for i := 1; i < len(wordList); i++ {
			if wordList[i] <= wordList[i-1] {
				t.Errorf("wordlist not sorted at index %d: %q <= %q", i, wordList[i], wordList[i-1])
			}
		}
	})

	t.Run("length 4-8 chars", func(t *testing.T) {
		for i, w := range wordList {
			if len(w) < 4 || len(w) > 8 {
				t.Errorf("word %d (%q) has length %d, expected 4-8", i, w, len(w))
			}
		}
	})

	t.Run("unique 4-char prefix", func(t *testing.T) {
		prefixes := make(map[string]int)
		for i, w := range wordList {
			prefix := w[:4]
			if prev, ok := prefixes[prefix]; ok {
				t.Errorf("words %d (%q) and %d (%q) share 4-char prefix %q", prev, wordList[prev], i, w, prefix)
			}
			prefixes[prefix] = i
		}
	})
}

// --- Mnemonic Decode Edge Cases ---

func TestDecodeTooShort(t *testing.T) {
	// 19 words is too short (minimum is 20).
	words := make([]string, 19)
	for i := range words {
		words[i] = wordList[0]
	}
	_, err := decodeMnemonic(strings.Join(words, " "))
	if !errors.Is(err, ErrInvalidMnemonic) {
		t.Errorf("expected ErrInvalidMnemonic, got %v", err)
	}
}

func TestDecodeUnknownWord(t *testing.T) {
	_, err := decodeMnemonic("zzzznotaword " + strings.Repeat(wordList[0]+" ", 19))
	if !errors.Is(err, ErrInvalidMnemonic) {
		t.Errorf("expected ErrInvalidMnemonic, got %v", err)
	}
}

// --- All-Zero Secret Test (F159) ---

func TestAllZeroSecret(t *testing.T) {
	secret := make([]byte, 16) // all zeros
	groups, err := Split(secret, nil, WithIterationExponent(0))
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := Combine(groups[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)
	if !bytes.Equal(recovered, secret) {
		t.Error("all-zero secret round-trip failed")
	}
}

// --- All-FF Secret Test (F186) ---

func TestAllFFSecret(t *testing.T) {
	secret := bytes.Repeat([]byte{0xFF}, 16)
	groups, err := Split(secret, nil, WithIterationExponent(0))
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := Combine(groups[0], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)
	if !bytes.Equal(recovered, secret) {
		t.Error("all-0xFF secret round-trip failed")
	}
}

// --- Wrong Passphrase Test (F178) ---

func TestWrongPassphraseProducesDifferentSecret(t *testing.T) {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	groups, err := Split(secret, []byte("correct"), WithIterationExponent(0))
	if err != nil {
		t.Fatal(err)
	}

	// Wrong passphrase should produce a different secret, NOT an error.
	wrong, err := Combine(groups[0], []byte("wrong"))
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(wrong)

	if bytes.Equal(wrong, secret) {
		t.Error("wrong passphrase produced the same secret")
	}
}

// --- WithExtendable Test ---

func TestExtendableFlag(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 16)

	for _, ext := range []bool{true, false} {
		t.Run(strconv.FormatBool(ext), func(t *testing.T) {
			groups, err := Split(secret, nil,
				WithExtendable(ext),
				WithIterationExponent(0),
			)
			if err != nil {
				t.Fatal(err)
			}

			sd, err := decodeMnemonic(groups[0][0])
			if err != nil {
				t.Fatal(err)
			}

			if sd.extendable != ext {
				t.Errorf("expected extendable=%v, got %v", ext, sd.extendable)
			}

			recovered, err := Combine(groups[0], nil)
			if err != nil {
				t.Fatal(err)
			}
			defer ZeroBytes(recovered)
			if !bytes.Equal(recovered, secret) {
				t.Errorf("round-trip failed with extendable=%v", ext)
			}
		})
	}
}

// --- Threshold Property Tests ---

func TestThresholdMinusOneFails(t *testing.T) {
	// F117: k-1 shares should fail.
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	groups, err := Split(secret, nil,
		WithGroups([]Group{{Threshold: 3, Count: 5}}),
		WithIterationExponent(0),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Try with only 2 of 3 required shares.
	twoShares := groups[0][:2]
	_, err = Combine(twoShares, nil)
	if err == nil {
		t.Error("expected error with insufficient shares")
	}
}

// --- Mix Shares from Different Splits (F160) ---

func TestMixSharesFromDifferentSplits(t *testing.T) {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	g1, err := Split(secret, nil,
		WithGroups([]Group{{Threshold: 2, Count: 3}}),
		WithIterationExponent(0),
	)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := Split(secret, nil,
		WithGroups([]Group{{Threshold: 2, Count: 3}}),
		WithIterationExponent(0),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Mix shares from two different Split calls.
	mixed := []string{g1[0][0], g2[0][1]}
	_, err = Combine(mixed, nil)
	if err == nil {
		t.Error("expected error when mixing shares from different splits")
	}
}

// --- secrets.json Round-Trip Tests (F108) ---

type secretEntry struct {
	Description      string `json:"description"`
	MasterSecret     string `json:"master_secret"`
	GroupThreshold   int    `json:"group_threshold"`
	MemberGroupParams []struct {
		MemberThreshold int `json:"member_threshold"`
		MemberCount     int `json:"member_count"`
	} `json:"member_group_params"`
}

func loadSecrets(t *testing.T) []secretEntry {
	t.Helper()
	data, err := os.ReadFile("testdata/secrets.json")
	if err != nil {
		t.Fatalf("reading secrets.json: %v", err)
	}
	var secrets []secretEntry
	if err := json.Unmarshal(data, &secrets); err != nil {
		t.Fatalf("parsing secrets.json: %v", err)
	}
	return secrets
}

func TestSecretsRoundTrip(t *testing.T) {
	secrets := loadSecrets(t)
	if len(secrets) == 0 {
		t.Fatal("no secrets loaded")
	}

	for _, s := range secrets {
		t.Run(s.Description, func(t *testing.T) {
			secret, err := hex.DecodeString(s.MasterSecret)
			if err != nil {
				t.Fatalf("invalid hex: %v", err)
			}

			groups := make([]Group, len(s.MemberGroupParams))
			for i, p := range s.MemberGroupParams {
				groups[i] = Group{Threshold: p.MemberThreshold, Count: p.MemberCount}
			}

			mnemonicGroups, err := Split(secret, nil,
				WithGroupThreshold(s.GroupThreshold),
				WithGroups(groups),
				WithIterationExponent(0),
				WithExtendable(false),
			)
			if err != nil {
				t.Fatalf("Split failed: %v", err)
			}

			// Collect the minimum shares needed: groupThreshold groups,
			// each with exactly memberThreshold shares.
			var combined []string
			groupsUsed := 0
			for gi, mg := range mnemonicGroups {
				if groupsUsed >= s.GroupThreshold {
					break
				}
				threshold := s.MemberGroupParams[gi].MemberThreshold
				combined = append(combined, mg[:threshold]...)
				groupsUsed++
			}

			recovered, err := Combine(combined, nil)
			if err != nil {
				t.Fatalf("Combine failed: %v", err)
			}
			defer ZeroBytes(recovered)

			if !bytes.Equal(recovered, secret) {
				t.Errorf("round-trip failed:\ngot:  %x\nwant: %x", recovered, secret)
			}
		})
	}
}

// --- Empty Secret Test (F158) ---

func TestSplitEmptySecret(t *testing.T) {
	_, err := Split(nil, nil)
	if !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("expected ErrInvalidSecret for nil secret, got %v", err)
	}
	_, err = Split([]byte{}, nil)
	if !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("expected ErrInvalidSecret for empty secret, got %v", err)
	}
}

// --- Excess Shares Test (F162) ---

func TestExcessSharesRejected(t *testing.T) {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	groups, err := Split(secret, nil,
		WithGroups([]Group{{Threshold: 2, Count: 5}}),
		WithIterationExponent(0),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Provide 3 shares when only 2 are required.
	threeShares := groups[0][:3]
	_, err = Combine(threeShares, nil)
	if err == nil {
		t.Error("expected error with excess shares (3 provided, 2 required)")
	}
	if !errors.Is(err, ErrInvalidShares) {
		t.Errorf("expected ErrInvalidShares, got %v", err)
	}
}

// --- Threshold Encoding Anti-Tamper Test (F264) ---

func TestThresholdEncodingAntiTamper(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 16)
	groups, err := Split(secret, nil,
		WithGroupThreshold(3),
		WithGroups([]Group{
			{Threshold: 2, Count: 3},
			{Threshold: 4, Count: 5},
			{Threshold: 1, Count: 1},
		}),
		WithIterationExponent(2),
		WithExtendable(false),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Decode a share from each group and verify thresholds round-trip correctly.
	for gi, mg := range groups {
		sd, err := decodeMnemonic(mg[0])
		if err != nil {
			t.Fatalf("group %d decode failed: %v", gi, err)
		}
		if sd.groupThreshold != 3 {
			t.Errorf("group %d: groupThreshold = %d, want 3", gi, sd.groupThreshold)
		}
		if sd.groupCount != 3 {
			t.Errorf("group %d: groupCount = %d, want 3", gi, sd.groupCount)
		}
		if sd.iterationExponent != 2 {
			t.Errorf("group %d: iterationExponent = %d, want 2", gi, sd.iterationExponent)
		}
		// Verify member thresholds match the group config.
		expectedMT := []int{2, 4, 1}
		if sd.memberThreshold != expectedMT[gi] {
			t.Errorf("group %d: memberThreshold = %d, want %d", gi, sd.memberThreshold, expectedMT[gi])
		}
	}
}

// --- Customization String Anti-Tamper Test (F266) ---

func TestCustomizationStringAntiTamper(t *testing.T) {
	// Verify the customization string constants match their expected byte values.
	origBytes := []byte(customizationStringOriginal)
	expected := []byte{0x73, 0x68, 0x61, 0x6D, 0x69, 0x72} // "shamir"
	if !bytes.Equal(origBytes, expected) {
		t.Errorf("customizationStringOriginal bytes mismatch:\ngot:  %x\nwant: %x", origBytes, expected)
	}

	extBytes := []byte(customizationStringExtendable)
	expectedExt := []byte{0x73, 0x68, 0x61, 0x6D, 0x69, 0x72, 0x5F, 0x65, 0x78, 0x74, 0x65, 0x6E, 0x64, 0x61, 0x62, 0x6C, 0x65}
	if !bytes.Equal(extBytes, expectedExt) {
		t.Errorf("customizationStringExtendable bytes mismatch:\ngot:  %x\nwant: %x", extBytes, expectedExt)
	}
}

// --- 16 Groups of 1-of-1 Test (F200) ---

func TestMaxConfiguration16GroupsOf1(t *testing.T) {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	// 16 groups of (1,1) with group threshold 16.
	groupCfg := make([]Group, 16)
	for i := range groupCfg {
		groupCfg[i] = Group{Threshold: 1, Count: 1}
	}

	groups, err := Split(secret, nil,
		WithGroupThreshold(16),
		WithGroups(groupCfg),
		WithIterationExponent(0),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 16 {
		t.Fatalf("expected 16 groups, got %d", len(groups))
	}

	// Collect one share from each group.
	var allShares []string
	for _, g := range groups {
		allShares = append(allShares, g[0])
	}

	recovered, err := Combine(allShares, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)

	if !bytes.Equal(recovered, secret) {
		t.Error("16-groups-of-1 round-trip failed")
	}
}

// --- Exhaustive Combination Test (F118) ---

func TestExhaustiveCombinations3of5(t *testing.T) {
	secret := make([]byte, 16)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}

	groups, err := Split(secret, nil,
		WithGroups([]Group{{Threshold: 3, Count: 5}}),
		WithIterationExponent(0),
	)
	if err != nil {
		t.Fatal(err)
	}
	shares := groups[0]

	// Test ALL C(5,3) = 10 combinations.
	count := 0
	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			for k := j + 1; k < 5; k++ {
				combo := []string{shares[i], shares[j], shares[k]}
				recovered, err := Combine(combo, nil)
				if err != nil {
					t.Fatalf("combination (%d,%d,%d) failed: %v", i, j, k, err)
				}
				if !bytes.Equal(recovered, secret) {
					t.Errorf("combination (%d,%d,%d) produced wrong secret", i, j, k)
				}
				ZeroBytes(recovered)
				count++
			}
		}
	}
	if count != 10 {
		t.Errorf("expected 10 combinations, tested %d", count)
	}
}

// --- WithRandom Determinism Test ---

func TestWithRandomDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 16)

	// Fixed random source: 256 bytes of deterministic data.
	// Must be enough for identifier (2) + outer splitSecret + inner splitSecret.
	seed := make([]byte, 256)
	for i := range seed {
		seed[i] = byte(i)
	}

	groups1, err := Split(secret, nil,
		WithGroups([]Group{{Threshold: 2, Count: 3}}),
		WithIterationExponent(0),
		WithRandom(bytes.NewReader(append([]byte{}, seed...))),
	)
	if err != nil {
		t.Fatal(err)
	}

	groups2, err := Split(secret, nil,
		WithGroups([]Group{{Threshold: 2, Count: 3}}),
		WithIterationExponent(0),
		WithRandom(bytes.NewReader(append([]byte{}, seed...))),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Same seed must produce identical mnemonics.
	for i := 0; i < len(groups1[0]); i++ {
		if groups1[0][i] != groups2[0][i] {
			t.Errorf("share %d differs with same random source:\n  got1: %s\n  got2: %s",
				i, groups1[0][i], groups2[0][i])
		}
	}

	// Verify the shares actually recover correctly.
	recovered, err := Combine(groups1[0][:2], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ZeroBytes(recovered)
	if !bytes.Equal(recovered, secret) {
		t.Error("deterministic round-trip failed")
	}
}

// --- Cross-Implementation Decode Verification ---
// Python-generated intermediate field values for decodeMnemonic.
// Generated via: PYTHONPATH=/tmp/python-shamir-mnemonic python3 -c "from shamir_mnemonic.share import Share; ..."

func TestDecodeCrossImpl(t *testing.T) {
	tests := []struct {
		mnemonic  string
		id        int
		ext       bool
		iterExp   int
		gi, gt, gc int
		mi, mt    int
		valueHex  string
	}{
		{
			mnemonic: "duckling enlarge academic academic agency result length solution fridge kidney coal piece deal husband erode duke ajar critical decision keyboard",
			id: 7945, ext: false, iterExp: 0,
			gi: 0, gt: 1, gc: 1, mi: 0, mt: 1,
			valueHex: "11bc609d21747c49ba78c0701293e417",
		},
		{
			mnemonic: "shadow pistol academic always adequate wildlife fancy gross oasis cylinder mustang wrist rescue view short owner flip making coding armed",
			id: 25653, ext: false, iterExp: 2,
			gi: 0, gt: 1, gc: 1, mi: 2, mt: 2,
			valueHex: "08fb14b66e692e25dfe2edf53289ed62",
		},
		{
			mnemonic: "theory painting academic academic armed sweater year military elder discuss acne wildlife boring employer fused large satoshi bundle carbon diagnose anatomy hamster leaves tracks paces beyond phantom capital marvel lips brave detect luck",
			id: 29172, ext: false, iterExp: 0,
			gi: 0, gt: 1, gc: 1, mi: 0, mt: 1,
			valueHex: "d772fee46424e100bec16d165f1fcc346d1e8d909da580f9f9f04ea5c788d212",
		},
		{
			mnemonic: "testify swimming academic academic column loyalty smear include exotic bedroom exotic wrist lobe cover grief golden smart junior estimate learn",
			id: 29019, ext: true, iterExp: 3,
			gi: 0, gt: 1, gc: 1, mi: 0, mt: 1,
			valueHex: "9e8773c7313b11d3bfe219291976433b",
		},
	}

	for i, tt := range tests {
		t.Run(strconv.Itoa(i+1), func(t *testing.T) {
			sd, err := decodeMnemonic(tt.mnemonic)
			if err != nil {
				t.Fatalf("decode failed: %v", err)
			}
			if sd.identifier != tt.id {
				t.Errorf("identifier: got %d, want %d", sd.identifier, tt.id)
			}
			if sd.extendable != tt.ext {
				t.Errorf("extendable: got %v, want %v", sd.extendable, tt.ext)
			}
			if sd.iterationExponent != tt.iterExp {
				t.Errorf("iterationExponent: got %d, want %d", sd.iterationExponent, tt.iterExp)
			}
			if sd.groupIndex != tt.gi {
				t.Errorf("groupIndex: got %d, want %d", sd.groupIndex, tt.gi)
			}
			if sd.groupThreshold != tt.gt {
				t.Errorf("groupThreshold: got %d, want %d", sd.groupThreshold, tt.gt)
			}
			if sd.groupCount != tt.gc {
				t.Errorf("groupCount: got %d, want %d", sd.groupCount, tt.gc)
			}
			if sd.memberIndex != tt.mi {
				t.Errorf("memberIndex: got %d, want %d", sd.memberIndex, tt.mi)
			}
			if sd.memberThreshold != tt.mt {
				t.Errorf("memberThreshold: got %d, want %d", sd.memberThreshold, tt.mt)
			}
			expectedValue, _ := hex.DecodeString(tt.valueHex)
			if !bytes.Equal(sd.value, expectedValue) {
				t.Errorf("value:\n  got:  %x\n  want: %x", sd.value, expectedValue)
			}
		})
	}
}

