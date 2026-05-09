// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

// Mnemonic encoding and decoding for SLIP-0039 shares.
// Uses BitStream for 10-bit word packing, inspired by C# Slip39 (lontivero/Slip39).
// Wordlist loaded via go:embed with SHA256 integrity check at init.

package slip39

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// radixBits is the number of bits per word index.
	radixBits = 10

	// idLengthBits is the length of the random identifier in bits.
	idLengthBits = 15

	// extendableFlagLengthBits is the length of the extendable backup flag in bits.
	extendableFlagLengthBits = 1

	// iterationExpLengthBits is the length of the iteration exponent in bits.
	iterationExpLengthBits = 4

	// idExpLengthWords is the length of (identifier + extendable flag + iteration exponent) in words.
	// 15 + 1 + 4 = 20 bits = 2 words of 10 bits each.
	idExpLengthWords = 2

	// metadataLengthWords is the total metadata word count (id/exp + share params + checksum).
	// 2 (id/exp) + 2 (share params) + 3 (RS1024 checksum) = 7.
	metadataLengthWords = idExpLengthWords + 2 + checksumLengthWords

	// minMnemonicLengthWords is the minimum mnemonic length in words.
	// metadata (7) + value for 128-bit secret (13 words) = 20.
	minMnemonicLengthWords = 20

	// minStrengthBits is the minimum secret entropy in bits.
	minStrengthBits = 128

	// maxGroupCount is the maximum number of groups (4-bit field).
	maxGroupCount = 16
)

// wordlistExpectedSHA256 is the expected SHA256 hash of wordlist.txt.
// Verified against the SatoshiLabs canonical source.
const wordlistExpectedSHA256 = "bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3"

//go:embed wordlist.txt
var wordlistRaw string

// wordList is the ordered array of 1024 SLIP-0039 words.
var wordList [1024]string

// wordMap maps each word to its 0-based index.
var wordMap map[string]int

func init() {
	// Verify SHA256 integrity before parsing.
	hash := sha256.Sum256([]byte(wordlistRaw))
	actual := hex.EncodeToString(hash[:])
	if actual != wordlistExpectedSHA256 {
		panic("slip39: wordlist SHA256 mismatch: got " + actual + ", want " + wordlistExpectedSHA256)
	}

	// Parse words with TrimSpace to handle platform-specific line endings.
	lines := strings.Split(wordlistRaw, "\n")
	idx := 0
	for _, line := range lines {
		w := strings.TrimSpace(line)
		if w == "" {
			continue
		}
		if idx >= 1024 {
			panic("slip39: wordlist contains more than 1024 words")
		}
		wordList[idx] = w
		idx++
	}
	if idx != 1024 {
		panic(fmt.Sprintf("slip39: wordlist contains %d words, expected 1024", idx))
	}

	// Build reverse map and check for duplicates and empty entries.
	wordMap = make(map[string]int, 1024)
	for i, w := range wordList {
		if w == "" {
			panic(fmt.Sprintf("slip39: wordlist entry %d is empty", i))
		}
		if _, exists := wordMap[w]; exists {
			panic("slip39: duplicate word in wordlist: " + w)
		}
		wordMap[w] = i
	}
	if len(wordMap) != 1024 {
		panic(fmt.Sprintf("slip39: wordlist map has %d entries, expected 1024", len(wordMap)))
	}
}

// shareData holds the parsed fields from a mnemonic share.
type shareData struct {
	identifier        int
	extendable        bool
	iterationExponent int
	groupIndex        int
	groupThreshold    int // stored as actual value (encoded as -1 in mnemonic)
	groupCount        int // stored as actual value (encoded as -1 in mnemonic)
	memberIndex       int
	memberThreshold   int // stored as actual value (encoded as -1 in mnemonic)
	value             []byte
}

// customizationString returns the RS1024 customization string for the given extendable mode.
func customizationString(extendable bool) []byte {
	if extendable {
		return []byte(customizationStringExtendable)
	}
	return []byte(customizationStringOriginal)
}

// encodeShare converts a shareData to a mnemonic string.
// The mnemonic format is: id/exp (2 words) + share params (2 words) + value (N words) + checksum (3 words).
func encodeShare(s *shareData) string {
	// Calculate value word count: ceil(len(value) * 8 / 10).
	valueBits := len(s.value) * 8
	valueWordCount := (valueBits + radixBits - 1) / radixBits
	totalWords := idExpLengthWords + 2 + valueWordCount + checksumLengthWords

	// Encode id/exp: identifier (15 bits) + extendable (1 bit) + iterationExponent (4 bits) = 20 bits.
	idExpInt := uint64(s.identifier) << (extendableFlagLengthBits + iterationExpLengthBits)
	if s.extendable {
		idExpInt |= uint64(1) << uint(iterationExpLengthBits)
	}
	idExpInt |= uint64(s.iterationExponent)

	// Encode share params: 5 x 4-bit fields = 20 bits.
	// groupIndex, groupThreshold-1, groupCount-1, memberIndex, memberThreshold-1.
	shareParamsInt := uint64(s.groupIndex)
	shareParamsInt <<= 4
	shareParamsInt |= uint64(s.groupThreshold - 1)
	shareParamsInt <<= 4
	shareParamsInt |= uint64(s.groupCount - 1)
	shareParamsInt <<= 4
	shareParamsInt |= uint64(s.memberIndex)
	shareParamsInt <<= 4
	shareParamsInt |= uint64(s.memberThreshold - 1)

	// Write header + value to BitStream, then extract as 10-bit word indices.
	// Only the data portion (no checksum) goes through BitStream.
	dataBits := (idExpLengthWords + 2 + valueWordCount) * radixBits
	w := newBitStreamWriter(dataBits)
	w.Write(idExpInt, 20)    // id/exp: 20 bits = 2 words
	w.Write(shareParamsInt, 20) // share params: 20 bits = 2 words

	// Value: padding zeros first (MSBs), then value bytes.
	// Padding bits are explicit; the writer buffer was zero-initialized at construction.
	paddingBits := valueWordCount*radixBits - valueBits
	if paddingBits > 0 {
		w.Write(0, paddingBits) // explicit padding zeros
	}
	for _, b := range s.value {
		w.Write(uint64(b), 8)
	}

	// Read back as 10-bit word indices for checksum computation.
	dataWordCount := idExpLengthWords + 2 + valueWordCount
	shareDataWords := make([]int, dataWordCount)
	r := newBitStreamReader(w.Bytes(), dataBits)
	defer ZeroBytes(w.Bytes()) // Zero BitStream buffer containing share value.
	for i := range shareDataWords {
		v, err := r.Read(radixBits)
		if err != nil {
			panic("slip39: BitStream read failed during encode: " + err.Error())
		}
		shareDataWords[i] = int(v)
	}

	// Compute RS1024 checksum.
	cs := customizationString(s.extendable)
	checksum := rs1024CreateChecksum(shareDataWords, cs)

	// Build mnemonic from word indices.
	allWords := make([]int, totalWords)
	copy(allWords, shareDataWords)
	for i := 0; i < checksumLengthWords; i++ {
		allWords[len(shareDataWords)+i] = checksum[i]
	}

	// Pre-allocate strings.Builder for single allocation.
	var sb strings.Builder
	sb.Grow(totalWords * 9) // average word ~8 chars + space
	for i, idx := range allWords {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(wordList[idx])
	}

	return sb.String()
}

// decodeMnemonic parses a mnemonic string into a shareData.
// Returns an error if the mnemonic is invalid (checksum, padding, length, etc.).
func decodeMnemonic(mnemonic string) (*shareData, error) {
	words := strings.Fields(mnemonic)
	if len(words) < minMnemonicLengthWords {
		return nil, fmt.Errorf("%w: mnemonic must be at least %d words, got %d",
			ErrInvalidMnemonic, minMnemonicLengthWords, len(words))
	}

	// Convert words to indices.
	indices := make([]int, len(words))
	for i, w := range words {
		idx, ok := wordMap[w]
		if !ok {
			return nil, fmt.Errorf("%w: unknown word %q at position %d",
				ErrInvalidMnemonic, w, i)
		}
		indices[i] = idx
	}

	// Validate padding length per spec.
	valueWordCount := len(words) - metadataLengthWords
	paddingLen := (radixBits * valueWordCount) % 16
	if paddingLen > 8 {
		return nil, fmt.Errorf("%w: invalid mnemonic length", ErrInvalidMnemonic)
	}

	// Parse id/exp from first 2 words.
	idExpInt := indices[0]*1024 + indices[1] // 2 words = 20 bits
	identifier := idExpInt >> (extendableFlagLengthBits + iterationExpLengthBits)
	extendable := (idExpInt>>iterationExpLengthBits)&1 == 1
	iterationExponent := idExpInt & ((1 << uint(iterationExpLengthBits)) - 1)

	// Verify RS1024 checksum (before parsing further fields).
	cs := customizationString(extendable)
	if !rs1024VerifyChecksum(indices, cs) {
		return nil, fmt.Errorf("%w: checksum verification failed for %q",
			ErrInvalidChecksum, strings.Join(words[:idExpLengthWords+2], " "))
	}

	// Parse share params from words 2-3 (20 bits = 5 x 4-bit fields).
	shareParamsInt := indices[2]*1024 + indices[3]
	memberThreshold := (shareParamsInt & 0xF) + 1
	shareParamsInt >>= 4
	memberIndex := shareParamsInt & 0xF
	shareParamsInt >>= 4
	groupCount := (shareParamsInt & 0xF) + 1
	shareParamsInt >>= 4
	groupThreshold := (shareParamsInt & 0xF) + 1
	shareParamsInt >>= 4
	groupIndex := shareParamsInt & 0xF

	// Validate group threshold <= group count.
	if groupThreshold > groupCount {
		return nil, fmt.Errorf("%w: group threshold (%d) exceeds group count (%d)",
			ErrInvalidMnemonic, groupThreshold, groupCount)
	}

	// Extract value bytes from words 4..(len-3).
	valueWords := indices[idExpLengthWords+2 : len(indices)-checksumLengthWords]
	valueBitCount := radixBits*len(valueWords) - paddingLen
	valueByteCount := valueBitCount / 8

	// Decoded share value must be at least 128 bits (16 bytes) per spec.
	if valueByteCount < minStrengthBits/8 {
		return nil, fmt.Errorf("%w: share value too short (%d bytes, minimum %d)",
			ErrInvalidMnemonic, valueByteCount, minStrengthBits/8)
	}
	// Share value must be even length for Feistel cipher (splits into halves).
	// The padding formula guarantees this (valueBitCount is always a multiple of 16),
	// but verify explicitly to prevent panics if the formula is ever modified.
	if valueByteCount%2 != 0 {
		return nil, fmt.Errorf("%w: share value length must be even, got %d",
			ErrInvalidMnemonic, valueByteCount)
	}

	// Decode value using BitStream.
	// First, pack value words into a byte buffer.
	totalValueBits := len(valueWords) * radixBits
	bw := newBitStreamWriter(totalValueBits)
	for _, wi := range valueWords {
		bw.Write(uint64(wi), radixBits)
	}
	defer ZeroBytes(bw.Bytes()) // Zero BitStream buffer containing share value.

	// Read and verify padding bits are zero.
	br := newBitStreamReader(bw.Bytes(), totalValueBits)
	if paddingLen > 0 {
		pad, err := br.Read(paddingLen)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read padding: %v", ErrInvalidMnemonic, err)
		}
		if pad != 0 {
			return nil, fmt.Errorf("%w: non-zero padding bits", ErrInvalidMnemonic)
		}
	}

	// Read value bytes.
	value := make([]byte, valueByteCount)
	for i := range value {
		b, err := br.Read(8)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to read value byte %d: %v", ErrInvalidMnemonic, i, err)
		}
		value[i] = byte(b)
	}

	return &shareData{
		identifier:        identifier,
		extendable:        extendable,
		iterationExponent: iterationExponent,
		groupIndex:        groupIndex,
		groupThreshold:    groupThreshold,
		groupCount:        groupCount,
		memberIndex:       memberIndex,
		memberThreshold:   memberThreshold,
		value:             value,
	}, nil
}
