// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT
//
// BitStream provides bit-level packing and unpacking for SLIP-0039 mnemonic encoding.
// Inspired by the C# Slip39 implementation (lontivero/Slip39).
// Replaces math/big for 10-bit word encoding, eliminating big.Int limb zeroing concerns.
//
// All operations use uint64 exclusively. Do NOT change to int64 (arithmetic
// shift on signed types would sign-extend, corrupting high bits).

package slip39

import "io"

// bitStreamWriter packs arbitrary-width values into a byte buffer, MSB first.
type bitStreamWriter struct {
	buf    []byte
	bitPos int // next bit position to write (0 = MSB of buf[0])
}

// newBitStreamWriter creates a writer pre-allocated for exactly totalBits.
func newBitStreamWriter(totalBits int) *bitStreamWriter {
	byteLen := (totalBits + 7) / 8
	return &bitStreamWriter{
		buf: make([]byte, byteLen),
	}
}

// Write writes the lowest count bits of value into the stream, MSB first.
// count must be in [1, 64].
func (w *bitStreamWriter) Write(value uint64, count int) {
	if count <= 0 || count > 64 {
		panic("slip39: BitStream Write count must be in [1, 64]")
	}
	for i := count - 1; i >= 0; i-- {
		byteIdx := w.bitPos / 8
		bitIdx := uint(7 - (w.bitPos % 8))
		if (value>>i)&1 != 0 {
			w.buf[byteIdx] |= byte(1) << bitIdx
		}
		w.bitPos++
	}
}

// Bytes returns the underlying buffer. The caller must not modify it.
func (w *bitStreamWriter) Bytes() []byte {
	return w.buf
}

// bitStreamReader unpacks arbitrary-width values from a byte buffer, MSB first.
type bitStreamReader struct {
	buf    []byte
	bitPos int
	total  int // total bits available
}

// newBitStreamReader creates a reader over the given bytes with totalBits readable.
func newBitStreamReader(data []byte, totalBits int) *bitStreamReader {
	return &bitStreamReader{
		buf:   data,
		total: totalBits,
	}
}

// Read reads count bits from the stream and returns them as a uint64.
// Returns io.ErrUnexpectedEOF if not enough bits remain.
// count must be in [1, 64].
func (r *bitStreamReader) Read(count int) (uint64, error) {
	if count <= 0 || count > 64 {
		panic("slip39: BitStream Read count must be in [1, 64]")
	}
	if r.bitPos+count > r.total {
		return 0, io.ErrUnexpectedEOF
	}
	var value uint64
	for i := count - 1; i >= 0; i-- {
		byteIdx := r.bitPos / 8
		bitIdx := uint(7 - (r.bitPos % 8))
		if (r.buf[byteIdx]>>bitIdx)&1 != 0 {
			value |= uint64(1) << uint(i)
		}
		r.bitPos++
	}
	return value, nil
}

// Remaining returns the number of unread bits.
func (r *bitStreamReader) Remaining() int {
	return r.total - r.bitPos
}
