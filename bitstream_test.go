// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

package slip39

import (
	"io"
	"testing"
)

// TestBitStreamWriteReadRoundTrip writes known values and reads them back.
func TestBitStreamWriteReadRoundTrip(t *testing.T) {
	// Write three 10-bit values (common for SLIP-0039 mnemonic words).
	w := newBitStreamWriter(30) // 3 * 10 bits
	w.Write(248, 10)            // "duckling" index
	w.Write(288, 10)            // "enlarge" index
	w.Write(0, 10)              // "academic" index

	r := newBitStreamReader(w.Bytes(), 30)
	v1, err := r.Read(10)
	if err != nil {
		t.Fatal(err)
	}
	if v1 != 248 {
		t.Fatalf("word 0: got %d, want 248", v1)
	}
	v2, err := r.Read(10)
	if err != nil {
		t.Fatal(err)
	}
	if v2 != 288 {
		t.Fatalf("word 1: got %d, want 288", v2)
	}
	v3, err := r.Read(10)
	if err != nil {
		t.Fatal(err)
	}
	if v3 != 0 {
		t.Fatalf("word 2: got %d, want 0", v3)
	}
}

// TestBitStreamSingleBit tests writing and reading a single bit.
func TestBitStreamSingleBit(t *testing.T) {
	w := newBitStreamWriter(1)
	w.Write(1, 1)
	r := newBitStreamReader(w.Bytes(), 1)
	v, err := r.Read(1)
	if err != nil {
		t.Fatal(err)
	}
	if v != 1 {
		t.Fatalf("got %d, want 1", v)
	}
}

// TestBitStreamExactByte tests writing and reading a full byte.
func TestBitStreamExactByte(t *testing.T) {
	w := newBitStreamWriter(8)
	w.Write(0xA5, 8)
	r := newBitStreamReader(w.Bytes(), 8)
	v, err := r.Read(8)
	if err != nil {
		t.Fatal(err)
	}
	if v != 0xA5 {
		t.Fatalf("got 0x%x, want 0xA5", v)
	}
}

// TestBitStreamMixedWidths tests writing values of different bit widths.
func TestBitStreamMixedWidths(t *testing.T) {
	// 15 + 1 + 4 + 4 + 4 + 4 + 4 + 4 = 40 bits = 4 words of header (SLIP-0039)
	w := newBitStreamWriter(40)
	w.Write(7945, 15)  // identifier
	w.Write(0, 1)      // extendable flag
	w.Write(0, 4)      // iteration exponent
	w.Write(0, 4)      // group threshold - 1
	w.Write(0, 4)      // group count - 1
	w.Write(0, 4)      // member threshold - 1
	w.Write(0, 4)      // member index
	w.Write(0, 4)      // reserved (share value start)

	r := newBitStreamReader(w.Bytes(), 40)
	id, err := r.Read(15)
	if err != nil {
		t.Fatal(err)
	}
	if id != 7945 {
		t.Fatalf("identifier: got %d, want 7945", id)
	}
}

// TestBitStreamReadPastEnd verifies EOF behavior.
func TestBitStreamReadPastEnd(t *testing.T) {
	w := newBitStreamWriter(10)
	w.Write(100, 10)
	r := newBitStreamReader(w.Bytes(), 10)
	_, err := r.Read(10) // consume all
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.Read(1)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}
}

// TestBitStreamRemaining verifies the Remaining method.
func TestBitStreamRemaining(t *testing.T) {
	r := newBitStreamReader([]byte{0xFF, 0xFF}, 16)
	if r.Remaining() != 16 {
		t.Fatalf("initial remaining: got %d, want 16", r.Remaining())
	}
	r.Read(10)
	if r.Remaining() != 6 {
		t.Fatalf("after reading 10: got %d, want 6", r.Remaining())
	}
}

// TestBitStreamWriteCountPanic verifies panic on invalid count.
func TestBitStreamWriteCountPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for count=0, got none")
		}
	}()
	w := newBitStreamWriter(10)
	w.Write(0, 0) // should panic
}

// TestBitStreamWriteCountOver64Panic verifies panic on count > 64.
func TestBitStreamWriteCountOver64Panic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for count=65, got none")
		}
	}()
	w := newBitStreamWriter(65)
	w.Write(0, 65) // should panic
}

// TestBitStreamReadCountPanic verifies panic on invalid count.
func TestBitStreamReadCountPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for count=0, got none")
		}
	}()
	r := newBitStreamReader([]byte{0}, 8)
	r.Read(0) // should panic
}

// TestBitStreamFull64Bit verifies 64-bit write/read round-trip.
func TestBitStreamFull64Bit(t *testing.T) {
	w := newBitStreamWriter(64)
	w.Write(0xDEADBEEFCAFEBABE, 64)
	r := newBitStreamReader(w.Bytes(), 64)
	v, err := r.Read(64)
	if err != nil {
		t.Fatal(err)
	}
	if v != 0xDEADBEEFCAFEBABE {
		t.Fatalf("got 0x%x, want 0xDEADBEEFCAFEBABE", v)
	}
}

// TestBitStreamEmpty verifies reading from an empty stream fails.
func TestBitStreamEmpty(t *testing.T) {
	r := newBitStreamReader(nil, 0)
	_, err := r.Read(1)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("expected io.ErrUnexpectedEOF, got %v", err)
	}
	if r.Remaining() != 0 {
		t.Fatalf("remaining: got %d, want 0", r.Remaining())
	}
}

// TestBitStreamWordBoundaries verifies 10-bit word packing across byte boundaries.
func TestBitStreamWordBoundaries(t *testing.T) {
	// 20 words = 200 bits (SLIP-0039 minimum mnemonic length).
	words := [20]uint64{
		248, 288, 0, 42, 1023, 512, 0, 100, 999, 1,
		500, 750, 300, 600, 123, 456, 789, 111, 222, 333,
	}
	w := newBitStreamWriter(200)
	for _, word := range words {
		w.Write(word, 10)
	}
	r := newBitStreamReader(w.Bytes(), 200)
	for i, expected := range words {
		got, err := r.Read(10)
		if err != nil {
			t.Fatalf("word %d: %v", i, err)
		}
		if got != expected {
			t.Fatalf("word %d: got %d, want %d", i, got, expected)
		}
	}
}

// TestBitStreamByteRoundTrip verifies byte-level write/read (8-bit values).
func TestBitStreamByteRoundTrip(t *testing.T) {
	data := []byte{0x00, 0xFF, 0xA5, 0x5A, 0x01, 0x80, 0x7F, 0xFE}
	w := newBitStreamWriter(len(data) * 8)
	for _, b := range data {
		w.Write(uint64(b), 8)
	}
	r := newBitStreamReader(w.Bytes(), len(data)*8)
	for i, expected := range data {
		got, err := r.Read(8)
		if err != nil {
			t.Fatalf("byte %d: %v", i, err)
		}
		if byte(got) != expected {
			t.Fatalf("byte %d: got 0x%x, want 0x%x", i, got, expected)
		}
	}
}
