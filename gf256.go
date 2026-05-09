// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT
//
// Bitsliced GF(2^8) arithmetic reduced by x^8 + x^4 + x^3 + x + 1 (AES polynomial 0x11B).
//
// Translated from Trezor firmware crypto/shamir.c by Daan Sprenkels.
// All operations are constant-time: zero data-dependent branches, zero table lookups.
// Uses [8]uint64 arrays to process up to 64 bytes in parallel (one bit-plane per element).

package slip39

// maxSecretLen is the maximum secret length in bytes supported by the bitsliced
// representation. Each uint64 holds 64 bit positions, supporting up to 64 bytes.
// The SLIP-0039 spec allows 128-512 bit secrets (16-64 bytes).
const maxSecretLen = 64

// bitslice converts a byte slice into a bitsliced representation.
// Each element r[i] holds bit i of every input byte packed into bit positions 0..len(x)-1.
// r is zeroed first, so len(x) < 64 is safe (high positions remain zero).
func bitslice(r *[8]uint64, x []byte) {
	*r = [8]uint64{} // Zero first, ensures high bits clean on re-use.
	for arrIdx := 0; arrIdx < len(x); arrIdx++ {
		cur := uint64(x[arrIdx])
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			r[bitIdx] |= ((cur >> bitIdx) & 1) << arrIdx
		}
	}
}

// unbitslice converts a bitsliced representation back to bytes.
// Only len(r) bytes are written, regardless of how many bit positions are populated.
func unbitslice(r []byte, x *[8]uint64) {
	for i := range r {
		r[i] = 0
	}
	for bitIdx := 0; bitIdx < 8; bitIdx++ {
		cur := x[bitIdx]
		for arrIdx := 0; arrIdx < len(r); arrIdx++ {
			r[arrIdx] |= byte(((cur >> arrIdx) & 1) << bitIdx)
		}
	}
}

// bitsliceSetAll broadcasts a single byte value to all 64 bit positions.
// Used to create a constant across the entire bit-parallel width.
func bitsliceSetAll(r *[8]uint64, x byte) {
	for idx := 0; idx < 8; idx++ {
		r[idx] = -uint64((x >> idx) & 1) // Two's complement, all 64 bits set or clear.
	}
}

// gf256Add XORs x into r in-place. Addition in GF(2^8) is XOR.
func gf256Add(r *[8]uint64, x *[8]uint64) {
	for idx := 0; idx < 8; idx++ {
		r[idx] ^= x[idx]
	}
}

// gf256Mul multiplies two bitsliced polynomials in GF(2^8) using Russian Peasant
// multiplication, reduced by x^8 + x^4 + x^3 + x + 1.
//
// r and a may overlap (r==a is safe). r and b MUST NOT overlap; overlapping
// r and b produces an incorrect result. Use gf256Square for squaring.
func gf256Mul(r *[8]uint64, a *[8]uint64, b *[8]uint64) {
	// Copy a to a2 so we can modify it during reduction.
	// This is the mechanical safety for r==a aliasing.
	a2 := *a

	r[0] = a2[0] & b[0]
	r[1] = a2[1] & b[0]
	r[2] = a2[2] & b[0]
	r[3] = a2[3] & b[0]
	r[4] = a2[4] & b[0]
	r[5] = a2[5] & b[0]
	r[6] = a2[6] & b[0]
	r[7] = a2[7] & b[0]
	a2[0] ^= a2[7] // reduce
	a2[2] ^= a2[7]
	a2[3] ^= a2[7]

	r[0] ^= a2[7] & b[1]
	r[1] ^= a2[0] & b[1]
	r[2] ^= a2[1] & b[1]
	r[3] ^= a2[2] & b[1]
	r[4] ^= a2[3] & b[1]
	r[5] ^= a2[4] & b[1]
	r[6] ^= a2[5] & b[1]
	r[7] ^= a2[6] & b[1]
	a2[7] ^= a2[6] // reduce
	a2[1] ^= a2[6]
	a2[2] ^= a2[6]

	r[0] ^= a2[6] & b[2]
	r[1] ^= a2[7] & b[2]
	r[2] ^= a2[0] & b[2]
	r[3] ^= a2[1] & b[2]
	r[4] ^= a2[2] & b[2]
	r[5] ^= a2[3] & b[2]
	r[6] ^= a2[4] & b[2]
	r[7] ^= a2[5] & b[2]
	a2[6] ^= a2[5] // reduce
	a2[0] ^= a2[5]
	a2[1] ^= a2[5]

	r[0] ^= a2[5] & b[3]
	r[1] ^= a2[6] & b[3]
	r[2] ^= a2[7] & b[3]
	r[3] ^= a2[0] & b[3]
	r[4] ^= a2[1] & b[3]
	r[5] ^= a2[2] & b[3]
	r[6] ^= a2[3] & b[3]
	r[7] ^= a2[4] & b[3]
	a2[5] ^= a2[4] // reduce
	a2[7] ^= a2[4]
	a2[0] ^= a2[4]

	r[0] ^= a2[4] & b[4]
	r[1] ^= a2[5] & b[4]
	r[2] ^= a2[6] & b[4]
	r[3] ^= a2[7] & b[4]
	r[4] ^= a2[0] & b[4]
	r[5] ^= a2[1] & b[4]
	r[6] ^= a2[2] & b[4]
	r[7] ^= a2[3] & b[4]
	a2[4] ^= a2[3] // reduce
	a2[6] ^= a2[3]
	a2[7] ^= a2[3]

	r[0] ^= a2[3] & b[5]
	r[1] ^= a2[4] & b[5]
	r[2] ^= a2[5] & b[5]
	r[3] ^= a2[6] & b[5]
	r[4] ^= a2[7] & b[5]
	r[5] ^= a2[0] & b[5]
	r[6] ^= a2[1] & b[5]
	r[7] ^= a2[2] & b[5]
	a2[3] ^= a2[2] // reduce
	a2[5] ^= a2[2]
	a2[6] ^= a2[2]

	r[0] ^= a2[2] & b[6]
	r[1] ^= a2[3] & b[6]
	r[2] ^= a2[4] & b[6]
	r[3] ^= a2[5] & b[6]
	r[4] ^= a2[6] & b[6]
	r[5] ^= a2[7] & b[6]
	r[6] ^= a2[0] & b[6]
	r[7] ^= a2[1] & b[6]
	a2[2] ^= a2[1] // reduce
	a2[4] ^= a2[1]
	a2[5] ^= a2[1]

	r[0] ^= a2[1] & b[7]
	r[1] ^= a2[2] & b[7]
	r[2] ^= a2[3] & b[7]
	r[3] ^= a2[4] & b[7]
	r[4] ^= a2[5] & b[7]
	r[5] ^= a2[6] & b[7]
	r[6] ^= a2[7] & b[7]
	r[7] ^= a2[0] & b[7]

	zeroUint64Array(&a2)
}

// gf256Square squares x in GF(2^8) and writes the result to r.
// r and x may overlap (in-place squaring is safe).
// Uses the Freshman's Dream rule: (a+b)^2 = a^2 + b^2 in characteristic 2.
//
// Note: local variables r14, r12, r10, r8 hold secret bit-plane data on the stack.
// Go does not provide a mechanism to zero stack variables on return. This matches
// Trezor C's behavior (stack temporaries are not memzeroed in gf256_square either).
// The caller (gf256Inv) zeroes its own heap-allocated intermediates via zeroUint64Array.
func gf256Square(r *[8]uint64, x *[8]uint64) {
	r14 := x[7]
	r12 := x[6]
	r10 := x[5]
	r8 := x[4]
	r[6] = x[3]
	r[4] = x[2]
	r[2] = x[1]
	r[0] = x[0]

	// Reduce with x^8 + x^4 + x^3 + x + 1 until order < 8.
	r[7] = r14
	r[6] ^= r14
	r10 ^= r14
	// r13 is always 0, skip.
	r[4] ^= r12
	r[5] = r12
	r[7] ^= r12
	r8 ^= r12
	// r11 is always 0, skip.
	r[2] ^= r10
	r[3] = r10
	r[5] ^= r10
	r[6] ^= r10
	r[1] = r14 // r9 == r14 always.
	r[2] ^= r14
	r[4] ^= r14
	r[5] ^= r14
	r[0] ^= r8
	r[1] ^= r8
	r[3] ^= r8
	r[4] ^= r8
}

// gf256Inv computes the multiplicative inverse of x in GF(2^8).
// x^254 = x^{-1} by Fermat's little theorem (since x^255 = 1 for x != 0).
func gf256Inv(r *[8]uint64, x *[8]uint64) {
	var y, z [8]uint64

	gf256Square(&y, x)   // y = x^2
	gf256Square(&y, &y)  // y = x^4
	gf256Square(r, &y)   // r = x^8
	gf256Mul(&z, r, x)   // z = x^9
	gf256Square(r, r)    // r = x^16
	gf256Mul(r, r, &z)   // r = x^25
	gf256Square(r, r)    // r = x^50
	gf256Square(&z, r)   // z = x^100
	gf256Square(&z, &z)  // z = x^200
	gf256Mul(r, r, &z)   // r = x^250
	gf256Mul(r, r, &y)   // r = x^254

	zeroUint64Array(&y)
	zeroUint64Array(&z)
}
