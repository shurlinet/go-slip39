// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

package slip39

// ZeroBytes overwrites a byte slice with zeros.
// Callers must use this to erase sensitive data (secrets, shares, intermediates)
// before the slice becomes unreachable.
//
//go:noinline
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ZeroUint64Array overwrites a bitsliced GF(256) array with zeros.
// Used to erase intermediates in constant-time Shamir arithmetic.
//
//go:noinline
func ZeroUint64Array(s *[8]uint64) {
	*s = [8]uint64{}
}
