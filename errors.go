// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

package slip39

import "errors"

// Error sentinels for SLIP-0039 operations.
// All error returns use %w wrapping so callers can use errors.Is.
var (
	ErrInvalidMnemonic   = errors.New("slip39: invalid mnemonic")
	ErrInvalidChecksum   = errors.New("slip39: invalid checksum")
	ErrInvalidSecret     = errors.New("slip39: invalid secret")
	ErrInvalidPassphrase = errors.New("slip39: invalid passphrase")
	ErrInvalidShares     = errors.New("slip39: invalid shares")
	ErrDigestMismatch    = errors.New("slip39: digest verification failed")
)
