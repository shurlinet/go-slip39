// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT
//
// Shamir's Secret Sharing over GF(2^8) using bitsliced arithmetic.
// Two-level scheme: group-level Shamir over member-level Shamir.

package slip39

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
)

const (
	// digestLengthBytes is the number of HMAC-SHA256 bytes used as a digest
	// to verify correct share reconstruction.
	digestLengthBytes = 4

	// digestIndex is the x-coordinate used for the digest share in Shamir interpolation.
	digestIndex = 254

	// secretIndex is the x-coordinate used for the secret in Shamir interpolation.
	secretIndex = 255

	// maxShareCount is the maximum number of shares in a single group.
	maxShareCount = 16
)

// share is an internal type representing a single Shamir share.
type share struct {
	x    byte   // x-coordinate (share index)
	data []byte // y-values (same length as the secret)
}

// interpolate evaluates the Lagrange interpolation polynomial at resultIndex,
// given a set of shares. This is the core Shamir reconstruction operation.
//
// All arithmetic is bitsliced and constant-time on secret data.
// The only data-dependent branch is on public share indices (F35).
//
// Returns error if share indices are not unique (duplicate detection via
// zero-denominator check) or if len exceeds maxSecretLen.
func interpolate(result []byte, resultIndex byte, shares []share) error {
	shareCount := len(shares)
	if shareCount == 0 {
		return fmt.Errorf("slip39: %w: no shares provided", ErrInvalidShares)
	}
	secretLen := len(shares[0].data)
	if secretLen == 0 {
		return fmt.Errorf("slip39: %w: share data is empty", ErrInvalidShares)
	}
	if secretLen > maxSecretLen {
		return fmt.Errorf("slip39: %w: share length %d exceeds maximum %d", ErrInvalidShares, secretLen, maxSecretLen)
	}
	if shareCount > maxShareCount {
		return fmt.Errorf("slip39: %w: share count %d exceeds maximum %d", ErrInvalidShares, shareCount, maxShareCount)
	}
	for i := 1; i < shareCount; i++ {
		if len(shares[i].data) != secretLen {
			return fmt.Errorf("slip39: %w: share %d has length %d, expected %d", ErrInvalidShares, i, len(shares[i].data), secretLen)
		}
	}

	var x [8]uint64
	xs := make([][8]uint64, shareCount)
	ys := make([][8]uint64, shareCount)
	var num [8]uint64
	var denom [8]uint64
	var tmp [8]uint64
	var secret [8]uint64

	// Cleanup all intermediates (F283, F284).
	defer func() {
		ZeroUint64Array(&x)
		for i := range xs {
			ZeroUint64Array(&xs[i])
		}
		for i := range ys {
			ZeroUint64Array(&ys[i])
		}
		ZeroUint64Array(&num)
		ZeroUint64Array(&denom)
		ZeroUint64Array(&tmp)
		ZeroUint64Array(&secret)
	}()

	// Collect x and y values into bitsliced form.
	for i := 0; i < shareCount; i++ {
		bitsliceSetAll(&xs[i], shares[i].x)
		bitslice(&ys[i], shares[i].data)
	}
	bitsliceSetAll(&x, resultIndex)

	// Compute numerator: product of (x - xs[i]) for all i.
	// Start with 1 (all bits set).
	bitsliceSetAll(&num, 1)
	for i := 0; i < shareCount; i++ {
		tmp = x
		gf256Add(&tmp, &xs[i])
		gf256Mul(&num, &num, &tmp)
	}

	// Lagrange basis polynomial evaluation.
	for i := 0; i < shareCount; i++ {
		// F181: if resultIndex matches a share index, return that share directly.
		if shares[i].x == resultIndex {
			bitsliceSetAll(&denom, 1)
			gf256Add(&secret, &ys[i])
		} else {
			denom = x
			gf256Add(&denom, &xs[i])
		}
		for j := 0; j < shareCount; j++ {
			if i == j {
				continue
			}
			tmp = xs[i]
			gf256Add(&tmp, &xs[j])
			gf256Mul(&denom, &denom, &tmp)
		}
		// Zero denominator means duplicate share indices (F33).
		if (denom[0] | denom[1] | denom[2] | denom[3] | denom[4] | denom[5] | denom[6] | denom[7]) == 0 {
			return fmt.Errorf("slip39: %w: share indices are not unique", ErrInvalidShares)
		}
		gf256Inv(&tmp, &denom)       // inverted denominator
		gf256Mul(&tmp, &tmp, &num)   // basis polynomial
		gf256Mul(&tmp, &tmp, &ys[i]) // scaled coefficient
		gf256Add(&secret, &tmp)
	}

	unbitslice(result, &secret)
	return nil
}

// createDigest computes HMAC-SHA256(key=randomPart, msg=sharedSecret)[:digestLengthBytes].
// The digest is used to verify correct share reconstruction.
func createDigest(randomPart, sharedSecret []byte) []byte {
	h := hmac.New(sha256.New, randomPart)
	n, err := h.Write(sharedSecret)
	if err != nil {
		panic("slip39: HMAC Write failed: " + err.Error())
	}
	if n != len(sharedSecret) {
		panic("slip39: HMAC Write returned unexpected byte count")
	}
	full := h.Sum(nil)
	if len(full) != sha256.Size {
		panic("slip39: HMAC-SHA256 returned unexpected length")
	}
	digest := make([]byte, digestLengthBytes)
	copy(digest, full[:digestLengthBytes])
	ZeroBytes(full)
	return digest
}

// splitSecret splits a secret into shares using Shamir's Secret Sharing.
//
// threshold is the number of shares required for reconstruction.
// shareCount is the total number of shares to generate.
// rng is the source of randomness (crypto/rand.Reader for production, deterministic for tests).
//
// Returns a slice of shares. The caller is responsible for zeroing share data.
func splitSecret(threshold, shareCount int, sharedSecret []byte, rng io.Reader) ([]share, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("slip39: %w: threshold must be at least 1", ErrInvalidShares)
	}
	if threshold > shareCount {
		return nil, fmt.Errorf("slip39: %w: threshold %d exceeds share count %d", ErrInvalidShares, threshold, shareCount)
	}
	if shareCount > maxShareCount {
		return nil, fmt.Errorf("slip39: %w: share count %d exceeds maximum %d", ErrInvalidShares, shareCount, maxShareCount)
	}

	secretLen := len(sharedSecret)
	if secretLen < 16 {
		return nil, fmt.Errorf("slip39: %w: secret must be at least 16 bytes", ErrInvalidSecret)
	}
	if secretLen > maxSecretLen {
		return nil, fmt.Errorf("slip39: %w: secret length %d exceeds maximum %d bytes", ErrInvalidSecret, secretLen, maxSecretLen)
	}
	if secretLen%2 != 0 {
		return nil, fmt.Errorf("slip39: %w: secret length must be even", ErrInvalidSecret)
	}

	// F40: threshold == 1 special case. All shares are copies of the secret.
	if threshold == 1 {
		shares := make([]share, shareCount)
		for i := 0; i < shareCount; i++ {
			// F102, F136: copy data per share, do NOT alias.
			data := make([]byte, secretLen)
			copy(data, sharedSecret)
			shares[i] = share{x: byte(i), data: data}
		}
		return shares, nil
	}

	// F179, F232: Pre-read ALL random bytes upfront.
	// Random shares: (threshold - 2) shares of secretLen bytes each.
	// Digest share: (secretLen - digestLengthBytes) random bytes.
	randomShareCount := threshold - 2
	totalRandom := randomShareCount*secretLen + (secretLen - digestLengthBytes)
	randomBytes := make([]byte, totalRandom)
	n, err := io.ReadFull(rng, randomBytes)
	if err != nil {
		ZeroBytes(randomBytes)
		return nil, fmt.Errorf("slip39: %w: reading random bytes: %v", ErrInvalidShares, err)
	}
	if n != len(randomBytes) {
		ZeroBytes(randomBytes)
		return nil, fmt.Errorf("slip39: %w: short random read: got %d, want %d", ErrInvalidShares, n, len(randomBytes))
	}

	// Build the base shares for polynomial interpolation.
	// Base shares define the polynomial:
	//   index 254 (digestIndex): digest share (4-byte HMAC + random padding)
	//   index 255 (secretIndex): the actual secret
	//   indices 0..randomShareCount-1: random shares
	baseShares := make([]share, threshold)

	// Random shares.
	for i := 0; i < randomShareCount; i++ {
		data := make([]byte, secretLen)
		copy(data, randomBytes[i*secretLen:(i+1)*secretLen])
		baseShares[i] = share{x: byte(i), data: data}
	}

	// Digest share: HMAC(randomPart, secret) || randomPart.
	randomPartOffset := randomShareCount * secretLen
	randomPart := make([]byte, secretLen-digestLengthBytes)
	copy(randomPart, randomBytes[randomPartOffset:])
	digest := createDigest(randomPart, sharedSecret)

	digestShareData := make([]byte, secretLen)
	copy(digestShareData, digest)
	copy(digestShareData[digestLengthBytes:], randomPart)
	ZeroBytes(digest)
	ZeroBytes(randomPart)
	baseShares[threshold-2] = share{x: digestIndex, data: digestShareData}

	// Secret share.
	secretShareData := make([]byte, secretLen)
	copy(secretShareData, sharedSecret)
	baseShares[threshold-1] = share{x: secretIndex, data: secretShareData}

	ZeroBytes(randomBytes)

	// Generate output shares by interpolating at indices 0..shareCount-1.
	// Random shares that already exist are reused directly.
	shares := make([]share, shareCount)
	for i := 0; i < shareCount; i++ {
		if i < randomShareCount {
			// This share is already a base share; copy it.
			data := make([]byte, secretLen)
			copy(data, baseShares[i].data)
			shares[i] = share{x: byte(i), data: data}
		} else {
			data := make([]byte, secretLen)
			if err := interpolate(data, byte(i), baseShares); err != nil {
				// Cleanup on error.
				for j := 0; j < i; j++ {
					ZeroBytes(shares[j].data)
				}
				for j := range baseShares {
					ZeroBytes(baseShares[j].data)
				}
				return nil, err
			}
			shares[i] = share{x: byte(i), data: data}
		}
	}

	// Zero base shares (F285).
	for i := range baseShares {
		ZeroBytes(baseShares[i].data)
	}

	return shares, nil
}

// recoverSecret reconstructs the secret from shares using Lagrange interpolation.
//
// The digest share is reconstructed at index digestIndex and verified against
// the recovered secret. Returns error if digest verification fails.
//
// The caller is responsible for zeroing the returned secret.
func recoverSecret(threshold int, shares []share) ([]byte, error) {
	if threshold < 1 {
		return nil, fmt.Errorf("slip39: %w: threshold must be at least 1", ErrInvalidShares)
	}
	if len(shares) < threshold {
		return nil, fmt.Errorf("slip39: %w: need %d shares but got %d", ErrInvalidShares, threshold, len(shares))
	}

	sharedSecret := make([]byte, len(shares[0].data))

	// F40: threshold == 1 special case.
	if threshold == 1 {
		copy(sharedSecret, shares[0].data)
		return sharedSecret, nil
	}

	// Reconstruct the secret at secretIndex.
	if err := interpolate(sharedSecret, secretIndex, shares[:threshold]); err != nil {
		ZeroBytes(sharedSecret)
		return nil, err
	}

	// Reconstruct the digest share at digestIndex.
	digestShare := make([]byte, len(shares[0].data))
	defer ZeroBytes(digestShare) // F286: always zero.

	if err := interpolate(digestShare, digestIndex, shares[:threshold]); err != nil {
		ZeroBytes(sharedSecret) // F286: zero on error.
		return nil, err
	}

	// Verify the digest.
	digest := digestShare[:digestLengthBytes]
	randomPart := digestShare[digestLengthBytes:]
	expectedDigest := createDigest(randomPart, sharedSecret)
	defer ZeroBytes(expectedDigest)

	// F9: constant-time comparison.
	if subtle.ConstantTimeCompare(digest, expectedDigest) != 1 {
		ZeroBytes(sharedSecret) // F286: zero on error.
		return nil, fmt.Errorf("slip39: %w", ErrDigestMismatch)
	}

	return sharedSecret, nil
}
