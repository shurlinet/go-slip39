// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT
//
// Package slip39 implements SLIP-0039: Shamir's Secret Sharing for Mnemonic Codes.
//
// Split splits a secret into mnemonic shares using a two-level (group + member) Shamir
// scheme. Combine reconstructs the original secret from a sufficient set of shares.
//
// The secret is encrypted with a passphrase via a 4-round Feistel cipher using
// PBKDF2-HMAC-SHA256 before splitting. An empty passphrase is valid and provides
// plausible deniability: any passphrase produces a valid-looking secret, but only the
// correct passphrase produces the original one.
//
// All GF(2^8) arithmetic is bitsliced and constant-time. Intermediate secrets are
// zeroed after use. The caller is responsible for zeroing the returned secret from
// Combine and the input secret passed to Split.
//
// Split is non-deterministic: each call produces different shares due to random
// identifier and random polynomial coefficients. Use WithRandom for deterministic
// testing only.
package slip39

import (
	"crypto/rand"
	"fmt"
	"io"
	"sort"
)

// Group defines a threshold scheme for one share group.
type Group struct {
	Threshold int // number of shares required to reconstruct the group secret
	Count     int // total number of shares in this group
}

// Option configures Split behavior.
type Option func(*splitConfig)

type splitConfig struct {
	groupThreshold    int
	groups            []Group
	iterationExponent int
	extendable        bool
	rng               io.Reader
}

// WithGroupThreshold sets the number of groups required to reconstruct the secret.
// Default: 1.
func WithGroupThreshold(t int) Option {
	return func(c *splitConfig) { c.groupThreshold = t }
}

// WithGroups sets the group configuration. Each Group specifies a member threshold
// and member count. Default: single group with Threshold=1, Count=1.
func WithGroups(groups []Group) Option {
	return func(c *splitConfig) { c.groups = groups }
}

// WithIterationExponent sets the PBKDF2 iteration exponent for the Feistel cipher.
// Total iterations per round = 2500 << e. Higher values increase encryption time
// exponentially: exponent 0 = 10,000 total, 1 = 20,000, 2 = 40,000.
// Range: 0-15. Default: 1.
func WithIterationExponent(e int) Option {
	return func(c *splitConfig) { c.iterationExponent = e }
}

// WithExtendable sets the extendable backup flag. When true, the backup can be
// extended with additional groups without invalidating existing shares.
// Default: true (spec default).
func WithExtendable(ext bool) Option {
	return func(c *splitConfig) { c.extendable = ext }
}

// WithRandom overrides the random source for deterministic testing.
// In production, the default crypto/rand.Reader is used.
// This option is for testing only; do not use in production.
func WithRandom(r io.Reader) Option {
	return func(c *splitConfig) { c.rng = r }
}

// Split splits a secret into mnemonic shares.
//
// The secret must be an even number of bytes, at least 16 and at most 64.
// The passphrase must contain only printable ASCII characters (codes 32-126)
// and is used to encrypt the secret before splitting. A nil or empty passphrase
// is valid.
//
// Returns a slice of groups, where each group is a slice of mnemonic strings.
func Split(secret []byte, passphrase []byte, opts ...Option) ([][]string, error) {
	// Apply options. Last call wins for each option.
	cfg := splitConfig{
		groupThreshold:    1,
		groups:            []Group{{Threshold: 1, Count: 1}},
		iterationExponent: 1,
		extendable:        true,
		rng:               rand.Reader,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	// Validate secret length: even, 16-64 bytes.
	if len(secret) < minStrengthBits/8 {
		return nil, fmt.Errorf("%w: secret must be at least %d bytes, got %d",
			ErrInvalidSecret, minStrengthBits/8, len(secret))
	}
	if len(secret) > maxSecretLen {
		return nil, fmt.Errorf("%w: secret must be at most %d bytes, got %d",
			ErrInvalidSecret, maxSecretLen, len(secret))
	}
	if len(secret)%2 != 0 {
		return nil, fmt.Errorf("%w: secret length must be even, got %d",
			ErrInvalidSecret, len(secret))
	}

	// Validate passphrase: printable ASCII only.
	if err := validatePassphrase(passphrase); err != nil {
		return nil, err
	}

	// Validate iteration exponent: 0-15.
	if cfg.iterationExponent < 0 || cfg.iterationExponent > 15 {
		return nil, fmt.Errorf("%w: iteration exponent must be in [0, 15], got %d",
			ErrInvalidShares, cfg.iterationExponent)
	}

	// Validate group configuration.
	if len(cfg.groups) < 1 {
		return nil, fmt.Errorf("%w: at least one group is required", ErrInvalidShares)
	}
	if len(cfg.groups) > maxGroupCount {
		return nil, fmt.Errorf("%w: number of groups (%d) exceeds maximum (%d)",
			ErrInvalidShares, len(cfg.groups), maxGroupCount)
	}
	if cfg.groupThreshold < 1 {
		return nil, fmt.Errorf("%w: group threshold must be at least 1", ErrInvalidShares)
	}
	if cfg.groupThreshold > maxGroupCount {
		return nil, fmt.Errorf("%w: group threshold (%d) exceeds maximum (%d)",
			ErrInvalidShares, cfg.groupThreshold, maxGroupCount)
	}
	if cfg.groupThreshold > len(cfg.groups) {
		return nil, fmt.Errorf("%w: group threshold (%d) exceeds number of groups (%d)",
			ErrInvalidShares, cfg.groupThreshold, len(cfg.groups))
	}
	for i, g := range cfg.groups {
		if g.Threshold < 1 {
			return nil, fmt.Errorf("%w: group %d member threshold must be at least 1", ErrInvalidShares, i)
		}
		if g.Count < 1 {
			return nil, fmt.Errorf("%w: group %d member count must be at least 1", ErrInvalidShares, i)
		}
		if g.Threshold > g.Count {
			return nil, fmt.Errorf("%w: group %d member threshold (%d) exceeds count (%d)",
				ErrInvalidShares, i, g.Threshold, g.Count)
		}
		if g.Count > maxShareCount {
			return nil, fmt.Errorf("%w: group %d member count (%d) exceeds maximum (%d)",
				ErrInvalidShares, i, g.Count, maxShareCount)
		}
		// Threshold 1 with count > 1 is forbidden (all shares would be identical).
		if g.Threshold == 1 && g.Count > 1 {
			return nil, fmt.Errorf("%w: group %d has threshold 1 with count %d; "+
				"use 1-of-1 sharing instead", ErrInvalidShares, i, g.Count)
		}
	}

	// Generate random 15-bit identifier.
	idBuf := make([]byte, 2)
	n, err := io.ReadFull(cfg.rng, idBuf)
	if err != nil {
		return nil, fmt.Errorf("%w: generating identifier: %v", ErrInvalidShares, err)
	}
	if n != 2 {
		return nil, fmt.Errorf("%w: short read generating identifier", ErrInvalidShares)
	}
	identifier := (int(idBuf[0])<<8 | int(idBuf[1])) & ((1 << uint(idLengthBits)) - 1)

	// Encrypt master secret via Feistel cipher.
	ems := encrypt(secret, passphrase, cfg.iterationExponent, identifier, cfg.extendable)
	defer ZeroBytes(ems)

	// Split EMS into group shares using outer Shamir.
	groupShares, err := splitSecret(cfg.groupThreshold, len(cfg.groups), ems, cfg.rng)
	if err != nil {
		return nil, fmt.Errorf("splitting into groups: %w", err)
	}
	defer func() {
		for _, gs := range groupShares {
			ZeroBytes(gs.data)
		}
	}()

	// Split each group's share into member shares.
	result := make([][]string, len(cfg.groups))
	for gi, g := range cfg.groups {
		memberShares, err := splitSecret(g.Threshold, g.Count, groupShares[gi].data, cfg.rng)
		if err != nil {
			return nil, fmt.Errorf("splitting group %d: %w", gi, err)
		}

		mnemonics := make([]string, g.Count)
		for mi, ms := range memberShares {
			sd := &shareData{
				identifier:        identifier,
				extendable:        cfg.extendable,
				iterationExponent: cfg.iterationExponent,
				groupIndex:        gi,
				groupThreshold:    cfg.groupThreshold,
				groupCount:        len(cfg.groups),
				memberIndex:       int(ms.x),
				memberThreshold:   g.Threshold,
				value:             ms.data,
			}
			mnemonics[mi] = encodeShare(sd)
		}

		// Zero member share data after encoding to mnemonics.
		for _, ms := range memberShares {
			ZeroBytes(ms.data)
		}

		result[gi] = mnemonics
	}

	return result, nil
}

// Combine reconstructs a secret from mnemonic shares.
//
// The passphrase must match the one used during Split. A wrong passphrase produces
// a different secret without any error (plausible deniability by design).
//
// The caller is responsible for zeroing the returned secret when done.
func Combine(mnemonics []string, passphrase []byte) ([]byte, error) {
	if len(mnemonics) == 0 {
		return nil, fmt.Errorf("%w: no mnemonics provided", ErrInvalidMnemonic)
	}

	// Validate passphrase.
	if err := validatePassphrase(passphrase); err != nil {
		return nil, err
	}

	// Decode all mnemonics.
	shares := make([]*shareData, len(mnemonics))
	for i, m := range mnemonics {
		sd, err := decodeMnemonic(m)
		if err != nil {
			return nil, fmt.Errorf("mnemonic %d: %w", i, err)
		}
		shares[i] = sd
	}

	// Verify common parameters match across all shares (id, ext, e, GT, G, value length).
	ref := shares[0]
	for i := 1; i < len(shares); i++ {
		s := shares[i]
		if s.identifier != ref.identifier {
			return nil, fmt.Errorf("%w: share %d has different identifier (%d vs %d) - shares belong to different backup sets",
				ErrInvalidShares, i, s.identifier, ref.identifier)
		}
		if s.extendable != ref.extendable {
			return nil, fmt.Errorf("%w: share %d has different extendable flag",
				ErrInvalidShares, i)
		}
		if s.iterationExponent != ref.iterationExponent {
			return nil, fmt.Errorf("%w: share %d has different iteration exponent (%d vs %d)",
				ErrInvalidShares, i, s.iterationExponent, ref.iterationExponent)
		}
		if s.groupThreshold != ref.groupThreshold {
			return nil, fmt.Errorf("%w: share %d has different group threshold (%d vs %d)",
				ErrInvalidShares, i, s.groupThreshold, ref.groupThreshold)
		}
		if s.groupCount != ref.groupCount {
			return nil, fmt.Errorf("%w: share %d has different group count (%d vs %d)",
				ErrInvalidShares, i, s.groupCount, ref.groupCount)
		}
		if len(s.value) != len(ref.value) {
			return nil, fmt.Errorf("%w: share %d has different value length (%d vs %d)",
				ErrInvalidShares, i, len(s.value), len(ref.value))
		}
	}

	// Group shares by group index.
	type groupEntry struct {
		memberThreshold int
		members         []share // internal share type
	}
	groups := make(map[int]*groupEntry)
	for _, s := range shares {
		ge, exists := groups[s.groupIndex]
		if !exists {
			ge = &groupEntry{memberThreshold: s.memberThreshold}
			groups[s.groupIndex] = ge
		} else {
			// Member threshold must be consistent within a group.
			if ge.memberThreshold != s.memberThreshold {
				return nil, fmt.Errorf("%w: group %d has inconsistent member threshold (%d vs %d)",
					ErrInvalidShares, s.groupIndex, ge.memberThreshold, s.memberThreshold)
			}
		}

		// Reject duplicate member indices within the same group.
		for _, existing := range ge.members {
			if existing.x == byte(s.memberIndex) {
				return nil, fmt.Errorf("%w: duplicate member index %d in group %d",
					ErrInvalidShares, s.memberIndex, s.groupIndex)
			}
		}

		ge.members = append(ge.members, share{x: byte(s.memberIndex), data: s.value})
	}

	// Spec requires exactly groupThreshold groups, not more, not fewer.
	if len(groups) < ref.groupThreshold {
		return nil, fmt.Errorf("%w: insufficient number of groups (%d provided, %d required)",
			ErrInvalidShares, len(groups), ref.groupThreshold)
	}
	if len(groups) != ref.groupThreshold {
		return nil, fmt.Errorf("%w: wrong number of groups (%d provided, expected exactly %d)",
			ErrInvalidShares, len(groups), ref.groupThreshold)
	}

	// Recover group secrets. Sorted iteration for deterministic behavior.
	groupIndices := make([]int, 0, len(groups))
	for gi := range groups {
		groupIndices = append(groupIndices, gi)
	}
	sort.Ints(groupIndices)

	groupShares := make([]share, 0, len(groups))
	for _, gi := range groupIndices {
		ge := groups[gi]
		if len(ge.members) != ge.memberThreshold {
			return nil, fmt.Errorf("%w: group %d requires exactly %d shares but %d were provided",
				ErrInvalidShares, gi, ge.memberThreshold, len(ge.members))
		}

		groupSecret, err := recoverSecret(ge.memberThreshold, ge.members)
		if err != nil {
			return nil, fmt.Errorf("recovering group %d: %w", gi, err)
		}
		groupShares = append(groupShares, share{x: byte(gi), data: groupSecret})
	}
	// Zero group secrets after use.
	defer func() {
		for _, gs := range groupShares {
			ZeroBytes(gs.data)
		}
	}()

	// Recover EMS from group shares.
	emsCiphertext, err := recoverSecret(ref.groupThreshold, groupShares)
	if err != nil {
		return nil, fmt.Errorf("recovering encrypted master secret: %w", err)
	}
	defer ZeroBytes(emsCiphertext)

	// Decrypt EMS to recover master secret.
	masterSecret := decrypt(emsCiphertext, passphrase, ref.iterationExponent, ref.identifier, ref.extendable)
	return masterSecret, nil
}

// validatePassphrase checks that all bytes are printable ASCII (32-126).
func validatePassphrase(passphrase []byte) error {
	for i, b := range passphrase {
		if b < 32 || b > 126 {
			return fmt.Errorf("%w: passphrase byte %d (0x%02x) is not printable ASCII (32-126)",
				ErrInvalidPassphrase, i, b)
		}
	}
	return nil
}
