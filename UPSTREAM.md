# Upstream Tracking

This file tracks the upstream sources that go-slip39 depends on or was derived from.

## Trezor firmware - crypto/shamir.c

The bitsliced GF(2^8) arithmetic is translated from Daan Sprenkels' C implementation.

- **Repo**: https://github.com/trezor/trezor-firmware
- **Path**: `crypto/shamir.c`
- **Commit used**: `main` branch as of 2026-05-09
- **Check**: `git ls-remote https://github.com/trezor/trezor-firmware HEAD`

## Trezor python-shamir-mnemonic

The Python reference implementation was used for:
- Spec correctness verification (45 test vectors)
- Cross-implementation test vector generation (testdata/crossimpl.json)
- Feistel cipher intermediate value verification

- **Repo**: https://github.com/trezor/python-shamir-mnemonic
- **Version**: 0.3.1
- **Check**: `git ls-remote https://github.com/trezor/python-shamir-mnemonic HEAD`

## SLIP-0039 Specification

- **Repo**: https://github.com/satoshilabs/slips
- **Path**: `slip-0039.md`
- **Check**: `git ls-remote https://github.com/satoshilabs/slips HEAD`

## Wordlist

The SLIP-0039 English wordlist is from the SatoshiLabs canonical source.
SHA256: `bcc4555340332d169718aed8bf31dd9d5248cb7da6e5d355140ef4f1e601eec3`
Verified at init() with panic on mismatch.

## golang.org/x/crypto

PBKDF2-HMAC-SHA256 for the Feistel cipher round function.

- **Module**: `golang.org/x/crypto`
- **Used for**: `pbkdf2.Key()`
