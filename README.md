# go-slip39

[![Go Tests](https://github.com/shurlinet/go-slip39/actions/workflows/test.yml/badge.svg)](https://github.com/shurlinet/go-slip39/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/shurlinet/go-slip39.svg)](https://pkg.go.dev/github.com/shurlinet/go-slip39)
[![Go Report Card](https://goreportcard.com/badge/github.com/shurlinet/go-slip39)](https://goreportcard.com/report/github.com/shurlinet/go-slip39)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Go implementation of [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md): Shamir's Secret Sharing for Mnemonic Codes.

Split a secret into mnemonic shares. Any threshold number of shares can reconstruct the original secret. Supports two-level group schemes for organizational key recovery.

## Security

- **Constant-time GF(2^8)**: Bitsliced arithmetic translated from the [Trezor firmware](https://github.com/trezor/trezor-firmware/blob/main/crypto/shamir.c). Zero data-dependent branches, zero table lookups. Immune to cache-timing and Spectre attacks.
- **Memory zeroing**: All intermediate secrets are zeroed via `//go:noinline` functions. The caller is responsible for zeroing the returned secret from `Combine`. The Go garbage collector may copy data before zeroing occurs; for hardware-grade security, use a hardware wallet.
- **Constant-time digest comparison**: `crypto/subtle.ConstantTimeCompare` for share verification.
- **No math/big**: BitStream encoding replaces big integer arithmetic, eliminating limb-zeroing concerns.
- **Concurrency**: `Split` and `Combine` are safe for concurrent use. No shared mutable state. The wordlist is immutable after init.
- **Minimal dependencies**: Only `golang.org/x/crypto` (PBKDF2). Everything else is Go stdlib.

## Install

```
go get github.com/shurlinet/go-slip39
```

Requires Go 1.25 or later (due to `golang.org/x/crypto` dependency).

## Usage

```go
package main

import (
    "fmt"
    "log"

    "github.com/shurlinet/go-slip39"
)

func main() {
    secret := []byte{0xBB, 0x54, 0xAA, 0xC4, 0xB8, 0x9D, 0xC8, 0x68,
        0xBA, 0x37, 0xD9, 0xCC, 0x21, 0xB2, 0xCE, 0xCE}

    // Split into 2-of-3 shares with a passphrase.
    groups, err := slip39.Split(secret, []byte("my passphrase"),
        slip39.WithGroups([]slip39.Group{
            {Threshold: 2, Count: 3},
        }),
    )
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println("Share 1:", groups[0][0])
    fmt.Println("Share 2:", groups[0][1])
    fmt.Println("Share 3:", groups[0][2])

    // Recover from any 2 shares.
    recovered, err := slip39.Combine(groups[0][:2], []byte("my passphrase"))
    if err != nil {
        log.Fatal(err)
    }
    defer slip39.ZeroBytes(recovered) // Caller zeroes the secret.

    fmt.Printf("Recovered: %x\n", recovered)
}
```

## API

```go
func Split(secret []byte, passphrase []byte, opts ...Option) ([][]string, error)
func Combine(mnemonics []string, passphrase []byte) ([]byte, error)

func WithGroupThreshold(t int) Option
func WithGroups(groups []Group) Option
func WithIterationExponent(e int) Option
func WithExtendable(ext bool) Option
func WithRandom(r io.Reader) Option   // Testing only.

func ZeroBytes(b []byte)

type Group struct {
    Threshold int
    Count     int
}
```

**Secret requirements**: Even number of bytes, 16-64 (128-512 bits).

**Passphrase**: Printable ASCII only (codes 32-126). Empty/nil is valid. A wrong passphrase produces a different secret, not an error (plausible deniability by design).

## Multi-Group Example

```go
// Three groups, any 2 needed:
//   Family: 2-of-3
//   Lawyer: 1-of-1
//   Vault:  3-of-5
groups, err := slip39.Split(secret, nil,
    slip39.WithGroupThreshold(2),
    slip39.WithGroups([]slip39.Group{
        {Threshold: 2, Count: 3},
        {Threshold: 1, Count: 1},
        {Threshold: 3, Count: 5},
    }),
)
```

## Spec Compliance ([SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md))

| Feature | Status | Notes |
|---------|--------|-------|
| 2-level Shamir (groups + members) | Supported | Up to 16 groups, 16 members each |
| Feistel cipher (PBKDF2-HMAC-SHA256) | Supported | 4 rounds, configurable iteration exponent 0-15 |
| RS1024 checksum | Supported | Exhaustive single-error detection verified (20,460 cases) |
| Extendable backup flag | Supported | Both modes, default true per spec |
| Passphrase encryption | Supported | Printable ASCII, plausible deniability by design |
| Secret sizes 128-512 bits | Supported | 16-64 bytes, even length |
| 1024-word English wordlist | Supported | SHA256-verified at init against SatoshiLabs canonical source |
| 45 official test vectors | All pass | Negative vectors mapped to specific error sentinels |
| Cross-impl verification | Verified | 77 encode round-trips byte-match Python encoder |

## Differences from Other Implementations

| Feature | go-slip39 (shurlinet) | Python ref | go-slip39 (duodekalexeis) | Trezor C |
|---------|----------------------|------------|--------------------------|----------|
| Constant-time GF(256) | Bitsliced | No | No | Bitsliced |
| Memory zeroing | Yes | No (immutable) | No | Yes |
| Fuzz testing | 5 targets | No | No | Yes |
| Anti-tamper tests | Yes | No | No | N/A |
| Dependencies | x/crypto only | Many | gonum, golang-set | None |
| Max secret size | 64 bytes | No limit | 32 bytes | 32 bytes |

## Consumer Responsibilities

**Zero the recovered secret.** `Combine` returns a `[]byte` that the caller must zero after use: `defer slip39.ZeroBytes(recovered)`.

**Wrong passphrase = different secret, not an error.** This is plausible deniability by design. There is no way to detect a wrong passphrase. The caller must verify the recovered secret independently (e.g., derive a public key and compare).

**Share storage.** Shares are mnemonic strings. How you store and distribute them is your responsibility. The library provides the math; you provide the operational security.

## Testing

- 45 SatoshiLabs spec vectors (mandatory gate)
- 6 Python cross-implementation vectors (deterministic seed, python-shamir-mnemonic 0.3.1)
- 77 encode round-trips byte-matching the Python encoder
- 65,536 exhaustive GF(256) multiplication verifications (bitsliced vs table oracle)
- 20,460 exhaustive RS1024 single-error detection cases
- 9 AI threat defense tests (Feistel round count, iteration base, digest length, special indices, wordlist hash, ZeroBytes effectiveness, secret-in-error scan, GF(256) exhaustive, reduction polynomial)
- Property tests (share independence, determinism, threshold enforcement, concurrent safety)
- 5 fuzz targets (Combine, RoundTrip, Interpolate, BitStream, Feistel)
- Anti-tamper tests (HMAC argument order, customization string bytes, threshold encoding, independent HMAC oracle)

```
go test -race -count=1 ./...
```

## Examples

See the [examples/](examples/) directory:

- [basic](examples/basic/) - 1-of-1 split and combine, no passphrase
- [sharing](examples/sharing/) - 2-of-3 with passphrase
- [multigroup](examples/multigroup/) - 2-of-3 groups (family/lawyer/vault scenario)

## Dependencies

| Dependency | Purpose |
|---|---|
| `golang.org/x/crypto` | PBKDF2-HMAC-SHA256 (Feistel cipher round function) |

No other external dependencies. Wordlist is embedded via `go:embed`.

## AI Transparency

This library was developed with assistance from Claude (Anthropic). All code was reviewed, tested against reference implementations, and verified against the SLIP-0039 specification. The test suite includes 9 AI threat defense tests designed to catch both human and AI-introduced errors. The AI generated code; the human made every design decision, reviewed every line, and owns every bug.

## Acknowledgments

- [SatoshiLabs](https://satoshilabs.com) for the [SLIP-0039 specification](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) and official test vectors
- [Daan Sprenkels](https://dsprenkels.com) for the bitsliced GF(2^8) arithmetic in [Trezor firmware](https://github.com/trezor/trezor-firmware/blob/main/crypto/shamir.c)
- [Trezor](https://github.com/trezor/python-shamir-mnemonic) for the Python reference implementation used for cross-implementation verification
- [Lucas Ontivero](https://github.com/lontivero/Slip39) for the BitStream encoding approach

## License

MIT. See [LICENSE](LICENSE).

GF(2^8) arithmetic translated from Trezor firmware (Apache 2.0).
See [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES).
