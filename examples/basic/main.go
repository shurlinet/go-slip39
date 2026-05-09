// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

// Example: basic 1-of-1 split and combine with no passphrase.
package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/shurlinet/go-slip39"
)

func main() {
	// A 128-bit secret (16 bytes).
	secret, _ := hex.DecodeString("bb54aac4b89dc868ba37d9cc21b2cece")

	// Split into a single share (1-of-1, no passphrase).
	groups, err := slip39.Split(secret, nil)
	if err != nil {
		log.Fatal(err)
	}

	mnemonic := groups[0][0]
	fmt.Println("Mnemonic:", mnemonic)

	// Recover the secret.
	recovered, err := slip39.Combine([]string{mnemonic}, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer slip39.ZeroBytes(recovered)

	fmt.Println("Recovered:", hex.EncodeToString(recovered))
}
