// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

// Example: 2-of-3 sharing with a passphrase.
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/shurlinet/go-slip39"
)

func main() {
	secret := bytes.Repeat([]byte{0x42}, 16)
	passphrase := []byte("my secret passphrase")

	// Split into 3 shares, any 2 can recover.
	groups, err := slip39.Split(secret, passphrase,
		slip39.WithGroups([]slip39.Group{
			{Threshold: 2, Count: 3},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Generated 3 shares:")
	for i, m := range groups[0] {
		fmt.Printf("  Share %d: %s\n", i+1, m)
	}

	// Recover using shares 1 and 3 (any 2 of 3).
	recovered, err := slip39.Combine(
		[]string{groups[0][0], groups[0][2]},
		passphrase,
	)
	if err != nil {
		log.Fatal(err)
	}
	defer slip39.ZeroBytes(recovered)

	fmt.Println("\nRecovery successful:", bytes.Equal(recovered, secret))
}
