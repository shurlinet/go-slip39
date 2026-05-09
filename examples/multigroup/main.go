// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

// Example: multi-group sharing (2-of-3 groups: family, lawyer, vault).
package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/shurlinet/go-slip39"
)

func main() {
	secret := bytes.Repeat([]byte{0x42}, 32) // 256-bit secret

	// Three groups, any 2 needed to recover:
	//   Family: 2-of-3 (any 2 family members)
	//   Lawyer: 1-of-1 (the lawyer alone)
	//   Vault:  3-of-5 (3 of 5 vault shares)
	groups, err := slip39.Split(secret, nil,
		slip39.WithGroupThreshold(2),
		slip39.WithGroups([]slip39.Group{
			{Threshold: 2, Count: 3}, // Family
			{Threshold: 1, Count: 1}, // Lawyer
			{Threshold: 3, Count: 5}, // Vault
		}),
		slip39.WithIterationExponent(1),
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Family shares (2-of-3):")
	for i, m := range groups[0] {
		fmt.Printf("  %d: %s\n", i+1, m)
	}
	fmt.Println("\nLawyer share (1-of-1):")
	fmt.Printf("  1: %s\n", groups[1][0])
	fmt.Println("\nVault shares (3-of-5):")
	for i, m := range groups[2] {
		fmt.Printf("  %d: %s\n", i+1, m)
	}

	// Recovery scenario: family (2 shares) + lawyer (1 share) = 2 groups.
	combined := []string{
		groups[0][0], groups[0][2], // Family: shares 1 and 3
		groups[1][0],               // Lawyer: the single share
	}

	recovered, err := slip39.Combine(combined, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer slip39.ZeroBytes(recovered)

	fmt.Println("\nRecovery successful:", bytes.Equal(recovered, secret))
}
