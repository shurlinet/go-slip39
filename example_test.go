// Copyright (c) 2026 Satinderjit Singh
// SPDX-License-Identifier: MIT

package slip39_test

import (
	"bytes"
	"fmt"

	"github.com/shurlinet/go-slip39"
)

func ExampleSplit() {
	secret := bytes.Repeat([]byte{0x42}, 16)

	groups, err := slip39.Split(secret, nil,
		slip39.WithGroups([]slip39.Group{
			{Threshold: 2, Count: 3},
		}),
		slip39.WithIterationExponent(0),
	)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	fmt.Printf("Generated %d shares\n", len(groups[0]))
	// Output: Generated 3 shares
}

func ExampleCombine() {
	secret := bytes.Repeat([]byte{0x42}, 16)

	// Split into 2-of-3.
	groups, err := slip39.Split(secret, nil,
		slip39.WithGroups([]slip39.Group{
			{Threshold: 2, Count: 3},
		}),
		slip39.WithIterationExponent(0),
	)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	// Recover from any 2 of 3 shares.
	recovered, err := slip39.Combine(groups[0][:2], nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	defer slip39.ZeroBytes(recovered)

	fmt.Println("Recovery successful:", bytes.Equal(recovered, secret))
	// Output: Recovery successful: true
}
