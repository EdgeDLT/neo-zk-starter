// Package all imports all available circuits to ensure they are registered.
package all

import (
	_ "zkp_example/circuits/hash_commit"
	_ "zkp_example/circuits/merkle_verify"
	_ "zkp_example/circuits/p256_verify"
	// Add new circuits here
)
