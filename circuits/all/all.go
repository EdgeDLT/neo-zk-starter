// Package all imports all available circuits to ensure they are registered.
package all

import (
	_ "neo_zk_starter/circuits/hash_commit"
	_ "neo_zk_starter/circuits/merkle_verify"
	_ "neo_zk_starter/circuits/p256_verify"
	// Add new circuits here
)
