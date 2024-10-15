package registration

import (
	_ "zkp_example/internal/circuit/hash_commit"
	_ "zkp_example/internal/circuit/merkle_verify"
	_ "zkp_example/internal/circuit/p256_verify"
	// Import other circuit packages here
)

// Init doesn't need to do anything.
// Its purpose is to ensure the packages are imported and their init() functions are called.
func Init() {}
