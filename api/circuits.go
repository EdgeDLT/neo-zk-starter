package api

import (
	"fmt"
	"math/big"
)

// HashCommitProof generates a proof that you know a preimage for a hash
func HashCommitProof(preimage uint64) (*ProofResult, error) {
	return GenerateProof("hash_commit", preimage)
}

// MerkleProofInput represents the input for merkle_verify circuit
type MerkleProofInput struct {
	LeafHash      []byte   // Hash of the leaf data
	ProofElements [][]byte // Array of sibling hashes (max 4)
	Root          []byte   // Expected Merkle root
}

// MerkleProof generates a proof of membership in a Merkle tree
func MerkleProof(input MerkleProofInput) (*ProofResult, error) {
	// Validate input
	if len(input.ProofElements) > 4 {
		return nil, fmt.Errorf("too many proof elements (max 4)")
	}
	if len(input.ProofElements) == 0 {
		return nil, fmt.Errorf("proof elements cannot be empty")
	}
	if len(input.LeafHash) == 0 || len(input.Root) == 0 {
		return nil, fmt.Errorf("leaf hash and root cannot be empty")
	}

	// Convert to circuit-compatible format
	circuitInput := struct {
		LeafHash      *big.Int
		ProofElements [4]*big.Int
		Root          *big.Int
	}{
		LeafHash: new(big.Int).SetBytes(input.LeafHash),
		Root:     new(big.Int).SetBytes(input.Root),
	}

	// Convert proof elements
	for i := 0; i < 4; i++ {
		if i < len(input.ProofElements) {
			circuitInput.ProofElements[i] = new(big.Int).SetBytes(input.ProofElements[i])
		} else {
			circuitInput.ProofElements[i] = new(big.Int) // zero for unused elements
		}
	}

	return GenerateProof("merkle_verify", circuitInput)
}

// P256ProofInput represents the input for p256_verify circuit
type P256ProofInput struct {
	PublicKey struct {
		X, Y []byte
	}
	MessageHash []byte
	Signature   struct {
		R, S []byte
	}
}

// P256Proof generates a proof of a valid ECDSA signature
func P256Proof(input P256ProofInput) (*ProofResult, error) {
	// Validate input
	if len(input.PublicKey.X) == 0 || len(input.PublicKey.Y) == 0 {
		return nil, fmt.Errorf("invalid public key")
	}
	if len(input.MessageHash) == 0 {
		return nil, fmt.Errorf("message hash cannot be empty")
	}
	if len(input.Signature.R) == 0 || len(input.Signature.S) == 0 {
		return nil, fmt.Errorf("invalid signature")
	}

	// Convert to circuit-compatible format
	circuitInput := struct {
		PublicKey struct {
			X, Y *big.Int
		}
		MessageHash *big.Int
		Signature   struct {
			R, S *big.Int
		}
	}{
		PublicKey: struct {
			X, Y *big.Int
		}{
			X: new(big.Int).SetBytes(input.PublicKey.X),
			Y: new(big.Int).SetBytes(input.PublicKey.Y),
		},
		MessageHash: new(big.Int).SetBytes(input.MessageHash),
		Signature: struct {
			R, S *big.Int
		}{
			R: new(big.Int).SetBytes(input.Signature.R),
			S: new(big.Int).SetBytes(input.Signature.S),
		},
	}

	return GenerateProof("p256_verify", circuitInput)
}
