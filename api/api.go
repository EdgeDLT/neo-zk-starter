package api

import (
	"fmt"
	"neo_zk_starter/circuits"
	"neo_zk_starter/internal/build"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/nspcc-dev/neo-go/pkg/smartcontract/zkpbinding"
)

// ProofResult contains all outputs from proof generation
type ProofResult struct {
	VerifyArgs     *zkpbinding.VerifyProofArgs
	Proof          groth16.Proof
	VerifyingKey   groth16.VerifyingKey
	PublicWitness  witness.Witness
	AdditionalData []string
}

// GenerateProof generates a proof for the specified circuit with the given input.
// The input type must match what the circuit's PrepareInput method expects.
// For example:
// - hash_commit: expects uint64
// - merkle_verify: expects struct{LeafHash, ProofElements, Root}
// - p256_verify: expects struct{PublicKey, MessageHash, Signature}
func GenerateProof(circuitName string, input interface{}) (*ProofResult, error) {
	circ, exists := circuits.Get(circuitName)
	if !exists {
		return nil, fmt.Errorf("circuit not found: %s", circuitName)
	}

	assignment, additionalOutput := circ.PrepareInput(input)
	if assignment == nil {
		return nil, fmt.Errorf("failed to prepare input for circuit %s", circuitName)
	}

	_, ccs, pk, vk := build.Init(circuitName, false)
	witness, publicWitness := circuits.PrepareWitness(assignment)

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	args, err := zkpbinding.GetVerifyProofArgs(proof, publicWitness)
	if err != nil {
		return nil, fmt.Errorf("failed to get verify proof args: %w", err)
	}

	return &ProofResult{
		VerifyArgs:     args,
		Proof:          proof,
		VerifyingKey:   vk,
		PublicWitness:  publicWitness,
		AdditionalData: additionalOutput,
	}, nil
}

// VerifyProof verifies a proof against a verifying key and public witness
func VerifyProof(proof groth16.Proof, vk groth16.VerifyingKey, publicWitness witness.Witness) (bool, error) {
	err := groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		return false, fmt.Errorf("proof verification failed: %w", err)
	}
	return true, nil
}
