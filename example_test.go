package main

import (
	"testing"

	"zkp_example/api"
	_ "zkp_example/circuits/all" // Important: register all circuits
)

func TestProofGeneration(t *testing.T) {
	// 1. Generate a hash commitment proof
	result, err := api.HashCommitProof(42)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Get the verification args ready for the smart contract
	verifyArgs := result.VerifyArgs
	t.Logf("Proof verification args for smart contract:")
	t.Logf("A: %v", verifyArgs.A)
	t.Logf("B: %v", verifyArgs.B)
	t.Logf("C: %v", verifyArgs.C)
	t.Logf("Public Witnesses: %v", verifyArgs.PublicWitnesses)

	// 3. Optional: Verify locally before sending to chain
	verified, err := api.VerifyProof(result.Proof, result.VerifyingKey, result.PublicWitness)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Local verification result: %v", verified)
}
