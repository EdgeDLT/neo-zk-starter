package api

import (
	"fmt"
	"zkp_example/internal/build"
	"zkp_example/internal/circuit"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/nspcc-dev/neo-go/pkg/smartcontract/zkpbinding"
)

// GenerateProof generates a proof for the specified circuit with the given input
func GenerateProof(circuitName string, input interface{}) (*zkpbinding.VerifyProofArgs, groth16.Proof, groth16.VerifyingKey, witness.Witness, []string, error) {
	circ, exists := circuit.GetCircuit(circuitName)
	if !exists {
		return nil, nil, nil, nil, nil, fmt.Errorf("circuit not found: %s", circuitName)
	}

	assignment, additionalOutput := circ.PrepareInput(input)

	_, ccs, pk, vk := build.Init(circuitName, false)
	witness, publicWitness := circuit.PrepareWitness(assignment)

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	args, err := zkpbinding.GetVerifyProofArgs(proof, publicWitness)
	if err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("failed to get verify proof args: %w", err)
	}

	return args, proof, vk, publicWitness, additionalOutput, nil
}

// Verifies that the proof is valid
func VerifyProof(proof groth16.Proof, vk groth16.VerifyingKey, publicWitness witness.Witness) (bool, error) {
	err := groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		return false, fmt.Errorf("proof verification failed: %w", err)
	}
	return true, nil
}
