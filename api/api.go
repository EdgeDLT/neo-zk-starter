package api

import (
	"zkp_example/internal/build"
	"zkp_example/internal/circuit"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/nspcc-dev/neo-go/pkg/smartcontract/zkpbinding"
)

// Returns the proof, public witness, and location commitment
func GenerateProof(circuitName string, input uint64) (*zkpbinding.VerifyProofArgs, groth16.Proof, groth16.VerifyingKey, witness.Witness, string) {
	circ, exists := circuit.GetCircuit(circuitName)
	if !exists {
		panic("Circuit not found")
	}

	assignment, locationCommit := circ.PrepareInput(input)

	_, ccs, pk, vk := build.Init(circuitName, false)
	witness, publicWitness := circuit.PrepareWitness(assignment)

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		panic(err)
	}

	args, _ := zkpbinding.GetVerifyProofArgs(proof, publicWitness)
	return args, proof, vk, publicWitness, locationCommit
}

// Verifies that the proof is valid
func VerifyProof(proof groth16.Proof, vk groth16.VerifyingKey, publicWitness witness.Witness) bool {
	err := groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		return false
	}
	return true
}
