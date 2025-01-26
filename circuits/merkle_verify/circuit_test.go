package merkle_verify

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

func TestCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := &Circuit{}
	validAssignment := circuit.ValidInput().(*Circuit)

	// Test with valid inputs
	assert.ProverSucceeded(circuit, validAssignment,
		test.WithCurves(ecc.BLS12_381),
		test.WithBackends(backend.GROTH16))

	// Test with invalid root
	invalidRootAssignment := &Circuit{
		LeafHash:      validAssignment.LeafHash,
		ProofElements: validAssignment.ProofElements,
		Root:          frontend.Variable(420), // Some arbitrary invalid root
	}
	assert.ProverFailed(circuit, invalidRootAssignment,
		test.WithCurves(ecc.BLS12_381),
		test.WithBackends(backend.GROTH16))

	// Test with invalid leaf hash
	invalidLeafAssignment := &Circuit{
		LeafHash:      frontend.Variable(5000), // Some arbitrary invalid leaf hash
		ProofElements: validAssignment.ProofElements,
		Root:          validAssignment.Root,
	}
	assert.ProverFailed(circuit, invalidLeafAssignment,
		test.WithCurves(ecc.BLS12_381),
		test.WithBackends(backend.GROTH16))

	// Test with invalid proof element
	invalidProofAssignment := &Circuit{
		LeafHash: validAssignment.LeafHash,
		ProofElements: func() [MaxProofElements]frontend.Variable {
			pe := validAssignment.ProofElements
			pe[0] = frontend.Variable(12345) // Modify the first proof element
			return pe
		}(),
		Root: validAssignment.Root,
	}
	assert.ProverFailed(circuit, invalidProofAssignment,
		test.WithCurves(ecc.BLS12_381),
		test.WithBackends(backend.GROTH16))

	// Test with extra (non-zero) proof element
	extraProofAssignment := &Circuit{
		LeafHash: validAssignment.LeafHash,
		ProofElements: func() [MaxProofElements]frontend.Variable {
			pe := validAssignment.ProofElements
			pe[1] = frontend.Variable(33333) // Add an extra non-zero element
			return pe
		}(),
		Root: validAssignment.Root,
	}
	assert.ProverFailed(circuit, extraProofAssignment,
		test.WithCurves(ecc.BLS12_381),
		test.WithBackends(backend.GROTH16))
}
