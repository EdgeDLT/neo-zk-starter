package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

func TestHashCommitCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := &HashCommitCircuit{}
	assignment := circuit.ValidInput().(*HashCommitCircuit)

	// Test with wrong input for commitment
	assert.ProverFailed(circuit, &HashCommitCircuit{
		HiddenInput:     9,
		InputCommitment: assignment.InputCommitment,
	}, test.WithCurves(ecc.BLS12_381), test.WithBackends(backend.GROTH16))

	// Test with wrong commitment for input
	assert.ProverFailed(circuit, &HashCommitCircuit{
		HiddenInput:     assignment.HiddenInput,
		InputCommitment: 1,
	}, test.WithCurves(ecc.BLS12_381), test.WithBackends(backend.GROTH16))

	// Test with valid inputs
	assert.ProverSucceeded(circuit, assignment,
		test.WithCurves(ecc.BLS12_381),
		test.WithBackends(backend.GROTH16))
}
