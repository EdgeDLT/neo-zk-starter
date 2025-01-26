package circuits

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

// Test executing all registered circuits without running a ZK-SNARK prover.
// Useful for circuit debugging, see:
// https://docs.gnark.consensys.net/HowTo/debug_test#common-errors
func TestCircuitExecution(t *testing.T) {
	for _, name := range ListCircuits() {
		t.Run(name, func(t *testing.T) {
			circ, _ := Get(name)
			assignment := circ.ValidInput()
			err := test.IsSolved(circ, assignment, ecc.BLS12_381.ScalarField())
			if err != nil {
				t.Errorf("Circuit %s failed: %v", name, err)
			}
		})
	}
}

// TestVerification performs circuit correctness testing
// over BLS12-381 curve using the Groth16 backend.
func TestCircuitVerification(t *testing.T) {
	for _, name := range ListCircuits() {
		t.Run(name, func(t *testing.T) {
			assert := test.NewAssert(t)
			circ, _ := Get(name)
			assignment := circ.ValidInput()

			assert.ProverSucceeded(circ, assignment,
				test.WithCurves(ecc.BLS12_381),
				test.WithBackends(backend.GROTH16))
		})
	}
}
