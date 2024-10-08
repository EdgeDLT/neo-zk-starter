package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"
)

// Test executing the circuit without running a ZK-SNARK prover (with the
// help of test engine). It can be useful for the circuit debugging, see
// https://docs.gnark.consensys.net/HowTo/debug_test#common-errors.
func TestCircuitExecution(t *testing.T) {
	for name, constructor := range registry {
		t.Run(name, func(t *testing.T) {
			circ := constructor()
			assignment := circ.ValidInput()
			err := test.IsSolved(circ, assignment, ecc.BLS12_381.ScalarField())
			if err != nil {
				t.Errorf("Circuit %s failed: %v", name, err)
			}
		})
	}
}

// TestVerification performs the circuit correctness testing
// over a specific curve and backend. It runs the circuit against a
// set of invalid inputs and ensures that the circuit fails to prove them.
func TestCircuitVerification(t *testing.T) {
	for name, constructor := range registry {
		t.Run(name, func(t *testing.T) {
			assert := test.NewAssert(t)
			circ := constructor()
			assignment := circ.ValidInput()

			assert.ProverSucceeded(circ, assignment,
				test.WithCurves(ecc.BLS12_381),
				test.WithBackends(backend.GROTH16))

			// You might want to add more general tests here,
			// like testing with invalid inputs if possible
		})
	}
}
