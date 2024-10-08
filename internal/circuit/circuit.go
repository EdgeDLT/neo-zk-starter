package circuit

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

type Circuit interface {
	Define(api frontend.API) error
	PrepareInput(input interface{}) (Circuit, string)
	ValidInput() Circuit
}

type CircuitConstructor func() Circuit

var registry = make(map[string]CircuitConstructor)

func RegisterCircuit(name string, constructor CircuitConstructor) {
	registry[name] = constructor
}

func GetCircuit(name string) (Circuit, bool) {
	constructor, exists := registry[name]
	if !exists {
		return nil, false
	}
	return constructor(), true
}

func PrepareWitness(circuit Circuit) (witness.Witness, witness.Witness) {
	witness, _ := frontend.NewWitness(circuit, ecc.BLS12_381.ScalarField())
	publicWitness, _ := witness.Public()

	return witness, publicWitness
}
