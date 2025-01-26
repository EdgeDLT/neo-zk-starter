package circuits

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
)

// Circuit defines the interface that all circuits must implement
type Circuit interface {
	Define(api frontend.API) error
	PrepareInput(input interface{}) (Circuit, []string)
	ValidInput() Circuit
}

// Registry stores all available circuits
type Registry struct {
	circuits map[string]func() Circuit
}

// Global registry instance
var registry = &Registry{
	circuits: make(map[string]func() Circuit),
}

// Register adds a new circuit to the registry
func Register(name string, constructor func() Circuit) {
	registry.circuits[name] = constructor
}

// Get retrieves a circuit by name
func Get(name string) (Circuit, bool) {
	constructor, exists := registry.circuits[name]
	if !exists {
		return nil, false
	}
	return constructor(), true
}

// ListCircuits returns all registered circuit names
func ListCircuits() []string {
	names := make([]string, 0, len(registry.circuits))
	for name := range registry.circuits {
		names = append(names, name)
	}
	return names
}

// PrepareWitness creates witness from circuit
func PrepareWitness(circuit Circuit) (witness.Witness, witness.Witness) {
	witness, _ := frontend.NewWitness(circuit, ecc.BLS12_381.ScalarField())
	publicWitness, _ := witness.Public()
	return witness, publicWitness
}
