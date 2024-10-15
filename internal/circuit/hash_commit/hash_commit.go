package circuit

import (
	"zkp_example/internal/circuit"
	"zkp_example/internal/util"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type HashCommitCircuit struct {
	HiddenInput     frontend.Variable
	InputCommitment frontend.Variable `gnark:",public"`
}

func (c *HashCommitCircuit) Define(api frontend.API) error {
	// Prepare our MiMC hasher
	// It is a SNARK-friendly alternative to SHA2
	// Provides reduction in constraint count
	// at a cost of a longer verification time
	mimc, _ := mimc.NewMiMC(api)

	// Write the hidden input to the hasher
	mimc.Write(c.HiddenInput)

	// Check that the input commitment matches the hidden input hash
	api.AssertIsEqual(c.InputCommitment, mimc.Sum())

	return nil
}

func (c *HashCommitCircuit) PrepareInput(input interface{}) (circuit.Circuit, []string) {
	// The HashInputsToString function emulates the MiMC hash used in the circuit.
	// It accepts any number of inputs as uint64 or *big.Int.
	// Data is written to the hash in sequential writes, one for each input.
	// The function returns a string representation of the hash.
	// The helper function StringToBigInt can convert the string to a big.Int for use as a circuit input.
	uint64Input, ok := input.(uint64)
	if !ok {
		panic("Input must be uint64 for HashCommitCircuit")
	}

	inputCommit := util.HashInputsToString([]interface{}{uint64Input})

	return &HashCommitCircuit{
		HiddenInput:     uint64Input,
		InputCommitment: util.StringToBigInt(inputCommit, 10),
	}, []string{inputCommit}
}

func (c *HashCommitCircuit) ValidInput() circuit.Circuit {
	var hiddenInput uint64 = 42.0
	preparedInput, _ := c.PrepareInput(hiddenInput)

	return preparedInput
}

func init() {
	circuit.RegisterCircuit("hash_commit", func() circuit.Circuit { return &HashCommitCircuit{} })
}
