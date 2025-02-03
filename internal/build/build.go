package build

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"neo_zk_starter/circuits"
	"neo_zk_starter/internal/util"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/nspcc-dev/neo-go/pkg/smartcontract/zkpbinding"
)

func createKeysAndCircuit(circuitName string, circ circuits.Circuit) (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	println("Creating new proving/verifying keys and circuit")
	ccs, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, circ)
	if err != nil {
		panic(fmt.Sprintf("Failed to compile circuit: %v", err))
	}
	pk, vk, err := groth16.Setup(ccs)
	// pk, vk, err := .Setup(ccs, "data/response21", 21) // use a real response file for production
	if err != nil {
		panic(fmt.Sprintf("Failed to setup keys: %v", err))
	}

	util.WriteDataToFile(circuitName, "prover_key", pk)
	util.WriteDataToFile(circuitName, "verifier_key", vk)
	util.WriteDataToFile(circuitName, "r1cs", ccs)

	println("Created key and circuit files")

	return ccs, pk, vk
}

func Init(circuitName string, rebuild bool) (circuits.Circuit, constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey) {
	circ, exists := circuits.Get(circuitName)
	if !exists {
		panic("Circuit not found")
	}

	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	var ccs constraint.ConstraintSystem

	// Check if the 'prover-key' file exists
	if rebuild {
		println("Rebuilding proving/verifying keys and circuit")
		ccs, pk, vk = createKeysAndCircuit(circuitName, circ)
	} else if _, err := os.Stat(filepath.Join("data", fmt.Sprintf("%s_prover_key", circuitName))); errors.Is(err, os.ErrNotExist) {
		ccs, pk, vk = createKeysAndCircuit(circuitName, circ)
	} else {
		println("Files exist, loading existing proving/verifying keys and circuit")

		pk, _ = util.ReadProvingKeyFromFile(circuitName)
		vk, _ = util.ReadVerifyingKeyFromFile(circuitName)
		ccs, _ = util.ReadConstraintSystemFromFile(circuitName)
	}

	return circ, ccs, pk, vk
}

func PrepareWitness(assignment circuits.Circuit) (witness.Witness, witness.Witness) {

	// define the witness
	witness, _ := frontend.NewWitness(assignment, ecc.BLS12_381.ScalarField())
	publicWitness, _ := witness.Public()

	return witness, publicWitness
}

func Build(circuitName string, rebuild bool) (string, string, *zkpbinding.VerifyProofArgs) {
	circuit, exists := circuits.Get(circuitName)
	if !exists {
		panic(fmt.Sprintf("Circuit not found: %s", circuitName))
	}

	// Step 1: compile circuit code into R1CS and setup keys
	_, ccs, pk, vk := Init(circuitName, rebuild)

	// Step 2: prepare inputs
	assignment := circuit.ValidInput()

	// Step 3: setup test witness
	witness, publicWitness := circuits.PrepareWitness(assignment)

	// Step 4: create groth16 proof
	proof, _ := groth16.Prove(ccs, pk, witness)

	// Step 5: verify proof
	_ = groth16.Verify(proof, vk, publicWitness)

	// Step 6: export verifier smart contract

	// Create contract file.
	_ = os.Mkdir("contract/", os.ModePerm)
	srcPath := filepath.Join("contract/", circuitName+"-verifier.go")
	f, _ := os.Create(srcPath)

	// Create contract configuration file.
	cfgPath := filepath.Join("contract/", circuitName+"-verifier.yml")
	fCfg, _ := os.Create(cfgPath)

	// Create contract go.mod and go.sum files.
	fMod, _ := os.Create(filepath.Join("contract/", "go.mod"))
	fSum, _ := os.Create(filepath.Join("contract/", "go.sum"))

	// Generate Verifier contract itself.
	_ = zkpbinding.GenerateVerifier(zkpbinding.Config{
		VerifyingKey: vk,
		Output:       f,
		CfgOutput:    fCfg,
		GomodOutput:  fMod,
		GosumOutput:  fSum,
	})

	args, _ := zkpbinding.GetVerifyProofArgs(proof, publicWitness)
	println("argA: ", formatByteSlice(args.A))
	println("argB: ", formatByteSlice(args.B))
	println("argC: ", formatByteSlice(args.C))
	for i, v := range args.PublicWitnesses {
		println("publicWitness[", i, "]: ", formatByteSlice(v.([]byte)))
	}

	return srcPath, cfgPath, args
}

// Format the byte slice as a Go byte array
func formatByteSlice(bytes []byte) string {
	formatted := ""
	for i, b := range bytes {
		if i > 0 {
			formatted += ", "
		}
		formatted += fmt.Sprintf("%d", b)
	}
	return formatted
}
