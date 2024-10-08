package build

import (
	"encoding/base64"
	"fmt"
	"testing"

	_ "zkp_example/internal/test_init"

	"github.com/nspcc-dev/neo-go/pkg/neotest"
	"github.com/nspcc-dev/neo-go/pkg/neotest/chain"
)

// More about circuit testing using gnark/test package: https://pkg.go.dev/github.com/consensys/gnark/test@v0.7.0
func TestBuild(t *testing.T) {
	circuitNames := []string{"hash_commitment"} // Add more circuit names as needed

	for _, circuitName := range circuitNames {
		t.Run(circuitName, func(t *testing.T) {
			// Run the build path
			srcPath, cfgPath, args := Build(circuitName, false)

			// Create testing chain and deploy contract onto it.
			bc, committee := chain.NewSingle(t)
			e := neotest.NewExecutor(t, bc, committee, committee)

			// Compile verification contract and deploy the contract onto chain.
			c := neotest.CompileFile(t, e.Validator.ScriptHash(), srcPath, cfgPath)
			e.DeployContract(t, c, nil)

			// Verify proof via verification contract call.
			validatorInvoker := e.ValidatorInvoker(c.Hash)
			h := validatorInvoker.Invoke(t, true, "verifyProof", args.A, args.B, args.C, args.PublicWitnesses)

			tx, _ := e.GetTransaction(t, h)
			r := e.GetTxExecResult(t, h)

			fmt.Println("\n----- Execution Result -----")
			fmt.Println("Tx script: ", base64.StdEncoding.EncodeToString(tx.Script))
			fmt.Printf("Tx result: %+v", r)
			fmt.Println("\n-----------------------------")
		})
	}
}
