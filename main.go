package main

import (
	"fmt"
	"log"
	"os"

	"neo_zk_starter/api"
	"neo_zk_starter/circuits"
	_ "neo_zk_starter/circuits/all"
	"neo_zk_starter/internal/build"
	"neo_zk_starter/internal/util"

	"github.com/urfave/cli"
)

func main() {
	app := &cli.App{
		Name:  "zk circuit verifier",
		Usage: "build zk circuits, generate keys, prove and verify computations, compile and deploy verifier contracts",
		Commands: []cli.Command{
			{
				Name:    "build",
				Aliases: []string{"b"},
				Usage:   "Build the circuit, generate keys and the verifier contract",
				Action: func(ctx *cli.Context) error {
					circuitName := ctx.String("circuit")
					rebuild := ctx.Bool("rebuild")
					build.Build(circuitName, rebuild)
					return nil
				},
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:  "circuit, c",
						Value: "hash_commit",
						Usage: fmt.Sprintf("Name of the circuit to build. Available: %v", circuits.ListCircuits()),
					},
					cli.BoolFlag{
						Name:  "rebuild, r",
						Usage: "Force rebuild of the circuit",
					},
				},
			},
			{
				Name:    "prove",
				Aliases: []string{"p"},
				Usage:   "Generate and verify a proof using test inputs",
				Action: func(ctx *cli.Context) error {
					circuitName := ctx.String("circuit")

					// Get circuit and its test input
					circuit, exists := circuits.Get(circuitName)
					if !exists {
						return fmt.Errorf("circuit not found: %s", circuitName)
					}

					input := circuit.ValidInput()

					// Generate proof
					result, err := api.GenerateProof(circuitName, input)
					if err != nil {
						return fmt.Errorf("failed to generate proof: %v", err)
					}

					// Print any additional output
					for _, output := range result.AdditionalData {
						fmt.Println(output)
					}

					// Verify the proof
					verified, err := api.VerifyProof(result.Proof, result.VerifyingKey, result.PublicWitness)
					if err != nil {
						return fmt.Errorf("failed to verify proof: %v", err)
					}

					fmt.Printf("Proof generated and verified: %v\n", verified)
					return nil
				},
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:  "circuit, c",
						Value: "hash_commit",
						Usage: fmt.Sprintf("Name of the circuit to prove. Available: %v", circuits.ListCircuits()),
					},
				},
			},
			{
				Name:    "compile",
				Aliases: []string{"c"},
				Usage:   "Compile the Groth16 verifier contract, ready for deployment.",
				Action: func(ctx *cli.Context) error {
					circuitName := ctx.String("circuit")
					err := util.CompileContract(circuitName)
					if err != nil {
						return err
					}
					return nil
				},
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:  "circuit, c",
						Value: "hash_commit",
						Usage: fmt.Sprintf("Name of the circuit to compile. Available: %v", circuits.ListCircuits()),
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
