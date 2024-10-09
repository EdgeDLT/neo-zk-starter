package main

import (
	"fmt"
	"log"
	"os"

	"zkp_example/api"
	"zkp_example/internal/build"
	"zkp_example/internal/util"

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
						Value: "hash_commitment",
						Usage: "Name of the circuit to build",
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
				Usage:   "Generate a proof for a circuit",
				Action: func(ctx *cli.Context) error {
					circuitName := ctx.String("circuit")
					var input interface{}
					if ctx.IsSet("input") {
						input = ctx.String("input")
					} else if ctx.NArg() > 0 {
						input = ctx.Args().First()
					} else {
						return cli.NewExitError("Input is required", 1)
					}

					// For hash_commitment circuit, convert input to uint64
					if circuitName == "hash_commitment" {
						input = util.StringToUint64(input.(string), 10)
					}

					_, proof, vk, witness, additionalOutput, err := api.GenerateProof(circuitName, input)
					if err != nil {
						return cli.NewExitError(fmt.Sprintf("Failed to generate proof: %v", err), 1)
					}

					// Print all additional output
					for _, output := range additionalOutput {
						println(output)
					}

					println("Proof:", proof)
					verified, err := api.VerifyProof(proof, vk, witness)
					if err != nil {
						return cli.NewExitError(fmt.Sprintf("Failed to verify proof: %v", err), 1)
					}
					println("Verify:", verified)
					return nil
				},
				Flags: []cli.Flag{
					cli.StringFlag{
						Name:  "circuit, c",
						Value: "hash_commitment",
						Usage: "Name of the circuit to use",
					},
					cli.StringFlag{
						Name:  "input, i",
						Usage: "Input for the circuit (optional, can be provided as positional argument)",
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
						Value: "hash_commitment",
						Usage: "Name of the circuit to compile",
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
