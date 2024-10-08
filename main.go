package main

import (
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
					var input uint64
					if ctx.IsSet("input") {
						input = util.StringToUint64(ctx.String("input"), 10)
					} else if ctx.NArg() > 0 {
						input = util.StringToUint64(ctx.Args().First(), 10)
					} else {
						return cli.NewExitError("Input is required", 1)
					}
					_, proof, vk, witness, commitment := api.GenerateProof(circuitName, input)
					println("Commitment: ", commitment)
					println("Proof: ", proof)
					println("Verify: ", api.VerifyProof(proof, vk, witness))
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
