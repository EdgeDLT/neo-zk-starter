## ZK dApp starter

This repo is a zero-knowledge dApp example and starter template for building your own ZK-powered apps on the Neo N3 blockchain.

Credits to `consensys/gnark` for making ZK tech accessible and `nspcc-dev/neo-go` for bringing them to Neo developers in a convenient way.

### Overview

This repo allows users to create, test, and work with multiple zero-knowledge circuits.

By default, the commands will build and test the `hash_commitment` circuit, which allows a user to prove they know the preimage for a given hash commitment without revealing the preimage. There is also a `merkle_verify` circuit which can verify a proof for a MiMC-Merkle tree.

Most of the circuit-specific logic lives in `internal/circuit/` directory. Each circuit implements the `Circuit` interface defined in `circuit/circuit.go`.

### Build

To build a circuit, run:
```ps1
go run . build -c <circuit_name>
```
This will build the specified circuit, generate proving/verifying keys, and generate verifier contracts. The default circuit is "hash_commitment" if not specified.

Use the -r or --rebuild flag to force a rebuild:

```ps1
go run . build -c <circuit_name> -r
```

### Prove

Generate and verify a proof for a circuit by running:

```ps1
go run . prove -c <circuit_name> -i <input_value>
```

or

```ps1
go run . prove -c <circuit_name> <input_value>
```


### Test

Run the test suite to test circuit execution, proof verification, and on-chain proof verification in a verifier contract, deployed to a local NeoGo private network:
```ps1
go test ./internal/circuit -v
go test ./internal/build -v
```

### Compile

Compile the verifier contract for deployment by running:

```ps1
go run . compile -c <circuit_name>
```

### Modify

To add your own ZKP circuit:

1. Create a new file in `internal/circuit/` (e.g., `my_circuit.go`).
2. Implement your circuit.
3. Implement the Circuit interface for your new circuit.
4. Register your circuit in the init() function of your new file:

```ps1
func init() {
    RegisterCircuit("my_circuit", func() Circuit { return &MyCircuit{} })
}
```
4. Add specific tests for your circuit in a new test file (e.g., `my_circuit_test.go`).

The existing commands (build, prove, compile) will automatically work with your new circuit once it's registered.

### Moving forward

The build process in `build.go` uses the `groth16.Setup()` method to perform the two-phase setup ceremony. This is a shortcut to be used for development purposes only.

For production use, a proper trusted setup ceremony should be conducted. This involves a multi-party computation process to generate the proving and verifying keys in a way that ensures no single party has complete knowledge of the secret randomness used in the setup. An example can be found in `setup/setup.go`.

Note that production setup requires a proper phase-1 response file, with a ceremony held over the BLS12-381 curve used on Neo, and with enough powers of tau to generate the required number of constraints for the circuit. One good source of appropriate response files is the [attestations repository](https://github.com/ZcashFoundation/powersoftau-attestations) from the ZCash Sapling upgrade. Also note that phase-2 contributions are dummied, and should be replaced with a proper MPC process.

Remember to always use appropriate security measures and conduct thorough testing before deploying any ZK application in a production environment.