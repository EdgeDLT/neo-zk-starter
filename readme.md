## ZK dApp Starter

A zero-knowledge dApp starter template for Neo N3 blockchain developers. This project helps you:
- Write and test ZK circuits in Go
- Generate and verify proofs both on-chain and off-chain
- Deploy ZK-powered smart contracts to Neo N3

Credits to `consensys/gnark` for making ZK tech accessible and `nspcc-dev/neo-go` for bringing them to Neo developers.

### Overview

This repo includes several example circuits demonstrating common ZK patterns:

- `hash_commit`: Proves knowledge of a preimage for a hash commitment
  - Pattern: Prove you know a value without revealing it
  - Use case: Private voting, sealed bids

- `merkle_verify`: Verifies membership in a MiMC-Merkle tree
  - Pattern: Prove membership in a set without revealing the set
  - Use case: Private token transfers, allowlists

- `p256_verify`: Verifies ECDSA signatures on the P256 curve
  - Pattern: Prove signature validity without revealing the signature
  - Use case: Anonymous credentials, private identity verification, recursive proof verification

### Quick Start

1. Generate and verify a proof locally:
```go
// Generate proof
result, err := api.HashCommitProof(42)
if err != nil {
    log.Fatal(err)
}

// Verify locally
verified, err := api.VerifyProof(result.Proof, result.VerifyingKey, result.PublicWitness)
if err != nil {
    log.Fatal(err)
}
log.Printf("Proof verified: %v", verified)
```

2. Deploy a circuit-specific verifier contract and verify on-chain
```ps1
# Generate verifier contract
go run . build -c hash_commit
go run . compile -c hash_commit

# Deploy to Neo N3 and call verify with proof args
verifyArgs := result.VerifyArgs  # Contains formatted proof for Neo verification
# See internal/build/build_test.go for complete deployment and verification example
```

### Project Structure

```
circuits/             # All ZK circuits live here
├── all/             # Imports and registers all circuits
├── hash_commit/     # Hash commitment circuit
├── merkle_verify/   # Merkle tree verification
└── p256_verify/     # P256 signature verification

internal/            # Internal packages
├── build/          # Build process utilities
├── setup/          # Trusted setup utilities
└── util/           # Common utilities
```

### Development Commands

#### Build
Build a circuit, generate proving/verifying keys:
```ps1
go run . build -c <circuit_name>
```

Force rebuild:
```ps1
go run . build -c <circuit_name> -r
```

#### Test
Test a circuit with its ValidInput:
```ps1
go run . prove -c <circuit_name>
```

#### Compile
Generate verifier contract:
```ps1
go run . compile -c <circuit_name>
```

### Adding Your Own Circuit

1. Create a new directory in `circuits/` (e.g., `my_circuit/`)
2. Create circuit files:
   - `circuit.go`: Circuit logic
   - `circuit_test.go`: Circuit tests

3. Implement your circuit:
```go
package my_circuit

import (
    "zkp_example/circuits"
    "github.com/consensys/gnark/frontend"
)

type Circuit struct {
    // Private inputs (known only to prover)
    SecretInput frontend.Variable

    // Public inputs (known to verifier)
    PublicOutput frontend.Variable `gnark:",public"`
}

func (c *Circuit) Define(api frontend.API) error {
    // Your circuit logic here
    // Use api.AssertIsEqual() for constraints
    return nil
}

func (c *Circuit) PrepareInput(input interface{}) (circuits.Circuit, []string) {
    // Convert raw input to circuit input
    // Return (assignment, additionalOutput)
}

func (c *Circuit) ValidInput() circuits.Circuit {
    // Return valid test input
}

func init() {
    circuits.Register("my_circuit", func() circuits.Circuit {
        return &Circuit{}
    })
}
```

4. Add your circuit to `circuits/all/all.go`:
```go
import (
    // ... existing imports ...
    _ "zkp_example/circuits/my_circuit"
)
```

5. Test your circuit:
```ps1
go test ./circuits/my_circuit -v
```

### Neo Smart Contract Integration

1. Build your circuit and generate keys:
```ps1
go run . build -c my_circuit
```

2. Generate the verifier contract:
```ps1
go run . compile -c my_circuit
```

3. Deploy the contract using neo-go

4. Generate and verify proofs:
```go
// Generate proof
result, err := api.GenerateProof("my_circuit", input)

// Get verification args for smart contract
verifyArgs := result.VerifyArgs
// Use verifyArgs with your deployed contract
```

### Testing

Run the test suite:
```ps1
# Test all circuits
go test ./circuits/... -v

# Test Neo integration
go test ./internal/build -v
```

### Production Setup

The development build uses a simplified setup. For production:

1. **Proper Trusted Setup**:
   - Use a proper phase-1 response file for BLS12-381
   - Ensure enough powers of tau for your constraints
   - Consider using [ZCash Sapling attestations](https://github.com/ZcashFoundation/powersoftau-attestations)

2. **Phase-2 Setup**: Replace dummy phase-2 with proper MPC process

3. **Security**:
   - Conduct thorough security audits
   - Test extensively with real-world inputs
   - Consider circuit size and gas costs

Remember that ZK proofs are cryptographic primitives - careful review and testing is essential.