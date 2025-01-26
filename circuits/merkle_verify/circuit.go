package merkle_verify

import (
	"fmt"
	"math/big"
	"zkp_example/circuits"
	"zkp_example/internal/util"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

type Leaf struct {
	SenderKey *big.Int
	Balance   *big.Int
	Nonce     *big.Int
}

const MaxProofElements = 4

type Circuit struct {
	LeafHash      frontend.Variable                   `gnark:",public"` // Hash of the leaf data
	ProofElements [MaxProofElements]frontend.Variable `gnark:",public"` // Array of sibling hashes along the Merkle proof path
	Root          frontend.Variable                   `gnark:",public"` // Expected Merkle root
}

func VerifyMerkleProof(api frontend.API, leafHash, root frontend.Variable, proofElements []frontend.Variable) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	currentHash := leafHash

	for i, proofElement := range proofElements {
		// Perform the hash in path order
		h.Reset()
		h.Write(currentHash)
		h.Write(proofElement)
		newHash := h.Sum()

		// Only update the hash if the proofElement is non-zero
		isZero := api.IsZero(proofElement)
		currentHash = api.Select(isZero, currentHash, newHash)

		api.Println(fmt.Sprintf("Hash after element %d:", i), currentHash)
	}

	api.AssertIsEqual(currentHash, root)
	return nil
}

func (c *Circuit) Define(api frontend.API) error {
	api.Println("LeafHash:", c.LeafHash)
	api.Println("Root:", c.Root)

	// Convert the fixed-size array to a slice
	proofElementsSlice := make([]frontend.Variable, MaxProofElements)
	for i := 0; i < MaxProofElements; i++ {
		proofElementsSlice[i] = c.ProofElements[i]
		api.Println(fmt.Sprintf("ProofElement[%d]:", i), proofElementsSlice[i])
	}

	// Use the VerifyMerkleProof function
	err := VerifyMerkleProof(api, c.LeafHash, c.Root, proofElementsSlice)
	if err != nil {
		return err
	}

	return nil
}

func (c *Circuit) PrepareInput(input interface{}) (circuits.Circuit, []string) {
	// Expecting the input to be a struct with the necessary fields
	inputData, ok := input.(struct {
		LeafHash      *big.Int
		ProofElements []*big.Int
		Root          *big.Int
	})
	if !ok {
		panic("Input must be of the correct type for MerkleVerifyCircuit")
	}

	var proofElements [MaxProofElements]frontend.Variable
	for i := 0; i < len(inputData.ProofElements) && i < MaxProofElements; i++ {
		proofElements[i] = frontend.Variable(inputData.ProofElements[i])
	}
	// Fill the rest with zero values
	for i := len(inputData.ProofElements); i < MaxProofElements; i++ {
		proofElements[i] = frontend.Variable(0)
	}

	return &Circuit{
		LeafHash:      util.StringToBigInt(inputData.LeafHash.String(), 10),
		ProofElements: proofElements,
		Root:          util.StringToBigInt(inputData.Root.String(), 10),
	}, []string{inputData.LeafHash.String(), inputData.Root.String()}
}

func (c *Circuit) ValidInput() circuits.Circuit {
	// Example Merkle tree stores account information for a ZK-Rollup
	// Create two account leaves
	leaves := []Leaf{
		{SenderKey: big.NewInt(1337), Balance: big.NewInt(9001), Nonce: big.NewInt(5)},
		{SenderKey: big.NewInt(420), Balance: big.NewInt(20), Nonce: big.NewInt(13)},
	}

	// Hash leaves
	leafHashes := make([]*big.Int, len(leaves))
	for i, leaf := range leaves {
		leafInputs := []interface{}{leaf.SenderKey, leaf.Balance, leaf.Nonce}
		leafHashed := util.HashInputsToString(leafInputs)
		leafHashes[i] = util.StringToBigInt(leafHashed, 10)
	}

	// Calculate root hash
	rootHashed := util.HashInputsToString([]interface{}{leafHashes[0], leafHashes[1]})
	rootHash := util.StringToBigInt(rootHashed, 10)

	// Create proof for the first leaf
	proofElements := []*big.Int{
		leafHashes[1], // Sibling of the first leaf
	}

	// Prepare the input
	input := struct {
		LeafHash      *big.Int
		ProofElements []*big.Int
		Root          *big.Int
	}{
		LeafHash:      leafHashes[0],
		ProofElements: proofElements,
		Root:          rootHash,
	}

	preparedInput, _ := c.PrepareInput(input)
	return preparedInput
}

func init() {
	circuits.Register("merkle_verify", func() circuits.Circuit { return &Circuit{} })
}
