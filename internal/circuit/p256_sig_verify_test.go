package circuit

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/consensys/gnark/test"
	"github.com/nspcc-dev/neo-go/pkg/crypto/hash"
)

func TestP256SigVerifyCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := &P256SigVerifyCircuit{}
	validAssignment := circuit.ValidInput().(*P256SigVerifyCircuit)

	// Test with valid inputs
	assert.ProverSucceeded(circuit, validAssignment,
		test.WithCurves(ecc.BW6_761),
		test.WithBackends(backend.GROTH16))

	// Test with invalid signature
	invalidSigAssignment := &P256SigVerifyCircuit{
		PublicKey: validAssignment.PublicKey,
		Signature: ecdsa.Signature[emparams.P256Fr]{
			R: validAssignment.Signature.R,
			S: validAssignment.Signature.R, // duplicated R
		},
		MessageHash: validAssignment.MessageHash,
	}
	assert.ProverFailed(circuit, invalidSigAssignment,
		test.WithCurves(ecc.BW6_761),
		test.WithBackends(backend.GROTH16))

	// Test with invalid MessageHash
	mockHash := hash.Sha256([]byte("construct additional pylons"))
	invalidMsgAssignment := &P256SigVerifyCircuit{
		PublicKey:   validAssignment.PublicKey,
		Signature:   validAssignment.Signature,
		MessageHash: emulated.ValueOf[emparams.P256Fr](mockHash.BytesBE()), // Some arbitrary invalid MessageHash
	}
	assert.ProverFailed(circuit, invalidMsgAssignment,
		test.WithCurves(ecc.BW6_761),
		test.WithBackends(backend.GROTH16))
}
