package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/nspcc-dev/neo-go/pkg/crypto/hash"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
)

type P256SigVerifyCircuit struct {
	PublicKey   ecdsa.PublicKey[emparams.P256Fp, emparams.P256Fr] `gnark:",public"`
	Signature   ecdsa.Signature[emparams.P256Fr]                  `gnark:",public"`
	MessageHash emulated.Element[emparams.P256Fr]                 `gnark:",public"`
}

func (c *P256SigVerifyCircuit) Define(api frontend.API) error {

	c.PublicKey.Verify(api, sw_emulated.GetP256Params(), &c.MessageHash, &c.Signature)

	return nil
}

func (c *P256SigVerifyCircuit) PrepareInput(input interface{}) (Circuit, []string) {

	inputData, ok := input.(struct {
		PublicKey   *keys.PublicKey
		MessageHash []byte
		Signature   []byte
	})
	if !ok {
		panic("Input must be of the correct type for P256SigVerifyCircuit")
	}

	keyX := emulated.ValueOf[emparams.P256Fp](inputData.PublicKey.X.Bytes())
	keyY := emulated.ValueOf[emparams.P256Fp](inputData.PublicKey.Y.Bytes())
	sigR := emulated.ValueOf[emparams.P256Fr](inputData.Signature[:32])
	sigS := emulated.ValueOf[emparams.P256Fr](inputData.Signature[32:])
	msg := emulated.ValueOf[emparams.P256Fr](inputData.MessageHash)

	return &P256SigVerifyCircuit{
		PublicKey: ecdsa.PublicKey[emparams.P256Fp, emparams.P256Fr]{
			X: keyX,
			Y: keyY,
		},
		Signature: ecdsa.Signature[emparams.P256Fr]{
			R: sigR,
			S: sigS,
		},
		MessageHash: msg,
	}, []string{}
}

func (c *P256SigVerifyCircuit) ValidInput() Circuit {

	w, _ := wallet.NewAccount()
	MessageHash := []byte("hello world")
	hashed := hash.Sha256(MessageHash)
	signature := w.PrivateKey().SignHash(hashed)

	preparedInputs, _ := c.PrepareInput(struct {
		PublicKey   *keys.PublicKey
		MessageHash []byte
		Signature   []byte
	}{
		PublicKey:   w.PublicKey(),
		MessageHash: hashed.BytesBE(),
		Signature:   signature,
	})

	return preparedInputs
}

func init() {
	RegisterCircuit("p256_sig_verify", func() Circuit { return &P256SigVerifyCircuit{} })
}
