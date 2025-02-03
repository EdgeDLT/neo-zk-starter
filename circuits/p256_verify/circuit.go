package p256_verify

import (
	"neo_zk_starter/circuits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/signature/ecdsa"
	"github.com/nspcc-dev/neo-go/pkg/crypto/hash"
	"github.com/nspcc-dev/neo-go/pkg/crypto/keys"
	"github.com/nspcc-dev/neo-go/pkg/wallet"
)

type Circuit struct {
	PublicKey   ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr] `gnark:",public"`
	Signature   ecdsa.Signature[emulated.P256Fr]                  `gnark:",public"`
	MessageHash emulated.Element[emulated.P256Fr]                 `gnark:",public"`
}

func VerifyP256Sig(api frontend.API, publicKey ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr], messageHash emulated.Element[emulated.P256Fr], signature ecdsa.Signature[emulated.P256Fr]) {
	publicKey.Verify(api, sw_emulated.GetP256Params(), &messageHash, &signature)
}

func (c *Circuit) Define(api frontend.API) error {
	VerifyP256Sig(api, c.PublicKey, c.MessageHash, c.Signature)
	return nil
}

func (c *Circuit) PrepareInput(input interface{}) (circuits.Circuit, []string) {
	inputData, ok := input.(struct {
		PublicKey   *keys.PublicKey
		MessageHash []byte
		Signature   []byte
	})
	if !ok {
		panic("Input must be of the correct type for P256SigVerifyCircuit")
	}

	keyX := emulated.ValueOf[emulated.P256Fp](inputData.PublicKey.X.Bytes())
	keyY := emulated.ValueOf[emulated.P256Fp](inputData.PublicKey.Y.Bytes())
	sigR := emulated.ValueOf[emulated.P256Fr](inputData.Signature[:32])
	sigS := emulated.ValueOf[emulated.P256Fr](inputData.Signature[32:])
	msg := emulated.ValueOf[emulated.P256Fr](inputData.MessageHash)

	return &Circuit{
		PublicKey: ecdsa.PublicKey[emulated.P256Fp, emulated.P256Fr]{
			X: keyX,
			Y: keyY,
		},
		Signature: ecdsa.Signature[emulated.P256Fr]{
			R: sigR,
			S: sigS,
		},
		MessageHash: msg,
	}, []string{}
}

func (c *Circuit) ValidInput() circuits.Circuit {
	w, _ := wallet.NewAccount()
	messageHash := []byte("hello world")
	hashed := hash.Sha256(messageHash)
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
	circuits.Register("p256_verify", func() circuits.Circuit { return &Circuit{} })
}
