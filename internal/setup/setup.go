package setup

import (
	"fmt"
	"math"
	"os"

	curve "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bls12-381"
)

// setup generates proving and verifying keys for the given compiled constrained
// system. It accepts path to the response file from Phase 1 of the Powers of Tau
// ceremony for the BLS12-381 curve and the power of the ceremony.
// See the README.md for details on the Phase 1 response file. It makes
// circuit-specific Phase 2 initialisation of the MPC ceremony and performs some
// dummy contributions for Phase 2. In production environment, participant will
// receive a []byte, deserialize it, add his contribution and send back to the
// coordinator.
func Setup(ccs constraint.ConstraintSystem, phase1ResponsePath string, inPow int) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	const (
		nContributionsPhase2 = 3
		blake2bHashSize      = 64
	)

	f, err := os.Open(phase1ResponsePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file: %w", err)
	}

	// Skip hash of the previous contribution, don't need it for the MPC initialisation.
	_, err = f.Seek(blake2bHashSize, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to seek file: %w", err)
	}
	dec := curve.NewDecoder(f)

	// Retrieve parameters.
	inN := int(math.Pow(2, float64(inPow)))
	coef_g1 := make([]curve.G1Affine, 2*inN-1)
	coef_g2 := make([]curve.G2Affine, inN)
	alpha_coef_g1 := make([]curve.G1Affine, inN)
	beta_coef_g1 := make([]curve.G1Affine, inN)

	// Accumulator serialization: https://github.com/filecoin-project/powersoftau/blob/ab8f85c28f04af5a99cfcc93a3b1f74c06f94105/src/accumulator.rs#L111
	for i := range coef_g1 {
		if err := dec.Decode(&coef_g1[i]); err != nil {
			return nil, nil, fmt.Errorf("failed to decode coef_g1: %w", err)
		}
	}
	for i := range coef_g2 {
		if err := dec.Decode(&coef_g2[i]); err != nil {
			return nil, nil, fmt.Errorf("failed to decode coef_g2: %w", err)
		}
	}
	for i := range alpha_coef_g1 {
		if err := dec.Decode(&alpha_coef_g1[i]); err != nil {
			return nil, nil, fmt.Errorf("failed to decode alpha_coef_g1: %w", err)
		}
	}
	for i := range beta_coef_g1 {
		if err := dec.Decode(&beta_coef_g1[i]); err != nil {
			return nil, nil, fmt.Errorf("failed to decode beta_coef_g1: %w", err)
		}
	}
	beta_g2 := &curve.G2Affine{}
	if err := dec.Decode(beta_g2); err != nil {
		return nil, nil, fmt.Errorf("failed to decode beta_g2: %w", err)
	}

	// Transform (take exactly those number of powers that needed for the given number of constraints).
	var (
		numConstraints = ccs.GetNbConstraints()
		outPow         int
	)
	for ; 1<<outPow < numConstraints; outPow++ {
	}
	outN := int64(math.Pow(2, float64(outPow)))

	// setup the SRS
	srs1 := mpcsetup.Phase1{}
	srs1.Parameters.G1.Tau = coef_g1[:2*outN-1]        // outN + (outN-1)
	srs1.Parameters.G2.Tau = coef_g2[:outN]            // outN
	srs1.Parameters.G1.AlphaTau = alpha_coef_g1[:outN] // outN
	srs1.Parameters.G1.BetaTau = beta_coef_g1[:outN]   // outN
	srs1.Parameters.G2.Beta = *beta_g2                 // 1

	// Prepare for phase-2
	var evals mpcsetup.Phase2Evaluations
	r1cs := ccs.(*cs.R1CS)
	srs2, evals := mpcsetup.InitPhase2(r1cs, &srs1)

	// Make some dummy contributions for phase2. In practice, participant will
	// receive a []byte, deserialize it, add his contribution and send back to
	// coordinator, like it is done in https://github.com/bnb-chain/zkbnb-setup
	// for BN254 elliptic curve.
	for i := 0; i < nContributionsPhase2; i++ {
		srs2.Contribute()
	}

	// Extract the proving and verifying keys
	pk, vk := mpcsetup.ExtractKeys(&srs1, &srs2, &evals, ccs.GetNbConstraints())
	return &pk, &vk, nil
}
