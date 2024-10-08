package util

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	blsMimc "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	sc "github.com/nspcc-dev/neo-go/cli/smartcontract"
	"github.com/nspcc-dev/neo-go/pkg/compiler"
	"github.com/nspcc-dev/neo-go/pkg/smartcontract/manifest"
)

func ensureDataDir() error {
	dataDir := filepath.Join("data")
	if _, err := os.Stat(dataDir); os.IsNotExist(err) {
		return os.MkdirAll(dataDir, 0755)
	}
	return nil
}

func WriteDataToFile(circuitName, filename string, data io.WriterTo) error {
	if err := ensureDataDir(); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}
	file, err := os.Create(filepath.Join("data", fmt.Sprintf("%s_%s", circuitName, filename)))
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	_, err = data.WriteTo(file)
	if err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}
	return nil
}

func ReadProvingKeyFromFile(circuitName string) (groth16.ProvingKey, error) {
	file, err := os.Open(filepath.Join("data", fmt.Sprintf("%s_prover_key", circuitName)))
	if err != nil {
		return nil, fmt.Errorf("failed to open prover key file: %w", err)
	}
	defer file.Close()

	pk := groth16.NewProvingKey(ecc.BLS12_381)
	_, err = pk.ReadFrom(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read prover key: %w", err)
	}

	return pk, nil
}

func ReadVerifyingKeyFromFile(circuitName string) (groth16.VerifyingKey, error) {
	file, err := os.Open(filepath.Join("data", fmt.Sprintf("%s_verifier_key", circuitName)))
	if err != nil {
		return nil, fmt.Errorf("failed to open verifier key file: %w", err)
	}
	defer file.Close()

	vk := groth16.NewVerifyingKey(ecc.BLS12_381)
	_, err = vk.ReadFrom(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read verifier key: %w", err)
	}

	return vk, nil
}

func ReadConstraintSystemFromFile(circuitName string) (constraint.ConstraintSystem, error) {
	file, err := os.Open(filepath.Join("data", fmt.Sprintf("%s_r1cs", circuitName)))
	if err != nil {
		return nil, fmt.Errorf("failed to open r1cs file: %w", err)
	}
	defer file.Close()

	ccs := groth16.NewCS(ecc.BLS12_381)
	_, err = ccs.ReadFrom(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read r1cs: %w", err)
	}

	return ccs, nil
}

func StringToUint64(str string, base int) uint64 {
	bigNum := new(big.Int)
	bigNum.SetString(str, base)
	return bigNum.Uint64()
}

func StringToBigInt(str string, base int) *big.Int {
	bigNum := new(big.Int)
	bigNum.SetString(str, base)
	return bigNum
}

// Use this method to pre-compute hash commitments outside of the circuit.
// Have to instantiate inputs as field elements to make sure
// that hash is computed using the same bytes chunks as the snark field.
// Accepts inputs as uint64 or *big.Int.
func HashInputsToString(inputs []interface{}) string {
	var buf fr.Element
	hasher := blsMimc.NewMiMC()

	for _, input := range inputs {
		switch v := input.(type) {
		case uint64:
			buf.SetUint64(v)
			hasher.Write(buf.Marshal())
		case *big.Int:
			buf.SetBigInt(v)
			hasher.Write(buf.Marshal())
		default:
			panic("Unsupported type")
		}
	}
	hash := new(big.Int).SetBytes(hasher.Sum(nil)).String()
	return hash
}

// A method to compile the verifier contract. Most of
// the code is the same as the NeoGo CLI compile command.
func CompileContract(circuitName string) error {
	src := fmt.Sprintf("contract/%s-verifier.go", circuitName)
	if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
		println("Verifier contract not found. Run the build command first.")
		return nil
	}

	if len(src) == 0 {
		return fmt.Errorf("no input file was found")
	}
	manifestFile := fmt.Sprintf("contract/%s-verifier.manifest.json", circuitName)
	confFile := fmt.Sprintf("contract/%s-verifier.yml", circuitName)
	debugFile := fmt.Sprintf("contract/%s-verifier.dbginfo", circuitName)
	out := fmt.Sprintf("contract/%s-verifier.nef", circuitName)
	bindings := fmt.Sprintf("contract/%s-verifier.bindings.yml", circuitName)
	if len(confFile) == 0 && (len(manifestFile) != 0 || len(debugFile) != 0 || len(bindings) != 0) {
		return fmt.Errorf("no config file was found")
	}
	autocomplete := len(manifestFile) == 0 &&
		len(confFile) == 0 &&
		len(out) == 0 &&
		len(bindings) == 0
	if autocomplete {
		var root string
		fileInfo, err := os.Stat(src)
		if err != nil {
			return fmt.Errorf("failed to stat source file or directory: %w", err)
		}
		if fileInfo.IsDir() {
			base := filepath.Base(fileInfo.Name())
			if base == string(filepath.Separator) {
				base = "contract"
			}
			root = filepath.Join(src, base)
		} else {
			root = strings.TrimSuffix(src, ".go")
		}
		manifestFile = root + ".manifest.json"
		confFile = root + ".yml"
		out = root + ".nef"
		bindings = root + ".bindings.yml"
	}

	o := &compiler.Options{
		Outfile: out,

		DebugInfo:    debugFile,
		ManifestFile: manifestFile,
		BindingsFile: bindings,

		NoStandardCheck:    false,
		NoEventsCheck:      false,
		NoPermissionsCheck: false,

		GuessEventTypes: false,
	}

	if len(confFile) != 0 {
		conf, err := sc.ParseContractConfig(confFile)
		if err != nil {
			return err
		}
		o.Name = conf.Name
		o.SourceURL = conf.SourceURL
		o.ContractEvents = conf.Events
		o.DeclaredNamedTypes = conf.NamedTypes
		o.ContractSupportedStandards = conf.SupportedStandards
		o.Permissions = make([]manifest.Permission, len(conf.Permissions))
		for i := range conf.Permissions {
			o.Permissions[i] = manifest.Permission(conf.Permissions[i])
		}
		o.SafeMethods = conf.SafeMethods
		o.Overloads = conf.Overloads
	}

	result, err := compiler.CompileAndSave(src, o)
	if err != nil {
		return fmt.Errorf("failed to compile: %w", err)
	}
	println("Contract compiled successfully:")
	println(hex.EncodeToString(result))
	return nil
}
