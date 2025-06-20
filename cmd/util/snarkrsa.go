package util

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

//type JWTRSACircuit struct {
//	// --- Public Inputs ---
//	// Pass everything as bit.Int for easy validation
//
//	EmPrime frontend.Variable `gnark:",public"`
//
//	// PublicKeyN is the modulus N of the RSA public key.
//	PublicKeyN frontend.Variable `gnark:",public"`
//
//	// PublicKeyE is the public exponent E of the RSA public key (e.g., 65537).
//	PublicKeyE frontend.Variable `gnark:",public"`
//
//	// --- Private Inputs (Witness) ---
//
//	// Signature is an array of frontend.Variable, where each Variable is a byte of the RSA signature.
//	// The size must match the RSA key size in bytes (e.g., 256 for RSA-2048).
//	Signature frontend.Variable // Assuming a 2048-bit RSA key (2048/8 = 256 bytes)
//}
//
//// Define the circuit logic using the gnark frontend API.
//func (circuit *JWTRSACircuit) Define(api frontend.API) error {
//	f, err := emulated.NewField[emparams.Mod1e4096](api)
//	if err != nil {
//		return fmt.Errorf("new variable modulus: %w", err)
//	}
//	modulus := f.NewElement(circuit.PublicKeyN)
//	exp := f.NewElement(circuit.PublicKeyE)
//	base := f.NewElement(circuit.Signature)
//	res := f.ModExp(base, exp, modulus)
//
//	expected := f.NewElement(circuit.EmPrime)
//	f.AssertIsEqual(expected, res)
//
//	return nil
//}

type JWTRSACircuit struct {
	// --- Public Inputs ---
	// Pass everything as bit.Int for easy validation

	EmPrime emulated.Element[emparams.Mod1e4096] `gnark:",public"`

	// PublicKeyN is the modulus N of the RSA public key.
	PublicKeyN emulated.Element[emparams.Mod1e4096] `gnark:",public"`

	// PublicKeyE is the public exponent E of the RSA public key (e.g., 65537).
	PublicKeyE frontend.Variable `gnark:",public"`

	// --- Private Inputs (Witness) ---

	// Signature is an array of frontend.Variable, where each Variable is a byte of the RSA signature.
	// The size must match the RSA key size in bytes (e.g., 256 for RSA-2048).
	Signature emulated.Element[emparams.Mod1e4096] // Assuming a 2048-bit RSA key (2048/8 = 256 bytes)
}

// Define the circuit logic using the gnark frontend API.
func (circuit *JWTRSACircuit) Define(api frontend.API) error {
	f, err := emulated.NewField[emparams.Mod1e4096](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	modulus := &circuit.PublicKeyN
	base := &circuit.Signature
	exp := f.NewElement(circuit.PublicKeyE)

	res := f.ModExp(base, exp, modulus)

	f.AssertIsEqual(&circuit.EmPrime, res)

	return nil
}
