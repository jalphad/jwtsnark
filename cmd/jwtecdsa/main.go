package main

import (
	"crypto/ecdsa"
	"crypto/elliptic" // For P-256 curve
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/rs/zerolog"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarklogger "github.com/consensys/gnark/logger"
	// gnark's emulated arithmetic and ECDSA gadgets
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	gnarkecdsa "github.com/consensys/gnark/std/signature/ecdsa"
)

// JWTECDSACircuit defines the ECDSA signature verification circuit.
type JWTECDSACircuit struct {
	// --- Public Inputs ---

	// HashedMessage is the SHA256 hash of the (header_b64.payload_b64) string.
	// Represented as 32 bytes.
	HashedMessage []frontend.Variable `gnark:",public"`

	// PublicKeyX is the X-coordinate of the ECDSA public key.
	PublicKeyX frontend.Variable `gnark:",public"`
	// PublicKeyY is the Y-coordinate of the ECDSA public key.
	PublicKeyY frontend.Variable `gnark:",public"`

	// --- Private Inputs (Witness) ---

	// SignatureR is the R component of the ECDSA signature.
	SignatureR frontend.Variable
	// SignatureS is the S component of the ECDSA signature.
	SignatureS frontend.Variable
}

// Define the circuit logic using the gnark frontend API.
func (circuit *JWTECDSACircuit) Define(api frontend.API) error {
	// Get P256 (secp256k1) curve parameters for emulated arithmetic.
	// These parameters are known to gnark.
	curveParams := sw_emulated.GetCurveParams[emulated.Secp256k1Fp]()

	// Create an emulated P256 curve instance within the circuit.
	// The curve operates over secp256k1.BaseField (for coordinates) and secp256k1.ScalarField (for R, S).
	//eCurve, err := sw_emulated.New[emulated.Secp256k1Fp, emulated.Secp256k1Fr](api, curveParams)
	//if err != nil {
	//	return fmt.Errorf("failed to create emulated P256 curve: %w", err)
	//}

	baseField, err := emulated.NewField[emulated.Secp256k1Fp](api)
	if err != nil {
		return fmt.Errorf("failed to create base field for P256 curve: %w", err)
	}
	scalarField, err := emulated.NewField[emulated.Secp256k1Fr](api)
	if err != nil {
		return fmt.Errorf("failed to create scalar field for P256 curve: %w", err)
	}

	// Prepare the public key for gnark's ecdsa.Verify gadget.
	// PublicKeyX and PublicKeyY are converted to emulated elements on the curve's base field.
	pubKey := gnarkecdsa.PublicKey[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{
		X: *baseField.NewElement(circuit.PublicKeyX),
		Y: *baseField.NewElement(circuit.PublicKeyY),
	}

	// Prepare the signature for gnark's ecdsa.Verify gadget.
	// SignatureR and SignatureS are converted to emulated elements on the curve's scalar field.
	sig := gnarkecdsa.Signature[emulated.Secp256k1Fr]{ // Note: R and S are on the ScalarField
		R: *scalarField.NewElement(circuit.SignatureR),
		S: *scalarField.NewElement(circuit.SignatureS),
	}

	msg := emulated.ValueOf[emulated.Secp256k1Fr](circuit.HashedMessage)

	// Perform ECDSA signature verification.
	// gnarkecdsa.Verify handles the complex elliptic curve math.
	// It expects the raw hash bytes; it will internally convert this to an integer
	// and truncate/process as per FIPS 186-5 for the curve order.
	pubKey.Verify(api, curveParams, &msg, &sig)

	return nil
}

// --- Helper Functions ---

// generateSelfSignedCertAndKeyECDSA creates a sample ECDSA (P-256) private key and a self-signed X.509 certificate.
func generateSelfSignedCertAndKeyECDSA() (*ecdsa.PrivateKey, *x509.Certificate, []byte /*DER bytes*/, error) {
	// Generate an ECDSA private key using the P-256 curve.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate ECDSA private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(2), // Changed serial number for uniqueness
		Subject: pkix.Name{
			CommonName:   "jwt-issuer-ecdsa.example.com",
			Organization: []string{"Example ECDSA JWT Issuer"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365),
		KeyUsage:              x509.KeyUsageDigitalSignature, // ECDSA is primarily for signing
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse created certificate: %w", err)
	}

	return privKey, cert, derBytes, nil
}

// --- Main Program ---

func main() {
	logger := gnarklogger.Logger()
	logger.Level(zerolog.InfoLevel)

	signedData := "This is the ECDSA-signed data for the JWT (header.payload)."
	fmt.Printf("📜 JWT Signed Data (simulated): \"%s\"\n", signedData)

	fmt.Println("\n🔑 Generating ECDSA (P-256) key pair and self-signed certificate for simulation...")
	jwtSignerPrivKey, _, certDERBytes, err := generateSelfSignedCertAndKeyECDSA()
	if err != nil {
		fmt.Printf("❌ Error generating sample ECDSA key/cert: %v\n", err)
		os.Exit(1)
	}

	x5cValue := base64.StdEncoding.EncodeToString(certDERBytes)
	fmt.Printf("📄 Simulated x5c certificate value (first 60 chars): %s...\n", x5cValue[:60])

	fmt.Println("\n🔍 Parsing x5c certificate to extract ECDSA public key...")
	decodedCertBytes, err := base64.StdEncoding.DecodeString(x5cValue)
	if err != nil {
		fmt.Printf("❌ Error base64-decoding x5c string: %v\n", err)
		os.Exit(1)
	}
	parsedCert, err := x509.ParseCertificate(decodedCertBytes)
	if err != nil {
		fmt.Printf("❌ Error parsing DER certificate from x5c: %v\n", err)
		os.Exit(1)
	}
	ecdsaPublicKey, ok := parsedCert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Println("❌ Certificate does not contain an ECDSA public key.")
		os.Exit(1)
	}
	publicKeyX := ecdsaPublicKey.X
	publicKeyY := ecdsaPublicKey.Y

	fmt.Printf("    Public Key X: %x\n", publicKeyX.Bytes())
	fmt.Printf("    Public Key Y: %x\n", publicKeyY.Bytes())

	fmt.Println("\n#️⃣ Hashing the JWT signed data (SHA-256)...")
	hashedData := sha256.Sum256([]byte(signedData))
	fmt.Printf("    Hash (hex): %x\n", hashedData)

	fmt.Println("\n✍️  Creating ECDSA signature with the private key...")
	// ecdsa.Sign returns R and S as *big.Int, which is what we need for the circuit witness.
	sigR, sigS, err := ecdsa.Sign(rand.Reader, jwtSignerPrivKey, hashedData[:])
	if err != nil {
		fmt.Printf("❌ Error signing hash with ECDSA: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("    Signature R: %x\n", sigR.Bytes())
	fmt.Printf("    Signature S: %x\n", sigS.Bytes())

	// Sanity check: Verify signature using standard crypto library
	if !ecdsa.Verify(ecdsaPublicKey, hashedData[:], sigR, sigS) {
		fmt.Println("❌ Standard library ECDSA verification FAILED (sanity check).")
		os.Exit(1)
	}
	fmt.Println("    ✅ Standard library ECDSA verification successful (sanity check).")

	// 5. Prepare inputs for the gnark circuit
	var circuit JWTECDSACircuit
	for _, el := range hashedData {
		circuit.HashedMessage = append(circuit.HashedMessage, el)
	}
	circuit.PublicKeyX = publicKeyX
	circuit.PublicKeyY = publicKeyY
	circuit.SignatureR = sigR
	circuit.SignatureS = sigS

	fmt.Println("\n⚙️ Compiling the gnark circuit for ECDSA...")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("❌ Error compiling ECDSA circuit: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("    ✅ ECDSA Circuit compiled successfully. Number of constraints: %d\n", cs.GetNbConstraints())

	fmt.Println("\n🛠️ Running Groth16 setup (generating PK and VK)...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		fmt.Printf("❌ Error in Groth16 setup: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("    ✅ Groth16 setup complete.")

	fmt.Println("\n📦 Creating witness for the prover...")
	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("❌ Error creating witness: %v\n", err)
		os.Exit(1)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Printf("❌ Error creating public witness: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("    ✅ Witness created.")

	fmt.Println("\n🛡️ Generating the Groth16 proof for ECDSA...")
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		fmt.Printf("❌ Error generating proof: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("    ✅ Proof generated successfully.")

	fmt.Println("\n🔍 Verifying the proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("❌ Proof verification FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("    🎉 Proof verified successfully for ECDSA signature!")
	fmt.Println("\nThis demonstrates proving possession of a valid ECDSA signature for the JWT payload")
	fmt.Println("and x5c-derived public key, without revealing the R and S values of the signature itself. ✨")
}
