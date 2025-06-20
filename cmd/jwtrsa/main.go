package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	// "encoding/pem" // Uncomment if you use exportPrivateKeyAsPEM/exportPublicKeyAsPEM
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarklogger "github.com/consensys/gnark/logger"
)

// JWTRSACircuit defines the RSA signature verification circuit.
// It proves that a given signature is valid for a given message hash and public key,
// without revealing the signature itself.
type JWTRSACircuit struct {
	// --- Public Inputs ---

	// HashedMessage is the SHA256 hash of the (header_b64.payload_b64) string.
	// It's represented as an array of frontend.Variable, where each Variable is a byte of the hash.
	// For SHA256, this will be 32 bytes.
	HashedMessage [32]frontend.Variable `gnark:",public"`

	// PublicKeyN is the modulus N of the RSA public key.
	PublicKeyN frontend.Variable `gnark:",public"`

	// PublicKeyE is the public exponent E of the RSA public key (e.g., 65537).
	PublicKeyE frontend.Variable `gnark:",public"`

	// --- Private Inputs (Witness) ---

	// Signature is an array of frontend.Variable, where each Variable is a byte of the RSA signature.
	// The size must match the RSA key size in bytes (e.g., 256 for RSA-2048).
	Signature [256]frontend.Variable // Assuming a 2048-bit RSA key (2048/8 = 256 bytes)
}

// Define the circuit logic using the gnark frontend API.
func (circuit *JWTRSACircuit) Define(api frontend.API) error {
	// Prepare the public key structure for gnark's RSA library.
	publicKey := gnarkrsa.PublicKey{
		N: circuit.PublicKeyN,
		E: circuit.PublicKeyE, // E is typically small (e.g., 65537)
	}

	// Convert HashedMessage from [32]frontend.Variable to []frontend.Variable
	// as expected by the gnarkrsa.Verify function.
	hashedMessageSlice := make([]frontend.Variable, len(circuit.HashedMessage))
	hashedMessageSlice = circuit.HashedMessage[:]

	// Convert Signature from [256]frontend.Variable to []frontend.Variable.
	signatureSlice := make([]frontend.Variable, len(circuit.Signature))
	signatureSlice = circuit.Signature[:]

	// Perform RSA PKCS#1v1.5 signature verification.
	// The gnarkrsa.Verify function handles:
	// 1. Constructing the DigestInfo (ASN.1 structure containing hash algorithm ID and hash).
	// 2. EMSA-PKCS1-v1_5 padding.
	// 3. Modular exponentiation (signature^E mod N).
	// 4. Comparison with the padded hash.
	// We provide the raw SHA256 hash; the function uses crypto.SHA256 to know how to format DigestInfo.
	err := gnarkrsa.Verify(api, publicKey, signatureSlice, hashedMessageSlice, &gnarkrsa.Options{
		Hash: crypto.SHA256, // Specify the hash algorithm used outside the circuit.
		// RSASignatureScheme defaults to PKCS1v15 if not specified.
	})
	if err != nil {
		return fmt.Errorf("RSA verification failed within circuit: %w", err)
	}

	return nil
}

// --- Helper Functions ---

// generateSelfSignedCertAndKey creates a sample RSA private key and a self-signed X.509 certificate.
// In a real scenario, the JWT issuer generates these. The x5c field contains the certificate.
func generateSelfSignedCertAndKey(rsaBits int) (*rsa.PrivateKey, *x509.Certificate, []byte /*DER bytes*/, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, rsaBits)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "jwt-issuer.example.com",
			Organization: []string{"Example JWT Issuer"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365), // Valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, // Example usages
		BasicConstraintsValid: true,
		IsCA:                  false, // Not a CA certificate
	}

	// Create the certificate, signed by the private key itself (self-signed).
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
	// Configure gnark logger (optional, useful for debugging)
	gnarklogger.SetSeverity(gnarklogger.INFO) // Or ERROR for less verbosity

	// 1. Simulate JWT data and x5c certificate
	// For a real JWT, the 'signedData' is: base64urlEncode(header) + "." + base64urlEncode(payload)
	// Example header: {"alg":"RS256","typ":"JWT"} -> eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
	// Example payload: {"sub":"user123","name":"John Doe"} -> eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IkpvaG4gRG9lIn0
	// signedData := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IkpvaG4gRG9lIn0"
	// For this example, we'll use a simpler string.
	signedData := "This is the data that was signed in the JWT (header.payload)."
	fmt.Printf("📜 JWT Signed Data (simulated): \"%s\"\n", signedData)

	// RSA key size (must match circuit's Signature array size)
	rsaKeyBits := 2048
	expectedSignatureSize := rsaKeyBits / 8
	if expectedSignatureSize != len(JWTRSACircuit{}.Signature) {
		fmt.Printf("❌ Configuration Error: RSA key size (%d bits) implies signature size %d, but circuit expects %d.\n",
			rsaKeyBits, expectedSignatureSize, len(JWTRSACircuit{}.Signature))
		os.Exit(1)
	}

	// Generate a sample RSA private key and its corresponding X.509 certificate (DER encoded).
	// The prover would possess the private key. The certificate (or its public key) is public.
	fmt.Println("\n🔑 Generating RSA key pair and self-signed certificate for simulation...")
	jwtSignerPrivKey, _, certDERBytes, err := generateSelfSignedCertAndKey(rsaKeyBits)
	if err != nil {
		fmt.Printf("❌ Error generating sample key/cert: %v\n", err)
		os.Exit(1)
	}

	// The 'x5c' field in a JWT header (or JWKS) would contain this certificate, base64-encoded.
	x5cValue := base64.StdEncoding.EncodeToString(certDERBytes)
	fmt.Printf("📄 Simulated x5c certificate value (first 60 chars): %s...\n", x5cValue[:60])

	// 2. Parse the x5c certificate to extract the public key (N, E)
	// This is what a verifier (or our circuit setup) would do.
	fmt.Println("\n🔍 Parsing x5c certificate to extract public key...")
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
	rsaPublicKey, ok := parsedCert.PublicKey.(*rsa.PublicKey)
	if !ok {
		fmt.Println("❌ Certificate does not contain an RSA public key.")
		os.Exit(1)
	}
	publicKeyN := rsaPublicKey.N
	publicKeyE := big.NewInt(int64(rsaPublicKey.E)) // E is typically 65537

	fmt.Printf("    Modulus N (first 16 bytes): %x...\n", publicKeyN.Bytes()[:16])
	fmt.Printf("    Exponent E: %d\n", rsaPublicKey.E)

	// 3. Hash the signed data (using SHA-256, as in RS256)
	// This hash is a public input to our zk-SNARK circuit.
	fmt.Println("\n#️⃣ Hashing the JWT signed data (SHA-256)...")
	hashedData := sha256.Sum256([]byte(signedData))
	fmt.Printf("    Hash (hex): %x\n", hashedData)

	// 4. Create the RSA signature (Prover's action)
	// This signature is the private witness for the zk-SNARK.
	fmt.Println("\n✍️  Creating RSA signature (PKCS#1v1.5) with the private key...")
	signatureBytes, err := rsa.SignPKCS1v15(rand.Reader, jwtSignerPrivKey, crypto.SHA256, hashedData[:])
	if err != nil {
		fmt.Printf("❌ Error signing hash: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("    Signature (first 16 bytes): %x...\n", signatureBytes[:16])

	// Sanity check: Verify signature using standard crypto library (outside ZK)
	err = rsa.VerifyPKCS1v15(rsaPublicKey, crypto.SHA256, hashedData[:], signatureBytes)
	if err != nil {
		fmt.Printf("❌ Standard library RSA verification FAILED (sanity check): %v\n", err)
		os.Exit(1)
	}
	fmt.Println("    ✅ Standard library RSA verification successful (sanity check).")

	// 5. Prepare inputs for the gnark circuit
	var circuit JWTRSACircuit

	// Populate public inputs
	for i := 0; i < len(hashedData); i++ {
		circuit.HashedMessage[i] = hashedData[i]
	}
	circuit.PublicKeyN = publicKeyN
	circuit.PublicKeyE = publicKeyE

	// Populate private inputs (the signature)
	if len(signatureBytes) != len(circuit.Signature) {
		fmt.Printf("❌ Error: Generated signature length (%d) does not match circuit's expected length (%d).\n",
			len(signatureBytes), len(circuit.Signature))
		os.Exit(1)
	}
	for i := 0; i < len(signatureBytes); i++ {
		circuit.Signature[i] = signatureBytes[i]
	}

	// 6. Compile the circuit
	fmt.Println("\n⚙️ Compiling the gnark circuit...")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Printf("❌ Error compiling circuit: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("    ✅ Circuit compiled successfully. Number of constraints: %d\n", cs.GetNbConstraints())

	// 7. Perform Groth16 Setup (generate Proving Key and Verifying Key)
	// This is a one-time setup for a given circuit structure.
	fmt.Println("\n🛠️ Running Groth16 setup (generating PK and VK)...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		fmt.Printf("❌ Error in Groth16 setup: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("    ✅ Groth16 setup complete.")

	// 8. Create a witness
	// The witness includes all inputs: public (hash, N, E) and private (signature).
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

	// 9. Generate the Proof (Prover's task)
	// The prover uses the Proving Key (pk) and the full witness.
	fmt.Println("\n🛡️ Generating the Groth16 proof...")
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		fmt.Printf("❌ Error generating proof: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("    ✅ Proof generated successfully.")

	// 10. Verify the Proof (Verifier's task)
	// The verifier uses the Verifying Key (vk) and only the Public Witness.
	// The private signature is NOT exposed to the verifier.
	fmt.Println("\n🔍 Verifying the proof...")
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Printf("❌ Proof verification FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("    🎉 Proof verified successfully!")
	fmt.Println("\nThis demonstrates that you have a valid signature for the JWT payload and x5c-derived public key,")
	fmt.Println("proven without revealing the signature itself. ✨")
}
