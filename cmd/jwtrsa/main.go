package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/consensys/gnark/constraint"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	//groth16bls12381 "github.com/consensys/gnark/backend/groth16/bls12-381"
	cs2 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	gnarklogger "github.com/consensys/gnark/logger"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"jwtZkp/cmd/util"
)

func main() {
	// Configure gnark logger (optional, useful for debugging)
	logger := zerolog.Logger{}
	logger.Level(zerolog.InfoLevel)
	gnarklogger.Set(logger)

	privateKey, cert, _, err := util.GenerateSelfSignedCertAndKey(2048)
	if err != nil {
		panic(err)
	}

	timeNow := fmt.Sprintf("%d", time.Now().Unix())
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":  "foo",
		"user": "John Doe",
		"id":   "abc123",
		"iat":  timeNow,
	})

	signed, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("failed to sign token: %s", err.Error())
	}

	// 2. Parse and verify the JWT
	parsed, err := jwt.Parse(signed, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return cert.PublicKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			log.Println("Token has expired.")
		} else if errors.Is(err, jwt.ErrTokenNotValidYet) {
			log.Println("Token not yet valid.")
		} else if errors.Is(err, jwt.ErrTokenSignatureInvalid) {
			log.Println("Token signature is invalid.")
		} else {
			log.Fatalf("Error parsing token: %v", err)
		}
		return
	}

	message, _ := token.SigningString()
	pubKey := cert.PublicKey.(*rsa.PublicKey)
	publicKeyN := pubKey.N
	publicKeyE := pubKey.E

	// Step 1: Hash the message using SHA-256
	hasher := sha256.New()
	hasher.Write([]byte(message)) // This Write never returns an error
	hashedMessage := hasher.Sum(nil)

	// Step 2: Encode the hash with its ASN.1 DER prefix to create the DigestInfo
	// T = ASN.1_DER_Prefix || Hashed_Message
	digestInfo := append(util.Sha256ASNDERPrefix, hashedMessage...)

	// Step 3: Construct the expected EMSA-PKCS1-v1_5 encoded message
	// EM = 0x00 || 0x01 || PS || 0x00 || T
	// k is the length of the modulus in bytes
	k := publicKeyN.BitLen() / 8

	// The length of T (DigestInfo)
	lenT := len(digestInfo)

	// Check if k is large enough for EM: 0x00 || 0x01 || PS (min 8 bytes) || 0x00 || T
	// This means k must be at least len(T) + 3 (for 00,01,00) + 8 (min PS length) = len(T) + 11
	if k < lenT+11 {
		logger.Fatal().Msgf("key modulus bit length %d is too short for message and padding (need at least %d bytes, got %d)", publicKeyN.BitLen(), lenT+11, k)
	}

	// PS is a string of (k - len(T) - 3) bytes, all 0xFF.
	psLen := k - lenT - 3
	// psLen must be at least 8 bytes according to PKCS#1 v1.5 spec.
	// This was implicitly checked by `k < lenT + 11` if lenT + 11 is the minimum k size.

	// Construct EM = 0x00 || 0x01 || PS || 0x00 || T
	expectedEM := make([]byte, k)
	expectedEM[0] = 0x00
	expectedEM[1] = 0x01 // Block type 01 for signature
	for i := 0; i < psLen; i++ {
		expectedEM[2+i] = 0xff // Padding string
	}
	expectedEM[2+psLen] = 0x00 // Separator
	copy(expectedEM[2+psLen+1:], digestInfo)
	emPrime := new(big.Int).SetBytes(expectedEM)

	// 5. Prepare inputs for the gnark circuit
	var circuit JWTRSACircuit

	// Populate public inputs
	circuit.EmPrime = emulated.ValueOf[emparams.Mod1e4096](emPrime)
	circuit.PublicKeyN = emulated.ValueOf[emparams.Mod1e4096](publicKeyN)
	circuit.PublicKeyE = emulated.ValueOf[emparams.Mod1e4096](publicKeyE)

	// Populate private inputs (the signature)
	circuit.Signature = emulated.ValueOf[emparams.Mod1e4096](new(big.Int).SetBytes(parsed.Signature))

	var cs constraint.ConstraintSystem
	var rsaCircuitPath = "./rsaCircuit"
	if _, err = os.Stat(rsaCircuitPath); errors.Is(err, os.ErrNotExist) {
		// 6. Compile the circuit
		fmt.Println("\n⚙️ Compiling the gnark circuit...")
		cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			fmt.Printf("❌ Error compiling circuit: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("    ✅ Circuit compiled successfully. Number of constraints: %d\n", cs.GetNbConstraints())
		f, err := os.Create(rsaCircuitPath)
		if err != nil {
			fmt.Printf("❌ Error creating provingKey file: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("\n⚙️ Writing the gnark circuit to disk...")
		buf := bytes.NewBuffer([]byte{})
		_, err = cs.WriteTo(buf)
		if err != nil {
			fmt.Printf("❌ Error writing circuit to buffer: %v\n", err)
			os.Exit(1)
		}
		_, err = f.Write(buf.Bytes())
		if err != nil {
			fmt.Printf("❌ Error writing buffer to %s: %v\n", rsaCircuitPath, err)
			os.Exit(1)
		}
	} else {
		fmt.Println("\n⚙️ Reading the gnark circuit from disk...")
		csBytes, err := os.ReadFile(rsaCircuitPath)
		if err != nil {
			fmt.Printf("❌ Error reading ./provingKey: %v\n", err)
			os.Exit(1)
		}
		rdr := bytes.NewReader(csBytes)
		cs = &cs2.R1CS{}
		_, err = cs.ReadFrom(rdr)
		if err != nil {
			fmt.Printf("❌ Error reading proving key from bytes: %v\n", err)
			os.Exit(1)
		}
	}

	var pk groth16.ProvingKey
	var vk groth16.VerifyingKey
	if _, err = os.Stat("./provingKey"); errors.Is(err, os.ErrNotExist) {
		// 7. Perform Groth16 Setup (generate Proving Key and Verifying Key)
		// This is a one-time setup for a given circuit structure.
		fmt.Println("\n🛠️ Running Groth16 setup (generating PK and VK)...")
		pk, vk, err = groth16.Setup(cs)
		if err != nil {
			fmt.Printf("❌ Error in Groth16 setup: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("    ✅ Groth16 setup complete.")
		f, err := os.Create("./provingKey")
		if err != nil {
			fmt.Printf("❌ Error creating provingKey file: %v\n", err)
			os.Exit(1)
		}
		buf := bytes.NewBuffer([]byte{})
		_, err = pk.WriteTo(buf)
		if err != nil {
			fmt.Printf("❌ Error writing proving key to buffer: %v\n", err)
			os.Exit(1)
		}
		_, err = f.Write(buf.Bytes())
		if err != nil {
			fmt.Printf("❌ Error writing buffer to ./provingKey: %v\n", err)
			os.Exit(1)
		}

		f, err = os.Create("./verifyingKey")
		if err != nil {
			fmt.Printf("❌ Error creating verifyingKey file: %v\n", err)
			os.Exit(1)
		}
		buf = bytes.NewBuffer([]byte{})
		_, err = vk.WriteTo(buf)
		if err != nil {
			fmt.Printf("❌ Error writing verification key to buffer: %v\n", err)
			os.Exit(1)
		}
		_, err = f.Write(buf.Bytes())
		if err != nil {
			fmt.Printf("❌ Error writing buffer to ./verifyingKey: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("\n🛠️ Reading Groth16 PK and VK from disk...")
		pkBytes, err := os.ReadFile("./provingKey")
		if err != nil {
			fmt.Printf("❌ Error reading ./provingKey: %v\n", err)
			os.Exit(1)
		}
		pk = &groth16bn254.ProvingKey{}
		_, err = pk.ReadFrom(bytes.NewReader(pkBytes))
		if err != nil {
			fmt.Printf("❌ Error reading proving key from bytes: %v\n", err)
			os.Exit(1)
		}

		vkBytes, err := os.ReadFile("./verifyingKey")
		if err != nil {
			fmt.Printf("❌ Error reading ./verifyingKey: %v\n", err)
			os.Exit(1)
		}
		vk = &groth16bn254.VerifyingKey{}
		_, err = vk.ReadFrom(bytes.NewReader(vkBytes))
		if err != nil {
			fmt.Printf("❌ Error reading veryfying key from bytes: %v\n", err)
			os.Exit(1)
		}
	}

	start := time.Now()
	// 8. Create a witness
	// The witness includes all inputs: public (hash, N, E) and private (signature).
	fmt.Println("\n📦 Creating witness for the prover...")
	witness, err := frontend.NewWitness(&circuit, ecc.BN254.ScalarField())
	if err != nil {
		fmt.Printf("❌ Error creating witness: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Creating the witness took: " + time.Since(start).String())
	fmt.Println("    ✅ Witness created.")

	// 9. Generate the Proof (Prover's task)
	// The prover uses the Proving Key (pk) and the full witness.
	fmt.Println("\n🛡️ Generating the Groth16 proof...")
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		fmt.Printf("❌ Error generating proof: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Proof generation took: " + time.Since(start).String())
	fmt.Println("    ✅ Proof generated successfully.")
	buf := bytes.NewBuffer([]byte{})
	_, err = proof.WriteTo(buf)
	if err != nil {
		fmt.Printf("❌ Error writing verification key to buffer: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("\n The proof: " + base64.StdEncoding.EncodeToString(buf.Bytes()))

	fmt.Println("\n📦 Creating public witness for the verifier...")
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Printf("❌ Error creating public witness: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("    ✅ Public witness created.")

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
