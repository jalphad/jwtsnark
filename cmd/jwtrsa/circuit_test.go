package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"jwtZkp/cmd/util"
	"log"
	"math/big"
	"testing"
	"time"
)

func TestJWTRSACircuit_Define_ValidTokenSucceeds(t *testing.T) {
	pk, cert, _, err := util.GenerateSelfSignedCertAndKey(2048)
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

	signed, err := token.SignedString(pk)
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
		t.Fatalf("key modulus bit length %d is too short for message and padding (need at least %d bytes, got %d)", publicKeyN.BitLen(), lenT+11, k)
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

	circuit := &JWTRSACircuit{}
	assignment := &JWTRSACircuit{
		EmPrime:    emulated.ValueOf[emparams.Mod1e4096](emPrime),
		PublicKeyN: emulated.ValueOf[emparams.Mod1e4096](publicKeyN),
		PublicKeyE: publicKeyE,
		Signature:  emulated.ValueOf[emparams.Mod1e4096](new(big.Int).SetBytes(parsed.Signature)),
	}
	err = test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(t, err)
}

func TestJWTRSACircuit_Define_InValidTokenFails(t *testing.T) {
	pk, cert, _, err := util.GenerateSelfSignedCertAndKey(2048)
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
	alteredToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":  "foo",
		"user": "John Doe",
		"id":   "abc124", // <-- id changed
		"iat":  timeNow,
	})

	signed, err := token.SignedString(pk)
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

	// We're using the alteredToken as the message for verification
	message, _ := alteredToken.SigningString()
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
		t.Fatalf("key modulus bit length %d is too short for message and padding (need at least %d bytes, got %d)", publicKeyN.BitLen(), lenT+11, k)
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

	circuit := &JWTRSACircuit{}
	assignment := &JWTRSACircuit{
		EmPrime:    emulated.ValueOf[emparams.Mod1e4096](emPrime),
		PublicKeyN: emulated.ValueOf[emparams.Mod1e4096](publicKeyN),
		PublicKeyE: publicKeyE,
		Signature:  emulated.ValueOf[emparams.Mod1e4096](new(big.Int).SetBytes(parsed.Signature)),
	}
	err = test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.Error(t, err)
}

func TestJWTRSACircuitDummy_Define(t *testing.T) {
	emPrime := big.NewInt(2554)
	publicKeyN := big.NewInt(2693)
	publicKeyE := 10
	sig := []byte{0x01, 0x00}

	circuit := &JWTRSACircuit{}
	assignment := &JWTRSACircuit{
		EmPrime:    emulated.ValueOf[emparams.Mod1e4096](emPrime),
		PublicKeyN: emulated.ValueOf[emparams.Mod1e4096](publicKeyN),
		PublicKeyE: publicKeyE,
		Signature:  emulated.ValueOf[emparams.Mod1e4096](new(big.Int).SetBytes(sig)),
	}
	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(t, err)
}

func TestReference(t *testing.T) {
	publicKeyN := big.NewInt(2693)
	publicKeyE := 10
	sig := []byte{0x01, 0x00}
	s := new(big.Int).SetBytes(sig)

	fmt.Println("signature: ", s.String())

	// Step 5: Perform the RSA public key operation (the "decryption" or "verification" step)
	// m' = s^E mod N
	// This should recover the EMSA-PKCS1-v1_5 encoded message (EM) if the signature is valid.
	mPrime := new(big.Int)
	eBig := big.NewInt(int64(publicKeyE))
	mPrime.Exp(s, eBig, publicKeyN)

	tmpM := 256
	mul := 256
	for i := 1; i < publicKeyE; i++ {
		tmpM = tmpM * mul
		fmt.Println("tmpM: ", tmpM)
		tmpM = tmpM % 2693
		fmt.Println("tmpM mod 2693: ", tmpM)
	}

	fmt.Println("tmpM final: ", tmpM)
	fmt.Println("mPrime equals: ", mPrime.String())
}
