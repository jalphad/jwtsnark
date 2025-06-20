package main

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"jwtZkp/cmd/util"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	// You'll need a way to parse your PEM-encoded public key.
	// "crypto/x509"
	// "encoding/pem"
)

func main() {
	pk, cert, _, err := util.GenerateSelfSignedCertAndKey(2048)
	if err != nil {
		panic(err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub":  "foo",
		"user": "John Doe",
		"id":   "abc123",
		"iat":  fmt.Sprintf("%d", time.Now().Unix()),
	})

	signed, err := token.SignedString(pk)
	if err != nil {
		log.Fatalf("failed to sign token: %s", err.Error())
	}

	fmt.Println(signed)

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
	valid, err := util.VerifyRSASignaturePKCS1v15([]byte(message), parsed.Signature, pubKey.N, pubKey.E)
	if err != nil {
		log.Println("custom verify function failed")
	}
	fmt.Println("Token is valid: ", valid)

	// 3. Check if the token is valid and access claims
	if claims, ok := parsed.Claims.(jwt.MapClaims); ok && parsed.Valid {
		fmt.Println("Token is valid!")
		fmt.Printf("Subject: %v\n", claims["sub"])
		fmt.Printf("Name: %v\n", claims["user"])
		fmt.Printf("Id: %v\n", claims["id"])
		fmt.Printf("Issued At: %v\n", claims["iat"])
	} else {
		fmt.Println("Token is not valid.")
	}
}
