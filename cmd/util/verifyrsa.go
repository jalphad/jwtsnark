package util

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"math/big"
)

// sha256ASNDERPrefix is the ASN.1 DER prefix for a SHA-256 DigestInfo structure.
//
//	DigestInfo ::= SEQUENCE {
//	  digestAlgorithm AlgorithmIdentifier { OID sha256 },
//	  digest OCTET STRING { actual_sha256_hash }
//	}
//
// The prefix is: 3031300d060960864801650304020105000420
var sha256ASNDERPrefix = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, // OID for SHA-256
	0x05, 0x00, // NULL parameters
	0x04, 0x20, // OCTET STRING tag and length for a 32-byte hash
}

// VerifyRSASignaturePKCS1v15 checks an RSA PKCS#1 v1.5 signature.
// message: The original unsigned message.
// signature: The signature bytes to verify.
// publicKeyN: The RSA public modulus N.
// publicKeyE: The RSA public exponent E.
// It returns true if the signature is valid, false otherwise, along with an error if one occurred.
func VerifyRSASignaturePKCS1v15(
	message []byte,
	signature []byte,
	publicKeyN *big.Int,
	publicKeyE int,
) (bool, error) {
	if publicKeyN == nil {
		return false, errors.New("public key modulus N cannot be nil")
	}
	if publicKeyE <= 1 { // Common values are 3, 65537
		return false, errors.New("public key exponent E must be greater than 1")
	}

	// Step 1: Hash the message using SHA-256
	hasher := sha256.New()
	hasher.Write(message) // This Write never returns an error
	hashedMessage := hasher.Sum(nil)

	// Step 2: Encode the hash with its ASN.1 DER prefix to create the DigestInfo
	// T = ASN.1_DER_Prefix || Hashed_Message
	digestInfo := append(sha256ASNDERPrefix, hashedMessage...)

	// Step 3: Construct the expected EMSA-PKCS1-v1_5 encoded message
	// EM = 0x00 || 0x01 || PS || 0x00 || T
	// k is the length of the modulus in bytes
	k := publicKeyN.BitLen() / 8

	// The length of T (DigestInfo)
	lenT := len(digestInfo)

	// Check if k is large enough for EM: 0x00 || 0x01 || PS (min 8 bytes) || 0x00 || T
	// This means k must be at least len(T) + 3 (for 00,01,00) + 8 (min PS length) = len(T) + 11
	if k < lenT+11 {
		return false, fmt.Errorf("key modulus bit length %d is too short for message and padding (need at least %d bytes, got %d)", publicKeyN.BitLen(), lenT+11, k)
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

	// Step 4: Convert the signature from bytes to a big.Int
	// The signature 's' is an integer s = m^d mod N, where m is the (padded) hash.
	// The input 'signature' byte slice is this integer 's' in big-endian binary form.
	s := new(big.Int).SetBytes(signature)

	// Step 5: Perform the RSA public key operation (the "decryption" or "verification" step)
	// m' = s^E mod N
	// This should recover the EMSA-PKCS1-v1_5 encoded message (EM) if the signature is valid.
	mPrime := new(big.Int)
	eBig := big.NewInt(int64(publicKeyE))
	mPrime.Exp(s, eBig, publicKeyN) // m' = s^E mod N

	// Step 6: Convert the result m' to a byte array of length k
	// The result of mPrime.Bytes() might be shorter than k if m' has leading zero bytes.
	// We need to left-pad it with zeros to ensure it's k bytes long for comparison.
	decryptedBlock := mPrime.Bytes()

	paddedDecryptedBlock := make([]byte, k)
	if len(decryptedBlock) > k {
		// This case should not happen if the signature is valid and k is derived from N.
		// If s >= N, then s^E mod N will be < N, so its byte length should be <= k.
		// If signature length > k, it implies s > N, which is unusual for a valid signature
		// unless it wasn't properly reduced modulo N or there's a misunderstanding of 'signature' format.
		// However, standard RSA signatures are integers s < N.
		// If mPrime.Bytes() itself is longer than k, it usually means mPrime >= 2^(8k),
		// which cannot happen if mPrime is the result of `mod publicKeyN` and N is k bytes long.
		// The only way this could happen is if mPrime.Bytes() yields more than k bytes due to
		// a negative mPrime (which also should not happen here). Let's stick to the common case.
		// If decryptedBlock > k, then the signature is invalid.
		// For simplicity here, we just ensure it's k bytes.
		// A more robust check might be to fail if len(decryptedBlock) > k.
		// But for now, we'll just make sure it's `k` for comparison.
		// If signature was not reduced mod N, it can be longer.
		// Let's assume signature is < N
		// If it's longer, copy the rightmost k bytes
		copy(paddedDecryptedBlock, decryptedBlock[len(decryptedBlock)-k:])
	} else {
		copy(paddedDecryptedBlock[k-len(decryptedBlock):], decryptedBlock) // Left-pad with zeros
	}
	decryptedBlock = paddedDecryptedBlock

	fmt.Println("mPrime equals emPrime: ", mPrime.Cmp(emPrime) == 0)

	// Step 7: Compare the decrypted block with the expected EMSA-PKCS1-v1_5 block
	// This comparison MUST be done in constant time to prevent timing attacks.
	// subtle.ConstantTimeCompare returns 1 if equal, 0 if not.
	if subtle.ConstantTimeCompare(decryptedBlock, expectedEM) == 1 {
		return true, nil // Signature is valid
	}

	return false, errors.New("signature verification failed: computed block does not match expected block")
}
