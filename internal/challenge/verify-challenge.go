package challenge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

func sha2Hex(input string) string {
	hasher := sha256.New()
	hasher.Write([]byte(input))
	return hex.EncodeToString(hasher.Sum(nil))
}

func validateSignature(challenge, signature string, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(challenge))
	expectedMac := hex.EncodeToString(mac.Sum(nil))
	return signature == expectedMac
}

type ChallengeVerifyPayload struct {
	Algorithm string `json:"algorithm"`
	Challenge string `json:"challenge"`
	Number    int    `json:"number"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

func VerifyChallenge(data ChallengeVerifyPayload, hmacKey []byte) (bool, error) {
	if data.Algorithm != "SHA-256" {
		return false, fmt.Errorf("invalid algorithm")
	}

	expectedChallenge := sha2Hex(fmt.Sprintf("%s%d", data.Salt, data.Number))
	if data.Challenge != expectedChallenge {
		return false, fmt.Errorf("invalid challenge")
	}

	if !validateSignature(data.Challenge, data.Signature, hmacKey) {
		return false, fmt.Errorf("invalid signature")
	}

	return true, nil
}
