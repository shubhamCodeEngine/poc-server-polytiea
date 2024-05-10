package challenge

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

func computeHmacSha256(data string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

type Challenge struct {
	Challenge string `json:"challenge"`
	Salt      string `json:"salt"`
	Signature string `json:"signature"`
}

func CreateChallenge(hmacKey []byte) (*Challenge, error) {
	saltBytes := make([]byte, 10) // adjust length as necessary
	if _, err := rand.Read(saltBytes); err != nil {
		return nil, err
	}
	salt := hex.EncodeToString(saltBytes)

	secretNumber, err := rand.Int(rand.Reader, big.NewInt(10000))
	if err != nil {
		return nil, err
	}

	hashInput := fmt.Sprintf("%s%d", salt, secretNumber)
	hasher := sha256.New()
	hasher.Write([]byte(hashInput))
	challenge := hex.EncodeToString(hasher.Sum(nil))

	signature := computeHmacSha256(challenge, hmacKey)

	return &Challenge{
		Challenge: challenge,
		Salt:      salt,
		Signature: signature,
	}, nil
}
