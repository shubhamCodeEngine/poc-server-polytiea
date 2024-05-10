package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"server/internal/challenge"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func (s *Server) RegisterRoutes() http.Handler {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowHeaders: []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, "X-Altcha-Spam-Filter"},
	}))
	e.GET("/get-challenge", s.GetChallengeHandler)
	e.POST("/verify-challenge", s.VerifyChallengeHandler)
	return e
}

func (s *Server) GetChallengeHandler(c echo.Context) error {

	hmacKey := os.Getenv("HMAC_KEY")
	hmacKeyAsBytes := []byte(hmacKey)
	ch, err := challenge.CreateChallenge(hmacKeyAsBytes)

	if err != nil {
		return c.JSON(500, map[string]string{"error": "Internal server error"})
	}

	response := map[string]string{
		"algorithm": "SHA-256",
		"challenge": ch.Challenge,
		"salt":      ch.Salt,
		"signature": ch.Signature,
	}
	fmt.Println(response)
	return c.JSON(200, response)
}

func (s *Server) VerifyChallengeHandler(c echo.Context) error {

	payload := c.FormValue("payload")
	fmt.Println(payload)

	decodedBytes, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return echo.NewHTTPError(400, "Invalid BASE64 encoding")
	}

	var data challenge.ChallengeVerifyPayload
	if err := json.Unmarshal(decodedBytes, &data); err != nil {
		return echo.NewHTTPError(400, "Invalid JSON data")
	}

	hmacKey := os.Getenv("HMAC_KEY")
	hmacKeyAsBytes := []byte(hmacKey)

	verified, err := challenge.VerifyChallenge(data, hmacKeyAsBytes)
	if err != nil {
		errString := fmt.Sprintf("Internal server error: %s", err)
		return c.JSON(500, map[string]string{"error": errString})
	}
	if !verified {
		return c.JSON(400, map[string]string{"error": "Invalid challenge"})
	}

	return c.JSON(200, map[string]bool{"verified": true})
}
