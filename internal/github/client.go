package github

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInstallationGone means GitHub answered 404 or 401: the app installation was deleted or
// revoked. The caller can drop the dead installation_id and treat the account as not connected.
var ErrInstallationGone = errors.New("github installation gone")

// httpClient has a hard timeout so a call to GitHub never hangs until nginx gives up with a 504.
var httpClient = &http.Client{Timeout: 12 * time.Second}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParseRSAPrivateKeyFromPEM(pem)
}

func appJWT(appID string, key *rsa.PrivateKey) (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    appID,
		IssuedAt:  jwt.NewNumericDate(now.Add(-30 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(9 * time.Minute)),
	}
	return jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
}

func InstallationToken(appID, keyPath string, installationID int64) (string, error) {
	key, err := loadPrivateKey(keyPath)
	if err != nil {
		return "", fmt.Errorf("load key: %w", err)
	}

	jwtStr, err := appJWT(appID, key)
	if err != nil {
		return "", fmt.Errorf("app jwt: %w", err)
	}

	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("create github request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+jwtStr)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "djaploy")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("github request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%w: github status %d: %s", ErrInstallationGone, resp.StatusCode, string(body))
	}
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("github status %d: %s", resp.StatusCode, string(body))
	}

	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode github token response: %w", err)
	}

	if out.Token == "" {
		return "", fmt.Errorf("github returned empty installation token")
	}

	return out.Token, nil
}
