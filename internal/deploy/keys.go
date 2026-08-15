package deploy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/ssh"
)

// genSSHKey makes an ed25519 pair: the private key in PEM (OpenSSH) and the authorized_keys line.
// The user never sees them: the public half goes to their server, the private one is encrypted and stored.
func genSSHKey() (privPEM, authLine string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return "", "", err
	}
	privPEM = string(pem.EncodeToMemory(block))

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	authLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	return privPEM, authLine, nil
}

// pubLineFromPriv rebuilds the authorized_keys line from the private PEM (to strip our key on purge).
func pubLineFromPriv(privPEM string) (string, error) {
	signer, err := ssh.ParsePrivateKey([]byte(privPEM))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), nil
}

// deriveKey builds a 32 byte encryption key from the JWT secret, so no separate env var is needed.
func deriveKey(secret string) []byte {
	h := sha256.Sum256([]byte("djaploy-ssh-key:" + secret))
	return h[:]
}

func encrypt(key []byte, plain string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.StdEncoding.EncodeToString(ct), nil
}

func decrypt(key []byte, enc string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
