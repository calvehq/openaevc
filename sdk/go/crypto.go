package openaevc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

// Sha256 returns the algorithm-tagged digest of data.
func Sha256(data []byte) string {
	s := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(s[:])
}

// DigestOf returns the digest of a value's canonical encoding.
func DigestOf(v any) (string, error) {
	b, err := Encode(v)
	if err != nil {
		return "", err
	}
	return Sha256(b), nil
}

// B64 is unpadded base64url.
var B64 = base64.RawURLEncoding

func domainMessage(domain string, msg []byte) []byte {
	return append([]byte("OPENAEVC/1 "+domain+"\n"), msg...)
}

// SigningKey is an in-memory Ed25519 key.
type SigningKey struct {
	priv ed25519.PrivateKey
	// PublicKey is the protocol text form `ed25519:<base64url>`.
	PublicKey string
}

// NewSigningKey creates a key from its 32-byte seed.
func NewSigningKey(seed []byte) (*SigningKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("Ed25519 seed must be 32 bytes")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &SigningKey{priv: priv, PublicKey: "ed25519:" + B64.EncodeToString(priv.Public().(ed25519.PublicKey))}, nil
}

// GenerateKey creates a random key.
func GenerateKey() (*SigningKey, error) {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	return NewSigningKey(seed)
}

// KeyFromHex parses a hex seed.
func KeyFromHex(h string) (*SigningKey, error) {
	b, err := hex.DecodeString(strings.TrimSpace(h))
	if err != nil {
		return nil, err
	}
	return NewSigningKey(b)
}

// Sign signs msg in the given domain (request, grant, object).
func (k *SigningKey) Sign(domain string, msg []byte) string {
	return B64.EncodeToString(ed25519.Sign(k.priv, domainMessage(domain, msg)))
}

// Verify checks a domain-separated signature.
func Verify(publicKey, domain string, msg []byte, signature string) bool {
	raw, err := B64.DecodeString(strings.TrimPrefix(publicKey, "ed25519:"))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return false
	}
	sig, err := B64.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(raw), domainMessage(domain, msg), sig)
}
