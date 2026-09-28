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

// SigningDigest is SHA-256 of an object envelope's canonical encoding without `signatures`:
// object signatures cover its 32 raw bytes ("object" domain); references use DigestOf(envelope).
func SigningDigest(envelope map[string]any) (string, error) {
	unsigned := make(map[string]any, len(envelope))
	for k, v := range envelope {
		if k != "signatures" {
			unsigned[k] = v
		}
	}
	return DigestOf(unsigned)
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

// Verify checks a domain-separated signature strictly (AEVC-ID-0006): canonical unpadded
// base64url, no small-order or non-canonical key or R, and S < L.
func Verify(publicKey, domain string, msg []byte, signature string) bool {
	if !strings.HasPrefix(publicKey, "ed25519:") {
		return false
	}
	raw, ok := strictB64(strings.TrimPrefix(publicKey, "ed25519:"), ed25519.PublicKeySize)
	if !ok {
		return false
	}
	sig, ok := strictB64(signature, ed25519.SignatureSize)
	if !ok || weakPoint(raw) || weakPoint(sig[:32]) || !canonicalScalar(sig[32:]) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(raw), domainMessage(domain, msg), sig)
}

func strictB64(s string, n int) ([]byte, bool) {
	b, err := B64.Strict().DecodeString(s)
	if err != nil || len(b) != n || B64.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

// Encodings (sign bit cleared) of points of small order, canonical or not (as in libsodium).
var smallOrder = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
}

// weakPoint reports a small-order or non-canonical (y >= p) point encoding.
func weakPoint(enc []byte) bool {
	c := append([]byte(nil), enc...)
	c[31] &= 0x7f
	h := hex.EncodeToString(c)
	for _, s := range smallOrder {
		if h == s {
			return true
		}
	}
	// y >= p = 2^255 - 19: little-endian compare against edff..ff7f.
	p := []byte{0xed}
	for i := 0; i < 30; i++ {
		p = append(p, 0xff)
	}
	p = append(p, 0x7f)
	for i := 31; i >= 0; i-- {
		if c[i] != p[i] {
			return c[i] > p[i]
		}
	}
	return true
}

// canonicalScalar reports S < L (little-endian).
func canonicalScalar(s []byte) bool {
	l, _ := hex.DecodeString("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
	for i := 31; i >= 0; i-- {
		if s[i] != l[i] {
			return s[i] < l[i]
		}
	}
	return false
}
