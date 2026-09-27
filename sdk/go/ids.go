package openaevc

import (
	"crypto/rand"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz234567"

var idRE = regexp.MustCompile(`^([a-z]{2,3})_([a-z2-7]{26})$`)

func base32(b []byte) string {
	var sb strings.Builder
	acc, bits := uint32(0), 0
	for _, x := range b {
		acc = acc<<8 | uint32(x)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(alphabet[(acc>>bits)&31])
		}
		acc &= 1<<bits - 1
	}
	if bits > 0 {
		sb.WriteByte(alphabet[(acc<<(5-bits))&31])
	}
	return sb.String()
}

// NewID returns a fresh typed identifier `<prefix>_<base32(uuidv7)>`.
func NewID(prefix string) string {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	_, _ = rand.Read(b[6:])
	b[6] = 0x70 | b[6]&0x0f
	b[8] = 0x80 | b[8]&0x3f
	return prefix + "_" + base32(b[:])
}

// ParseID validates a typed identifier (case-insensitive) and returns its canonical form.
func ParseID(text string) (string, error) {
	low := strings.ToLower(text)
	m := idRE.FindStringSubmatch(low)
	if m == nil || !contains(IDPrefixes, m[1]) {
		return "", fmt.Errorf("invalid identifier %q", text)
	}
	var raw []byte
	acc, bits := uint32(0), 0
	for _, ch := range m[2] {
		acc = acc<<5 | uint32(strings.IndexRune(alphabet, ch))
		bits += 5
		if bits >= 8 {
			bits -= 8
			raw = append(raw, byte(acc>>bits))
		}
		acc &= 1<<bits - 1
	}
	if acc != 0 || raw[6]>>4 != 7 || raw[8]>>6 != 2 {
		return "", fmt.Errorf("invalid identifier %q", text)
	}
	return low, nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
