package openaevc

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func load(t *testing.T, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fixtures", name))
	if err != nil {
		t.Fatal(err)
	}
	v, err := ParseJSON(b)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}

func unhex(t *testing.T, s any) []byte {
	b, err := hex.DecodeString(s.(string))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// normalize converts json.Number to int64 for comparison with decoded values.
func normalize(v any) any {
	b, _ := Encode(v)
	d, _ := Decode(b)
	return d
}

func TestCanonicalValues(t *testing.T) {
	f := load(t, "canonical/values.json")
	for _, c := range f["valid"].([]any) {
		c := c.(map[string]any)
		b, err := Encode(c["json"])
		if err != nil {
			t.Fatalf("%v: %v", c["name"], err)
		}
		if hex.EncodeToString(b) != c["cbor_hex"] || Sha256(b) != c["digest"] {
			t.Errorf("%v: bytes or digest differ", c["name"])
		}
		d, err := Decode(b)
		if err != nil || !reflect.DeepEqual(d, normalize(c["json"])) {
			t.Errorf("%v: decode mismatch %v", c["name"], err)
		}
	}
	for _, c := range f["invalid_cbor"].([]any) {
		c := c.(map[string]any)
		if _, err := Decode(unhex(t, c["cbor_hex"])); err == nil {
			t.Errorf("%v accepted", c["name"])
		}
	}
	for _, c := range f["invalid_json"].([]any) {
		c := c.(map[string]any)
		if _, err := Encode(c["json"]); err == nil {
			t.Errorf("%v accepted", c["name"])
		}
	}
}

func TestObjects(t *testing.T) {
	for _, c := range load(t, "canonical/objects.json")["valid"].([]any) {
		c := c.(map[string]any)
		b := unhex(t, c["cbor_hex"])
		if Sha256(b) != c["digest"] {
			t.Errorf("%v: digest", c["name"])
		}
		re, err := Encode(c["json"])
		if err != nil || hex.EncodeToString(re) != c["cbor_hex"] {
			t.Errorf("%v: re-encode %v", c["name"], err)
		}
		if want, ok := c["signing_digest"]; ok {
			// Object digest covers the signatures; each signature covers the signing digest.
			unsigned := map[string]any{}
			for k, v := range c["json"].(map[string]any) {
				if k != "signatures" {
					unsigned[k] = v
				}
			}
			sd, _ := Encode(unsigned)
			if Sha256(sd) != want {
				t.Errorf("%v: signing digest", c["name"])
			}
			if got, err := SigningDigest(c["json"].(map[string]any)); err != nil || got != want {
				t.Errorf("%v: SigningDigest %v %v", c["name"], got, err)
			}
			sum := sha256.Sum256(sd)
			for _, s := range c["json"].(map[string]any)["signatures"].([]any) {
				s := s.(map[string]any)
				if !Verify(s["public_key"].(string), "object", sum[:], s["signature"].(string)) {
					t.Errorf("%v: object signature", c["name"])
				}
			}
		}
	}
}

func TestSignatures(t *testing.T) {
	for _, c := range load(t, "canonical/signatures.json")["cases"].([]any) {
		c := c.(map[string]any)
		k, err := NewSigningKey(unhex(t, c["seed_hex"]))
		if err != nil {
			t.Fatal(err)
		}
		if k.PublicKey != c["public_key"] {
			t.Errorf("public key mismatch")
		}
		msg, _ := Encode(c["unsigned"])
		domain := c["domain"].(string)
		if domain == "object" {
			sum := sha256.Sum256(msg)
			msg = sum[:]
		}
		if hex.EncodeToString(msg) != c["message_hex"] {
			t.Errorf("message mismatch")
		}
		if k.Sign(domain, msg) != c["signature"] || !Verify(k.PublicKey, domain, msg, c["signature"].(string)) {
			t.Errorf("signature mismatch for %v", c["name"])
		}
		other := "object"
		if domain == "object" {
			other = "request"
		}
		if Verify(k.PublicKey, other, msg, c["signature"].(string)) {
			t.Errorf("cross-domain signature verified")
		}
	}
}

func TestInvalidSignatures(t *testing.T) {
	for _, c := range load(t, "canonical/signatures.json")["invalid"].([]any) {
		c := c.(map[string]any)
		msg := unhex(t, c["message_hex"])
		if Verify(c["public_key"].(string), c["domain"].(string), msg, c["signature"].(string)) {
			t.Errorf("%v verified", c["name"])
		}
	}
}

func TestIdentifiers(t *testing.T) {
	f := load(t, "canonical/identifiers.json")
	for _, s := range f["valid"].([]any) {
		s := s.(string)
		if strings.Contains(s, "_") && !strings.HasPrefix(s, "sha256") {
			if got, err := ParseID(s); err != nil || got != strings.ToLower(s) {
				t.Errorf("%s: %v", s, err)
			}
		}
	}
	for _, s := range f["invalid"].([]any) {
		s := s.(string)
		if strings.Contains(s, "_") && !strings.HasPrefix(s, "sha256") {
			if _, err := ParseID(s); err == nil {
				t.Errorf("%s accepted", s)
			}
		}
	}
	id := NewID("cpk")
	if _, err := ParseID(id); err != nil {
		t.Error(err)
	}
}
