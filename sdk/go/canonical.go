// Package openaevc is the Go client SDK for OpenAEVC (protocol 0.1.0).
package openaevc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxSafe is the largest integer magnitude permitted in canonical objects.
const MaxSafe = 1<<53 - 1

// ErrCanonical reports a value or encoding outside the canonical data model.
var ErrCanonical = errors.New("canonical encoding error")

func canonErr(msg string) error { return fmt.Errorf("%w: %s", ErrCanonical, msg) }

func head(out *bytes.Buffer, major byte, n uint64) {
	m := major << 5
	switch {
	case n < 24:
		out.WriteByte(m | byte(n))
	case n <= 0xff:
		out.Write([]byte{m | 24, byte(n)})
	case n <= 0xffff:
		out.Write([]byte{m | 25, byte(n >> 8), byte(n)})
	case n <= 0xffffffff:
		out.Write([]byte{m | 26, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	default:
		out.Write([]byte{m | 27, byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)})
	}
}

func encodeInt(out *bytes.Buffer, v int64) error {
	if v > MaxSafe || v < -MaxSafe {
		return canonErr("integer outside +/-(2^53-1)")
	}
	if v >= 0 {
		head(out, 0, uint64(v))
	} else {
		head(out, 1, uint64(-1-v))
	}
	return nil
}

func encodeInto(out *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		return canonErr("null is not permitted")
	case bool:
		if x {
			out.WriteByte(0xf5)
		} else {
			out.WriteByte(0xf4)
		}
	case int:
		return encodeInt(out, int64(x))
	case int64:
		return encodeInt(out, x)
	case uint64:
		if x > MaxSafe {
			return canonErr("integer outside +/-(2^53-1)")
		}
		head(out, 0, x)
	case json.Number:
		s := string(x)
		if strings.ContainsAny(s, ".eE") {
			return canonErr("floating-point values are not permitted")
		}
		i, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return canonErr("integer outside +/-(2^53-1)")
		}
		return encodeInt(out, i)
	case float64, float32:
		return canonErr("floating-point values are not permitted")
	case string:
		head(out, 3, uint64(len(x)))
		out.WriteString(x)
	case []any:
		head(out, 4, uint64(len(x)))
		for _, item := range x {
			if err := encodeInto(out, item); err != nil {
				return err
			}
		}
	case map[string]any:
		type entry struct {
			key []byte
			val any
		}
		entries := make([]entry, 0, len(x))
		for k, val := range x {
			var kb bytes.Buffer
			head(&kb, 3, uint64(len(k)))
			kb.WriteString(k)
			entries = append(entries, entry{kb.Bytes(), val})
		}
		sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].key, entries[j].key) < 0 })
		head(out, 5, uint64(len(entries)))
		for _, e := range entries {
			out.Write(e.key)
			if err := encodeInto(out, e.val); err != nil {
				return err
			}
		}
	default:
		return canonErr(fmt.Sprintf("unsupported type %T", v))
	}
	return nil
}

// Encode returns the deterministic CBOR encoding of a JSON-model value
// (map[string]any, []any, string, bool, json.Number or integers).
func Encode(v any) ([]byte, error) {
	var out bytes.Buffer
	if err := encodeInto(&out, v); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// ToModel converts any JSON-marshalable Go value into the JSON model (numbers as json.Number).
func ToModel(v any) (any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return ParseJSON(b)
}

// ParseJSON parses JSON preserving integer/float distinction.
func ParseJSON(b []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// Decode strictly decodes canonical CBOR into the JSON model (integers as int64).
func Decode(data []byte) (any, error) {
	d := decoder{buf: data}
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	if d.pos != len(data) {
		return nil, canonErr("trailing bytes")
	}
	return v, nil
}

type decoder struct {
	buf []byte
	pos int
}

func (d *decoder) take(n uint64) ([]byte, error) {
	if n > uint64(len(d.buf)-d.pos) {
		return nil, canonErr("truncated")
	}
	s := d.buf[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return s, nil
}

func (d *decoder) arg(info byte) (uint64, error) {
	var size int
	var min uint64
	switch {
	case info < 24:
		return uint64(info), nil
	case info == 24:
		size, min = 1, 24
	case info == 25:
		size, min = 2, 0x100
	case info == 26:
		size, min = 4, 0x10000
	case info == 27:
		size, min = 8, 0x100000000
	case info == 31:
		return 0, canonErr("indefinite lengths are not permitted")
	default:
		return 0, canonErr("unsupported item")
	}
	b, err := d.take(uint64(size))
	if err != nil {
		return 0, err
	}
	var n uint64
	for _, x := range b {
		n = n<<8 | uint64(x)
	}
	if n < min {
		return 0, canonErr("non-shortest encoding")
	}
	return n, nil
}

func (d *decoder) text(info byte) (string, error) {
	n, err := d.arg(info)
	if err != nil {
		return "", err
	}
	b, err := d.take(n)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(b) {
		return "", canonErr("invalid UTF-8")
	}
	return string(b), nil
}

func (d *decoder) value(depth int) (any, error) {
	if depth > 128 {
		return nil, canonErr("nesting too deep")
	}
	ib, err := d.take(1)
	if err != nil {
		return nil, err
	}
	major, info := ib[0]>>5, ib[0]&0x1f
	switch major {
	case 0:
		n, err := d.arg(info)
		if err != nil {
			return nil, err
		}
		if n > MaxSafe {
			return nil, canonErr("integer outside the canonical range")
		}
		return int64(n), nil
	case 1:
		n, err := d.arg(info)
		if err != nil {
			return nil, err
		}
		if n >= MaxSafe {
			return nil, canonErr("integer outside the canonical range")
		}
		return -1 - int64(n), nil
	case 3:
		return d.text(info)
	case 4:
		n, err := d.arg(info)
		if err != nil {
			return nil, err
		}
		if n > uint64(len(d.buf)-d.pos) {
			return nil, canonErr("truncated")
		}
		out := make([]any, 0, n)
		for i := uint64(0); i < n; i++ {
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		n, err := d.arg(info)
		if err != nil {
			return nil, err
		}
		if n > uint64(len(d.buf)-d.pos) {
			return nil, canonErr("truncated")
		}
		out := make(map[string]any, n)
		var prev []byte
		for i := uint64(0); i < n; i++ {
			start := d.pos
			kb, err := d.take(1)
			if err != nil {
				return nil, err
			}
			if kb[0]>>5 != 3 {
				return nil, canonErr("map keys must be text")
			}
			key, err := d.text(kb[0] & 0x1f)
			if err != nil {
				return nil, err
			}
			raw := d.buf[start:d.pos]
			if prev != nil && bytes.Compare(prev, raw) >= 0 {
				return nil, canonErr("map keys unsorted or duplicated")
			}
			prev = raw
			v, err := d.value(depth + 1)
			if err != nil {
				return nil, err
			}
			out[key] = v
		}
		return out, nil
	case 7:
		switch info {
		case 20:
			return false, nil
		case 21:
			return true, nil
		}
		return nil, canonErr("null, undefined and floats are not permitted")
	}
	if info == 31 {
		return nil, canonErr("indefinite lengths are not permitted")
	}
	return nil, canonErr("unsupported CBOR major type")
}

// Prune removes nil fields (absent values are omitted, never null).
func Prune(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range x {
			if val == nil {
				continue
			}
			out[k] = Prune(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = Prune(item)
		}
		return out
	}
	return v
}
