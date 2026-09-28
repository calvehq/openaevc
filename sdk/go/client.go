package openaevc

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// ProtocolError is a structured OpenAEVC error (spec/errors.md).
type ProtocolError struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Retryable bool           `json:"retryable"`
	Detail    map[string]any `json:"-"`
}

func (e *ProtocolError) Error() string { return e.Code + ": " + e.Message }

// Session carries the identity and signing key for requests.
type Session struct {
	Key       *SigningKey
	Principal string
	Namespace string
	ActAs     string
}

// Envelope builds and signs a canonical request envelope for body.
func (s Session) Envelope(body map[string]any) (map[string]any, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	env := map[string]any{
		"protocol_version": ProtocolVersion,
		"request_id":       NewID("req"),
		"caller":           s.Principal,
		"nonce":            B64.EncodeToString(nonce),
		"issued_at":        time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z"),
	}
	if s.Namespace != "" {
		env["namespace"] = s.Namespace
	}
	if s.ActAs != "" {
		env["act_as"] = s.ActAs
	}
	b, err := ToModel(body)
	if err != nil {
		return nil, err
	}
	env["body"] = Prune(b)
	msg, err := Encode(env)
	if err != nil {
		return nil, err
	}
	env["signature"] = s.Key.Sign("request", msg)
	return env, nil
}

// Client talks to openaevcd. Endpoint is "host:port" or "unix:/path/to/socket".
type Client struct {
	Endpoint string
	Session  Session
	http     *http.Client
}

// NewClient creates a client.
func NewClient(endpoint string, session Session) *Client {
	tr := &http.Transport{}
	if strings.HasPrefix(endpoint, "unix:") {
		path := strings.TrimPrefix(endpoint, "unix:")
		tr.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", path)
		}
	}
	return &Client{Endpoint: endpoint, Session: session, http: &http.Client{Transport: tr}}
}

// WithSession returns a client for another session on the same endpoint.
func (c *Client) WithSession(s Session) *Client {
	return &Client{Endpoint: c.Endpoint, Session: s, http: c.http}
}

func (c *Client) url(path string) string {
	if strings.HasPrefix(c.Endpoint, "unix:") {
		return "http://localhost" + path
	}
	return "http://" + c.Endpoint + path
}

func transportErr(err error) error {
	return &ProtocolError{Code: "INTERNAL", Message: "transport: " + err.Error(), Retryable: true}
}

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, transportErr(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, transportErr(err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		pe := &ProtocolError{}
		if json.Unmarshal(body, pe) != nil || pe.Code == "" {
			pe = &ProtocolError{Code: "INTERNAL", Message: fmt.Sprintf("HTTP %d", resp.StatusCode)}
		}
		_ = json.Unmarshal(body, &pe.Detail)
		return nil, pe
	}
	return body, nil
}

func (c *Client) post(path string, body map[string]any) (map[string]any, error) {
	env, err := c.Session.Envelope(body)
	if err != nil {
		return nil, err
	}
	raw, err := Encode(env)
	if err != nil {
		return nil, err
	}
	req, _ := http.NewRequest("POST", c.url(path), bytes.NewReader(raw))
	req.Header.Set("content-type", "application/cbor")
	req.Header.Set("accept", "application/json")
	out, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, transportErr(err)
	}
	return v, nil
}

// Info returns GET /v1/info.
func (c *Client) Info() (map[string]any, error) {
	req, _ := http.NewRequest("GET", c.url("/v1/info"), nil)
	out, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var v map[string]any
	return v, json.Unmarshal(out, &v)
}

// Negotiate verifies the daemon supports this SDK's protocol version.
func (c *Client) Negotiate() (string, error) {
	info, err := c.Info()
	if err != nil {
		return "", err
	}
	p, _ := info["protocol"].(map[string]any)
	lo, _ := p["min"].(string)
	hi, _ := p["max"].(string)
	if lo == "" || hi == "" {
		return "", &ProtocolError{Code: "INTERNAL", Message: "daemon info has no protocol range"}
	}
	if cmpVersion(ProtocolVersion, lo) < 0 || cmpVersion(ProtocolVersion, hi) > 0 {
		return "", &ProtocolError{Code: "PROTOCOL_VERSION_UNSUPPORTED", Message: "daemon does not support " + ProtocolVersion}
	}
	return ProtocolVersion, nil
}

func cmpVersion(a, b string) int {
	var x, y [3]int
	fmt.Sscanf(a, "%d.%d.%d", &x[0], &x[1], &x[2])
	fmt.Sscanf(b, "%d.%d.%d", &y[0], &y[1], &y[2])
	for i := range x {
		if x[i] != y[i] {
			return x[i] - y[i]
		}
	}
	return 0
}

// Command executes a signed command.
func (c *Client) Command(body map[string]any) (map[string]any, error) {
	return c.post("/v1/commands", body)
}

// Query executes a signed query.
func (c *Client) Query(body map[string]any) (any, error) {
	env, err := c.Session.Envelope(body)
	if err != nil {
		return nil, err
	}
	raw, _ := Encode(env)
	req, _ := http.NewRequest("POST", c.url("/v1/queries"), bytes.NewReader(raw))
	req.Header.Set("content-type", "application/cbor")
	out, err := c.do(req)
	if err != nil {
		return nil, err
	}
	var v any
	return v, json.Unmarshal(out, &v)
}

// GetObject fetches an object's canonical bytes and verifies the digest.
func (c *Client) GetObject(digest string) ([]byte, error) {
	env, err := c.Session.Envelope(map[string]any{"type": "GetObject", "digest": digest})
	if err != nil {
		return nil, err
	}
	hdr, _ := Encode(env)
	req, _ := http.NewRequest("GET", c.url("/v1/objects/"+digest), nil)
	req.Header.Set("openaevc-envelope", B64.EncodeToString(hdr))
	out, err := c.do(req)
	if err != nil {
		return nil, err
	}
	if Sha256(out) != digest {
		return nil, &ProtocolError{Code: "DIGEST_MISMATCH", Message: "object bytes do not match their digest"}
	}
	return out, nil
}

// Events streams journal events (SSE) to fn until fn returns false or the stream ends.
func (c *Client) Events(after int64, kinds []string, fn func(map[string]any) bool) error {
	ks := make([]any, len(kinds))
	for i, k := range kinds {
		ks[i] = k
	}
	env, err := c.Session.Envelope(map[string]any{"type": "ListEvents", "after": after, "kinds": ks})
	if err != nil {
		return err
	}
	hdr, _ := Encode(env)
	req, _ := http.NewRequest("GET", c.url("/v1/events"), nil)
	req.Header.Set("openaevc-envelope", B64.EncodeToString(hdr))
	resp, err := c.http.Do(req)
	if err != nil {
		return transportErr(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		pe := &ProtocolError{}
		b, _ := io.ReadAll(resp.Body)
		_ = json.Unmarshal(b, pe)
		return pe
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	kind, data := "", ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if data != "" {
				var ev map[string]any
				if err := json.Unmarshal([]byte(data), &ev); err != nil {
					return transportErr(err)
				}
				if kind == "error" {
					pe := &ProtocolError{}
					_ = json.Unmarshal([]byte(data), pe)
					return pe
				}
				if !fn(ev) {
					return nil
				}
			}
			kind, data = "", ""
		case strings.HasPrefix(line, "event:"):
			kind = strings.TrimSpace(line[6:])
		case strings.HasPrefix(line, "data:"):
			data += strings.TrimLeft(line[5:], " ")
		}
	}
	return sc.Err()
}

func result(r map[string]any) map[string]any {
	m, _ := r["result"].(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

// CreateNamespace (administrators only) returns the namespace and root principal IDs.
func (c *Client) CreateNamespace(roots []map[string]any) (string, []string, error) {
	rs := make([]any, len(roots))
	for i, r := range roots {
		rs[i] = r
	}
	r, err := c.Command(map[string]any{"type": "CreateNamespace", "root_principals": rs})
	if err != nil {
		return "", nil, err
	}
	var ids []string
	for _, x := range result(r)["ids"].([]any) {
		ids = append(ids, x.(string))
	}
	return result(r)["id"].(string), ids, nil
}

// Result returns a receipt's result field.
func Result(r map[string]any) map[string]any { return result(r) }
