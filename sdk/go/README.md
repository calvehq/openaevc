# OpenAEVC Go SDK

`go get github.com/Shiva936/OpenAEVC/sdk/go` — standard library only (Go ≥ 1.22), protocol 0.1.0.

```go
key, _ := openaevc.KeyFromHex(seed)
c := openaevc.NewClient("127.0.0.1:7878", openaevc.Session{Key: key, Principal: pri, Namespace: ns})
if _, err := c.Negotiate(); err != nil { log.Fatal(err) }
r, err := c.Command(map[string]any{"type": "CreateChangePack", "spec": map[string]any{}})
```

Unix sockets: `openaevc.NewClient("unix:/var/lib/openaevc/openaevcd.sock", session)`.

`Encode`/`Decode` implement deterministic CBOR (JSON numbers must be decoded with
`UseNumber`, see `ParseJSON`). Tests: `go test ./...` (golden fixtures; `TestE2E` runs against a
daemon when `OPENAEVC_ENDPOINT` is set).
