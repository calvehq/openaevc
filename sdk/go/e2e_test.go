package openaevc

import (
	"encoding/json"
	"os"
	"testing"
)

// TestE2E is Scenario J for Go; it runs only when OPENAEVC_ENDPOINT is set by the
// interoperability harness.
func TestE2E(t *testing.T) {
	endpoint := os.Getenv("OPENAEVC_ENDPOINT")
	if endpoint == "" {
		t.Skip("OPENAEVC_ENDPOINT not set")
	}
	raw, err := os.ReadFile(os.Getenv("OPENAEVC_ADMIN_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	var admin struct{ ID, Seed string }
	if err := json.Unmarshal(raw, &admin); err != nil {
		t.Fatal(err)
	}
	akey, _ := KeyFromHex(admin.Seed)
	ac := NewClient(endpoint, Session{Key: akey, Principal: admin.ID})
	if _, err := ac.Negotiate(); err != nil {
		t.Fatal(err)
	}
	rootKey, _ := GenerateKey()
	ns, roots, err := ac.CreateNamespace([]map[string]any{{"kind": "KEY", "public_key": rootKey.PublicKey}})
	if err != nil {
		t.Fatal(err)
	}
	c := NewClient(endpoint, Session{Key: rootKey, Principal: roots[0], Namespace: ns})
	must := func(r map[string]any, err error) map[string]any {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return Result(r)
	}
	must(c.Command(map[string]any{"type": "RegisterExtension", "entrypoint": os.Getenv("OPENAEVC_KV_ENTRYPOINT"), "artifact_digest": os.Getenv("OPENAEVC_KV_DIGEST"), "approved_host_capabilities": []any{"resource.read"}}))
	must(c.Command(map[string]any{"type": "RegisterProvider", "provider": map[string]any{
		"id": "org.example.go-provider", "version": "1.0.0", "worker_kinds": []any{"org.example.worker"}, "harnesses": []any{"org.example.harness"},
		"cancellation": true, "resumable": false, "heartbeat": true, "principal": roots[0]}}))
	pack := must(c.Command(map[string]any{"type": "CreateChangePack", "spec": map[string]any{}}))["id"].(string)
	wu := must(c.Command(map[string]any{"type": "AddWorkUnit", "pack": pack, "expected_generation": 1, "kind": "org.example.task"}))["id"].(string)
	lease := must(c.Command(map[string]any{"type": "StartExecution", "request": map[string]any{
		"pack": pack, "expected_generation": 2, "work_unit": wu, "provider": "org.example.go-provider", "harness": "org.example.harness",
		"allowed_resources": []any{map[string]any{"kind": "kv.entry"}}, "allowed_effects": []any{"kv.set"}, "timeout_ms": 60000,
		"max_attempts": 1, "idempotency_key": "go-e2e"}}))["lease"].(map[string]any)
	must(c.Command(map[string]any{"type": "HeartbeatExecution", "execution": lease["execution"], "lease": lease["id"], "generation": lease["generation"]}))
	eff := must(c.Command(map[string]any{"type": "SubmitEffectProposal", "execution": lease["execution"], "lease": lease["id"], "effect": map[string]any{
		"kind": "kv.set", "target": map[string]any{"kind": "kv.entry", "locator": "lang", "extension": "org.openaevc.reference.kv"}, "payload": map[string]any{"value": "go"}}}))
	if eff["state"] != "APPLIED" {
		t.Fatalf("effect %v", eff)
	}
	must(c.Command(map[string]any{"type": "CompleteExecution", "execution": lease["execution"], "lease": lease["id"]}))
	candidate := must(c.Command(map[string]any{"type": "SealChangePack", "pack": pack, "expected_generation": 2}))["digest"].(string)
	if must(c.Command(map[string]any{"type": "RunVerification", "pack": pack, "generation": 2, "verifier": "kv.expect", "config": map[string]any{"key": "lang", "value": "go"}}))["state"] != "PASS" {
		t.Fatal("verification failed")
	}
	if must(c.Command(map[string]any{"type": "RefreshQualification", "pack": pack, "generation": 2}))["state"] != "QUALIFIED" {
		t.Fatal("not qualified")
	}
	promoted := must(c.Command(map[string]any{"type": "PromoteChangePack", "pack": pack, "generation": 2}))["digest"].(string)
	baseline := must(c.Command(map[string]any{"type": "CreateBaseline", "members": []any{promoted}}))["digest"].(string)
	v, err := c.Query(map[string]any{"type": "ValidateBaseline", "digest": baseline})
	if err != nil || v.(map[string]any)["valid"] != true {
		t.Fatalf("baseline invalid: %v %v", v, err)
	}
	if _, err := c.GetObject(candidate); err != nil {
		t.Fatal(err)
	}
	seen := false
	err = c.Events(0, []string{"changepack.promoted"}, func(e map[string]any) bool {
		seen = e["body"].(map[string]any)["pack"] == pack
		return false
	})
	if err != nil || !seen {
		t.Fatalf("promotion event not observed: %v", err)
	}
	t.Logf("go e2e ok %s", promoted)
}
