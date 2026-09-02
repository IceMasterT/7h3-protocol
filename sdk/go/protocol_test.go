package protocol7h3

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Test 1: CanonicalizeEnvelope matches the conformance vector exactly.
func TestCanonicalizeEnvelopeConformanceVector(t *testing.T) {
	h := ProtocolHeader{
		Version:     "7h3/0.1",
		MessageID:   "vec-1",
		Nonce:       "nonce-vec-1",
		Sender:      "agent.alpha",
		Recipient:   "agent.beta",
		TimestampMs: 1712500000000,
		TTLMs:       60000,
	}
	b := ProtocolBody{
		Intent:        "TASK",
		Content:       "route:alpha->beta",
		Capability:    "task.plan",
		CorrelationID: "corr-1",
	}

	expected := `{"body":{"capability":"task.plan","content":"route:alpha->beta","correlationId":"corr-1","intent":"TASK"},"header":{"messageId":"vec-1","nonce":"nonce-vec-1","recipient":"agent.beta","sender":"agent.alpha","timestampMs":1712500000000,"ttlMs":60000,"version":"7h3/0.1"}}`
	got := CanonicalizeEnvelope(h, b)

	if got != expected {
		t.Errorf("canonical mismatch:\ngot:  %s\nwant: %s", got, expected)
	}
}

// Test 2: CanonicalizeEnvelope with no optional fields.
func TestCanonicalizeEnvelopeNoOptionals(t *testing.T) {
	h := ProtocolHeader{
		Version:     "7h3/0.1",
		MessageID:   "msg-1",
		Nonce:       "nonce-1",
		Sender:      "agent.a",
		TimestampMs: 1000000,
		TTLMs:       30000,
	}
	b := ProtocolBody{
		Intent:  "PING",
		Content: "hello",
	}

	got := CanonicalizeEnvelope(h, b)

	// Must not contain recipient, capability, correlationId keys
	if strings.Contains(got, "recipient") {
		t.Errorf("canonical should not contain 'recipient' when empty: %s", got)
	}
	if strings.Contains(got, "capability") {
		t.Errorf("canonical should not contain 'capability' when empty: %s", got)
	}
	if strings.Contains(got, "correlationId") {
		t.Errorf("canonical should not contain 'correlationId' when empty: %s", got)
	}

	// Verify it's valid JSON
	var v interface{}
	if err := json.Unmarshal([]byte(got), &v); err != nil {
		t.Errorf("canonical is not valid JSON: %v\n%s", err, got)
	}
}

// Test 3: GenerateKeypair returns non-empty strings.
func TestGenerateKeypair(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair error: %v", err)
	}
	if pub == "" {
		t.Error("public key is empty")
	}
	if priv == "" {
		t.Error("private key is empty")
	}
}

// Test 4: SignEnvelopeEd25519 + VerifyEnvelopeEd25519 round trip.
func TestSignVerifyEd25519RoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	env := CreateEnvelope("agent.a", "agent.b", 60000, ProtocolBody{
		Intent:  "TASK",
		Content: "hello",
	})

	signed, err := SignEnvelopeEd25519(env, priv)
	if err != nil {
		t.Fatalf("SignEnvelopeEd25519: %v", err)
	}

	ok, err := VerifyEnvelopeEd25519(signed, pub)
	if err != nil {
		t.Fatalf("VerifyEnvelopeEd25519: %v", err)
	}
	if !ok {
		t.Error("expected verification to succeed")
	}
}

// Test 5: VerifyEnvelopeEd25519 tampered envelope returns false.
func TestVerifyEd25519Tampered(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	env := CreateEnvelope("agent.a", "agent.b", 60000, ProtocolBody{
		Intent:  "TASK",
		Content: "hello",
	})

	signed, err := SignEnvelopeEd25519(env, priv)
	if err != nil {
		t.Fatalf("SignEnvelopeEd25519: %v", err)
	}

	// Tamper with the body content
	signed.Body.Content = "tampered"

	ok, err := VerifyEnvelopeEd25519(signed, pub)
	if err != nil {
		t.Fatalf("VerifyEnvelopeEd25519: %v", err)
	}
	if ok {
		t.Error("expected verification to fail for tampered envelope")
	}
}

// Test 6: SignEnvelopeHmac + VerifyEnvelopeHmac round trip.
func TestSignVerifyHmacRoundTrip(t *testing.T) {
	secret := "super-secret-key"
	env := CreateEnvelope("agent.a", "agent.b", 60000, ProtocolBody{
		Intent:  "PING",
		Content: "ping",
	})

	signed, err := SignEnvelopeHmac(env, secret, "key-1")
	if err != nil {
		t.Fatalf("SignEnvelopeHmac: %v", err)
	}

	ok, err := VerifyEnvelopeHmac(signed, secret)
	if err != nil {
		t.Fatalf("VerifyEnvelopeHmac: %v", err)
	}
	if !ok {
		t.Error("expected HMAC verification to succeed")
	}
}

// Test 7: ValidateEnvelope expired returns error diagnostic.
func TestValidateEnvelopeExpired(t *testing.T) {
	env := ProtocolEnvelope{
		Header: ProtocolHeader{
			Version:     WireVersion,
			MessageID:   "msg-old",
			Nonce:       "nonce-old",
			Sender:      "agent.a",
			TimestampMs: time.Now().UnixMilli() - 120000, // 2 minutes ago
			TTLMs:       60000,                           // 1 minute TTL → expired
		},
		Body: ProtocolBody{
			Intent:  "PING",
			Content: "old",
		},
	}

	diags := ValidateEnvelope(env)
	found := false
	for _, d := range diags {
		if d.Message == "Message TTL expired" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'Message TTL expired' diagnostic, got: %+v", diags)
	}
}

// Test 7b: ValidateEnvelope rejects ttlMs above the 24h ceiling.
func TestValidateEnvelopeTTLCeiling(t *testing.T) {
	env := ProtocolEnvelope{
		Header: ProtocolHeader{
			Version:     WireVersion,
			MessageID:   "msg-huge-ttl",
			Nonce:       "nonce-huge-ttl",
			Sender:      "agent.a",
			TimestampMs: time.Now().UnixMilli(),
			TTLMs:       MaxTTLMs + 1,
		},
		Body: ProtocolBody{
			Intent:  "PING",
			Content: "long-lived",
		},
	}

	diags := ValidateEnvelope(env)
	found := false
	for _, d := range diags {
		if strings.Contains(d.Message, "exceeds maximum") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ttlMs ceiling diagnostic, got: %+v", diags)
	}

	// Exactly at the ceiling stays valid
	env.Header.TTLMs = MaxTTLMs
	for _, d := range ValidateEnvelope(env) {
		if d.Level == "error" {
			t.Errorf("ttlMs == MaxTTLMs should not error, got: %+v", d)
		}
	}
}

// Test 8: HTTP: VerifyHTTPEnvelope valid signed request.
func TestHTTPVerifyValidSignedRequest(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	env := CreateEnvelope("agent.a", "agent.b", 60000, ProtocolBody{
		Intent:  "TASK",
		Content: "do something",
	})

	signed, err := SignEnvelopeEd25519(env, priv)
	if err != nil {
		t.Fatalf("SignEnvelopeEd25519: %v", err)
	}

	b, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	req.Header.Set(HTTPEnvelopeHeader, string(b))

	registry := &StaticKeyRegistry{Keys: map[string]string{"agent.a": pub}}
	result := VerifyHTTPEnvelope(req, registry)

	if !result.OK {
		t.Errorf("expected OK=true, got reason=%s detail=%s", result.Reason, result.Detail)
	}
}

// Test 9: HTTP: VerifyHTTPEnvelope missing header returns ReasonMissingHeader.
func TestHTTPVerifyMissingHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	registry := &StaticKeyRegistry{Keys: map[string]string{}}
	result := VerifyHTTPEnvelope(req, registry)

	if result.OK {
		t.Error("expected OK=false")
	}
	if result.Reason != ReasonMissingHeader {
		t.Errorf("expected reason=%s got=%s", ReasonMissingHeader, result.Reason)
	}
}

// Test 10: Webhook: SignWebhook + VerifyWebhook round trip.
func TestWebhookSignVerifyRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	body := `{"event":"order.created","id":"ord-1"}`
	sig, tsMs, err := SignWebhook(body, priv)
	if err != nil {
		t.Fatalf("SignWebhook: %v", err)
	}

	ok, err := VerifyWebhook(body, sig, tsMs, pub)
	if err != nil {
		t.Fatalf("VerifyWebhook: %v", err)
	}
	if !ok {
		t.Error("expected webhook verification to succeed")
	}
}

// signWithTimestamp is a test helper that signs a webhook payload with a specific timestamp.
func signWithTimestamp(body, privKeyBase64Url string, tsMs int64) (string, error) {
	privDER, err := decodeBase64Url(privKeyBase64Url)
	if err != nil {
		return "", fmt.Errorf("decode: %w", err)
	}
	privKeyIface, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return "", fmt.Errorf("parse: %w", err)
	}
	edPriv, ok := privKeyIface.(ed25519.PrivateKey)
	if !ok {
		return "", fmt.Errorf("not ed25519")
	}
	payload := webhookPayload(tsMs, body)
	sigBytes := ed25519.Sign(edPriv, []byte(payload))
	return encodeBase64Url(sigBytes), nil
}

// Test 11: Webhook: expired timestamp returns false.
func TestWebhookExpiredTimestamp(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	body := `{"event":"test"}`

	// Create a signature with a timestamp 10 minutes in the past
	oldTs := time.Now().UnixMilli() - 600000
	sig, err := signWithTimestamp(body, priv, oldTs)
	if err != nil {
		t.Fatalf("signWithTimestamp: %v", err)
	}
	tsStr := strconv.FormatInt(oldTs, 10)

	ok, err := VerifyWebhook(body, sig, tsStr, pub, WebhookDefaultTTLMs)
	if err != nil {
		t.Fatalf("VerifyWebhook: %v", err)
	}
	if ok {
		t.Error("expected expired webhook to return false")
	}
}

// Test 12: Webhook: tampered body returns false.
func TestWebhookTamperedBody(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	body := `{"event":"order.created"}`
	sig, tsMs, err := SignWebhook(body, priv)
	if err != nil {
		t.Fatalf("SignWebhook: %v", err)
	}

	// Tamper with body
	tamperedBody := `{"event":"order.deleted"}`
	ok, err := VerifyWebhook(tamperedBody, sig, tsMs, pub)
	if err != nil {
		t.Fatalf("VerifyWebhook: %v", err)
	}
	if ok {
		t.Error("expected tampered webhook body to return false")
	}
}

// TestValidateEnvelopeClockSkew mirrors the TypeScript, Python and Rust SDKs:
// MaxTTLMs bounds nothing unless a post-dated timestamp is also rejected.
func TestValidateEnvelopeClockSkew(t *testing.T) {
	env := ProtocolEnvelope{
		Header: ProtocolHeader{
			Version: WireVersion, MessageID: "msg-1", Sender: "a@b.test",
			Nonce: "abc123", TTLMs: 60_000,
			TimestampMs: time.Now().UnixMilli() + 31_536_000_000,
		},
		Body: ProtocolBody{Intent: "TASK", Content: "x"},
	}
	found := false
	for _, d := range ValidateEnvelope(env) {
		if d.Level == "error" && strings.Contains(d.Message, "in the future") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a future-timestamp error for a post-dated envelope")
	}

	env.Header.TimestampMs = time.Now().UnixMilli() + MaxClockSkewMs - 5_000
	for _, d := range ValidateEnvelope(env) {
		if d.Level == "error" {
			t.Fatalf("timestamp within skew should not error, got %q", d.Message)
		}
	}
}
