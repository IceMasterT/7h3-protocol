package protocol7h3

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func TestEncodeDecodeEnvelopeCBOR_RoundTrip(t *testing.T) {
	env := ProtocolEnvelope{
		Header: ProtocolHeader{
			Version:     WireVersion,
			MessageID:   "msg-1234567890-abc12345",
			TimestampMs: time.Now().UnixMilli(),
			TTLMs:       60000,
			Sender:      "agent:alice@example.com",
			Nonce:       "abcdefghij",
		},
		Body: ProtocolBody{
			Intent:  "TASK",
			Content: "Hello, agent!",
		},
	}

	encoded, err := EncodeEnvelopeCBOR(env)
	if err != nil {
		t.Fatalf("EncodeEnvelopeCBOR error: %v", err)
	}

	decoded, err := DecodeEnvelopeCBOR(encoded)
	if err != nil {
		t.Fatalf("DecodeEnvelopeCBOR error: %v", err)
	}

	if decoded.Header.Version != env.Header.Version {
		t.Errorf("version mismatch: got %q want %q", decoded.Header.Version, env.Header.Version)
	}
	if decoded.Header.MessageID != env.Header.MessageID {
		t.Errorf("messageId mismatch: got %q want %q", decoded.Header.MessageID, env.Header.MessageID)
	}
	if decoded.Header.TimestampMs != env.Header.TimestampMs {
		t.Errorf("timestampMs mismatch: got %d want %d", decoded.Header.TimestampMs, env.Header.TimestampMs)
	}
	if decoded.Header.TTLMs != env.Header.TTLMs {
		t.Errorf("ttlMs mismatch: got %d want %d", decoded.Header.TTLMs, env.Header.TTLMs)
	}
	if decoded.Header.Sender != env.Header.Sender {
		t.Errorf("sender mismatch: got %q want %q", decoded.Header.Sender, env.Header.Sender)
	}
	if decoded.Header.Nonce != env.Header.Nonce {
		t.Errorf("nonce mismatch: got %q want %q", decoded.Header.Nonce, env.Header.Nonce)
	}
	if decoded.Body.Intent != env.Body.Intent {
		t.Errorf("intent mismatch: got %q want %q", decoded.Body.Intent, env.Body.Intent)
	}
	if decoded.Body.Content != env.Body.Content {
		t.Errorf("content mismatch: got %q want %q", decoded.Body.Content, env.Body.Content)
	}
	if decoded.Signature != nil {
		t.Errorf("expected nil signature, got %+v", decoded.Signature)
	}
}

func TestEncodeDecodeEnvelopeCBOR_AllOptionalFields(t *testing.T) {
	env := ProtocolEnvelope{
		Header: ProtocolHeader{
			Version:     WireVersion,
			MessageID:   "msg-full",
			TimestampMs: 1700000000000,
			TTLMs:       30000,
			Sender:      "agent:alice",
			Recipient:   "agent:bob",
			Nonce:       "nonce-xyz",
		},
		Body: ProtocolBody{
			Intent:        "TASK",
			Content:       "do something",
			Capability:    "file.read",
			CorrelationID: "corr-abc",
		},
		Signature: &ProtocolSignature{
			Alg:   "HS256",
			KeyID: "my-key-id",
			Value: "base64urlencodedvalue",
		},
	}

	encoded, err := EncodeEnvelopeCBOR(env)
	if err != nil {
		t.Fatalf("EncodeEnvelopeCBOR error: %v", err)
	}

	decoded, err := DecodeEnvelopeCBOR(encoded)
	if err != nil {
		t.Fatalf("DecodeEnvelopeCBOR error: %v", err)
	}

	if decoded.Header.Recipient != env.Header.Recipient {
		t.Errorf("recipient: got %q want %q", decoded.Header.Recipient, env.Header.Recipient)
	}
	if decoded.Body.Capability != env.Body.Capability {
		t.Errorf("capability: got %q want %q", decoded.Body.Capability, env.Body.Capability)
	}
	if decoded.Body.CorrelationID != env.Body.CorrelationID {
		t.Errorf("correlationId: got %q want %q", decoded.Body.CorrelationID, env.Body.CorrelationID)
	}
	if decoded.Signature == nil {
		t.Fatal("expected signature, got nil")
	}
	if decoded.Signature.Alg != env.Signature.Alg {
		t.Errorf("sig.alg: got %q want %q", decoded.Signature.Alg, env.Signature.Alg)
	}
	if decoded.Signature.KeyID != env.Signature.KeyID {
		t.Errorf("sig.keyId: got %q want %q", decoded.Signature.KeyID, env.Signature.KeyID)
	}
	if decoded.Signature.Value != env.Signature.Value {
		t.Errorf("sig.value: got %q want %q", decoded.Signature.Value, env.Signature.Value)
	}
}

func TestEncodeDecodeEnvelopeCBOR_Deterministic(t *testing.T) {
	env := ProtocolEnvelope{
		Header: ProtocolHeader{
			Version:     WireVersion,
			MessageID:   "msg-det",
			TimestampMs: 1700000000000,
			TTLMs:       60000,
			Sender:      "agent:sender",
			Nonce:       "nonce-det",
		},
		Body: ProtocolBody{
			Intent:  "PING",
			Content: "ping",
		},
	}

	enc1, err := EncodeEnvelopeCBOR(env)
	if err != nil {
		t.Fatalf("first encode error: %v", err)
	}
	enc2, err := EncodeEnvelopeCBOR(env)
	if err != nil {
		t.Fatalf("second encode error: %v", err)
	}

	if !bytes.Equal(enc1, enc2) {
		t.Error("encoding same envelope twice gave different bytes (not deterministic)")
	}
}

func TestEncodeEnvelopeCBOR_SmallerThanJSON(t *testing.T) {
	env := ProtocolEnvelope{
		Header: ProtocolHeader{
			Version:     WireVersion,
			MessageID:   "msg-size-test-1234567890",
			TimestampMs: 1700000000000,
			TTLMs:       60000,
			Sender:      "agent:alice@example.com",
			Recipient:   "agent:bob@example.com",
			Nonce:       "nonce-abcdefgh",
		},
		Body: ProtocolBody{
			Intent:        "TASK",
			Content:       "Hello, this is a test message content",
			Capability:    "file.read",
			CorrelationID: "corr-xyz-1234",
		},
		Signature: &ProtocolSignature{
			Alg:   "HS256",
			KeyID: "my-key-id-v1",
			Value: "base64urlencodedvalueofthesignature",
		},
	}

	cborBytes, err := EncodeEnvelopeCBOR(env)
	if err != nil {
		t.Fatalf("EncodeEnvelopeCBOR error: %v", err)
	}
	jsonBytes, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("json.Marshal error: %v", err)
	}

	t.Logf("CBOR size: %d bytes, JSON size: %d bytes, ratio: %.2f",
		len(cborBytes), len(jsonBytes), float64(len(cborBytes))/float64(len(jsonBytes)))

	if len(cborBytes) >= len(jsonBytes) {
		t.Errorf("expected CBOR (%d bytes) to be smaller than JSON (%d bytes)", len(cborBytes), len(jsonBytes))
	}
}

func TestEncodeDecodeEnvelopeCBOR_OptionalFieldsAbsent(t *testing.T) {
	// Minimal envelope - no optional fields
	env := ProtocolEnvelope{
		Header: ProtocolHeader{
			Version:     WireVersion,
			MessageID:   "msg-min",
			TimestampMs: 1700000000000,
			TTLMs:       30000,
			Sender:      "agent:sender",
			Nonce:       "nonce123",
		},
		Body: ProtocolBody{
			Intent:  "PING",
			Content: "ping",
		},
	}

	encoded, err := EncodeEnvelopeCBOR(env)
	if err != nil {
		t.Fatalf("EncodeEnvelopeCBOR error: %v", err)
	}

	decoded, err := DecodeEnvelopeCBOR(encoded)
	if err != nil {
		t.Fatalf("DecodeEnvelopeCBOR error: %v", err)
	}

	if decoded.Header.Recipient != "" {
		t.Errorf("expected empty recipient, got %q", decoded.Header.Recipient)
	}
	if decoded.Body.Capability != "" {
		t.Errorf("expected empty capability, got %q", decoded.Body.Capability)
	}
	if decoded.Body.CorrelationID != "" {
		t.Errorf("expected empty correlationId, got %q", decoded.Body.CorrelationID)
	}
	if decoded.Signature != nil {
		t.Errorf("expected nil signature, got %+v", decoded.Signature)
	}
}
