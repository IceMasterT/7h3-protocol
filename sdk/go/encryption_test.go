package protocol7h3_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	protocol7h3 "github.com/IceMasterT/7h3-protocol/sdk/go"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func makeEnvelopeGo(t *testing.T, body protocol7h3.ProtocolBody) protocol7h3.ProtocolEnvelope {
	t.Helper()
	nowMs := time.Now().UnixMilli()
	return protocol7h3.ProtocolEnvelope{
		Header: protocol7h3.ProtocolHeader{
			Version:     "7h3/0.1",
			MessageID:   "msg-go-test",
			TimestampMs: nowMs,
			TTLMs:       60_000,
			Sender:      "agent-alice",
			Recipient:   "agent-bob",
			Nonce:       "test-nonce-go",
		},
		Body: body,
	}
}

// ---------------------------------------------------------------------------
// Test 1: GenerateX25519KeyPair returns 32-byte base64url keys (~43 chars, no padding)
// ---------------------------------------------------------------------------

func TestGenerateX25519KeyPair(t *testing.T) {
	pub, priv, err := protocol7h3.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair error: %v", err)
	}

	// Should not contain base64 padding
	if strings.Contains(pub, "=") {
		t.Errorf("public key has padding: %s", pub)
	}
	if strings.Contains(priv, "=") {
		t.Errorf("private key has padding: %s", priv)
	}

	// Should be 43 chars (base64url of 32 bytes without padding)
	if len(pub) != 43 {
		t.Errorf("public key length = %d, want 43", len(pub))
	}
	if len(priv) != 43 {
		t.Errorf("private key length = %d, want 43", len(priv))
	}

	// Decoded must be exactly 32 bytes
	pubBytes, err := base64.RawURLEncoding.DecodeString(pub)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Errorf("public key decoded length = %d, want 32", len(pubBytes))
	}

	privBytes, err := base64.RawURLEncoding.DecodeString(priv)
	if err != nil {
		t.Fatalf("decode private key: %v", err)
	}
	if len(privBytes) != 32 {
		t.Errorf("private key decoded length = %d, want 32", len(privBytes))
	}
}

// ---------------------------------------------------------------------------
// Test 2: SealEnvelope + OpenEnvelope round-trip recovers original body exactly
// ---------------------------------------------------------------------------

func TestSealOpenEnvelopeRoundTrip(t *testing.T) {
	recipientPub, recipientPriv, err := protocol7h3.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	senderPub, senderPriv, err := protocol7h3.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	originalBody := protocol7h3.ProtocolBody{
		Intent:        "TASK",
		Content:       "Hello encrypted world!",
		Capability:    "some-cap",
		CorrelationID: "corr-123",
	}
	envelope := makeEnvelopeGo(t, originalBody)

	sealed, err := protocol7h3.SealEnvelope(envelope, recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}

	_, body, err := protocol7h3.OpenEnvelope(sealed, recipientPriv, senderPub)
	if err != nil {
		t.Fatalf("OpenEnvelope: %v", err)
	}

	if body.Intent != originalBody.Intent {
		t.Errorf("intent = %q, want %q", body.Intent, originalBody.Intent)
	}
	if body.Content != originalBody.Content {
		t.Errorf("content = %q, want %q", body.Content, originalBody.Content)
	}
	if body.Capability != originalBody.Capability {
		t.Errorf("capability = %q, want %q", body.Capability, originalBody.Capability)
	}
	if body.CorrelationID != originalBody.CorrelationID {
		t.Errorf("correlationId = %q, want %q", body.CorrelationID, originalBody.CorrelationID)
	}
}

// ---------------------------------------------------------------------------
// Test 3: OpenEnvelope fails with wrong recipient key
// ---------------------------------------------------------------------------

func TestOpenEnvelopeWrongRecipientKey(t *testing.T) {
	recipientPub, _, err := protocol7h3.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	_, wrongPriv, err := protocol7h3.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair wrong: %v", err)
	}
	senderPub, senderPriv, err := protocol7h3.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	envelope := makeEnvelopeGo(t, protocol7h3.ProtocolBody{Intent: "PING", Content: "secret"})
	sealed, err := protocol7h3.SealEnvelope(envelope, recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}

	// Wrong recipient private key — we need to test decryptBody path directly.
	// To bypass signature check (which uses senderPub correctly), we test OpenEnvelope
	// with wrong key but correct signature — the AEAD tag will fail.
	// However, OpenEnvelope verifies Ed25519 first using senderPub (which matches),
	// so signature passes, and then decryption fails with wrong key.
	_, _, err = protocol7h3.OpenEnvelope(sealed, wrongPriv, senderPub)
	if err == nil {
		t.Error("expected error with wrong recipient key, got nil")
	}
}

// ---------------------------------------------------------------------------
// Test 4: OpenEnvelope fails if envelope signature tampered
// ---------------------------------------------------------------------------

func TestOpenEnvelopeTamperedSignature(t *testing.T) {
	recipientPub, recipientPriv, err := protocol7h3.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	senderPub, senderPriv, err := protocol7h3.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	envelope := makeEnvelopeGo(t, protocol7h3.ProtocolBody{Intent: "PING", Content: "secret"})
	sealed, err := protocol7h3.SealEnvelope(envelope, recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}

	// Tamper with signature
	tamperedSig := *sealed.Signature
	tamperedSig.Value = strings.Repeat("A", 86)
	sealed.Signature = &tamperedSig

	_, _, err = protocol7h3.OpenEnvelope(sealed, recipientPriv, senderPub)
	if err == nil {
		t.Error("expected error with tampered signature, got nil")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("expected signature error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 5: OpenEnvelope fails if ciphertext tampered (AEAD auth tag fails)
// ---------------------------------------------------------------------------

func TestOpenEnvelopeTamperedCiphertext(t *testing.T) {
	recipientPub, recipientPriv, err := protocol7h3.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	senderPub, senderPriv, err := protocol7h3.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	envelope := makeEnvelopeGo(t, protocol7h3.ProtocolBody{Intent: "PING", Content: "secret"})
	sealed, err := protocol7h3.SealEnvelope(envelope, recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}

	// Decode the encrypted payload, flip a bit in ciphertext
	payloadJSON, err := base64.RawURLEncoding.DecodeString(sealed.Body.Content)
	if err != nil {
		t.Fatalf("decode content: %v", err)
	}
	var payload map[string]string
	if err = json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	ctBytes, err := base64.RawURLEncoding.DecodeString(payload["ciphertext"])
	if err != nil {
		t.Fatalf("decode ciphertext: %v", err)
	}
	ctBytes[0] ^= 0xFF
	payload["ciphertext"] = base64.RawURLEncoding.EncodeToString(ctBytes)

	tamperedPayloadJSON, _ := json.Marshal(payload)
	tamperedContent := base64.RawURLEncoding.EncodeToString(tamperedPayloadJSON)

	// We need to test decryptBody path, bypassing the signature check by calling
	// a sealed envelope that we signed correctly but with tampered content.
	// Since we can't re-sign (that would require a new seal), test via a helper approach:
	// Create a new sealed envelope with the tampered content re-signed.
	tamperedEnv := sealed
	tamperedEnv.Body.Content = tamperedContent
	// Re-sign it so sig check passes but AEAD fails
	reSealed, err := protocol7h3.SignEnvelopeEd25519(protocol7h3.ProtocolEnvelope{
		Header: tamperedEnv.Header,
		Body:   tamperedEnv.Body,
	}, senderPriv)
	if err != nil {
		t.Fatalf("re-sign tampered envelope: %v", err)
	}

	_, _, err = protocol7h3.OpenEnvelope(reSealed, recipientPriv, senderPub)
	if err == nil {
		t.Error("expected error with tampered ciphertext, got nil")
	}
}

// ---------------------------------------------------------------------------
// Test 6: Two SealEnvelope calls on same body produce different ciphertexts
// ---------------------------------------------------------------------------

func TestSealEnvelopeEphemeralRandomness(t *testing.T) {
	recipientPub, _, err := protocol7h3.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	_, senderPriv, err := protocol7h3.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	body := protocol7h3.ProtocolBody{Intent: "PING", Content: "same content"}
	envelope1 := makeEnvelopeGo(t, body)
	envelope2 := makeEnvelopeGo(t, body)

	sealed1, err := protocol7h3.SealEnvelope(envelope1, recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("SealEnvelope 1: %v", err)
	}
	sealed2, err := protocol7h3.SealEnvelope(envelope2, recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("SealEnvelope 2: %v", err)
	}

	if sealed1.Body.Content == sealed2.Body.Content {
		t.Error("two seal calls produced identical ciphertexts — ephemeral key randomness failure")
	}
}

// ---------------------------------------------------------------------------
// Test 7: Encrypted content is opaque (does not contain original body.content)
// ---------------------------------------------------------------------------

func TestEncryptedContentIsOpaque(t *testing.T) {
	recipientPub, _, err := protocol7h3.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	_, senderPriv, err := protocol7h3.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	originalContent := "super-secret-data-12345"
	envelope := makeEnvelopeGo(t, protocol7h3.ProtocolBody{Intent: "TASK", Content: originalContent})

	sealed, err := protocol7h3.SealEnvelope(envelope, recipientPub, senderPriv)
	if err != nil {
		t.Fatalf("SealEnvelope: %v", err)
	}

	// The raw encrypted content should not contain the original plaintext
	if strings.Contains(sealed.Body.Content, originalContent) {
		t.Error("encrypted content contains original plaintext (raw base64url)")
	}

	// Decoded JSON of encrypted payload should also not contain it
	payloadJSON, _ := base64.RawURLEncoding.DecodeString(sealed.Body.Content)
	if strings.Contains(string(payloadJSON), originalContent) {
		t.Error("encrypted payload JSON contains original plaintext")
	}
}
