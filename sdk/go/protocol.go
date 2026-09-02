// Package protocol7h3 implements the 7h3 agent messaging protocol.
// Canonical form is byte-identical to the TypeScript reference implementation.
package protocol7h3

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// WireVersion is the protocol version string.
const WireVersion = "7h3/0.1"

// MaxTTLMs is the ceiling on ttlMs — a huge TTL keeps an envelope replayable
// (and its nonce pinned in every replay store) far beyond any legitimate
// messaging window.
const MaxTTLMs int64 = 86_400_000 // 24 hours

// MaxClockSkewMs is how far into the future a timestamp may sit before it is
// rejected. Without this ceiling MaxTTLMs bounds nothing: a sender can post-date
// TimestampMs by a year and still pass a 24h TTLMs, keeping the envelope valid —
// and replayable — long after any replay store has forgotten its nonce.
const MaxClockSkewMs int64 = 30_000

// ProtocolHeader contains routing and metadata for a message.
type ProtocolHeader struct {
	Version     string `json:"version"`
	MessageID   string `json:"messageId"`
	TimestampMs int64  `json:"timestampMs"`
	TTLMs       int64  `json:"ttlMs"`
	Sender      string `json:"sender"`
	Recipient   string `json:"recipient,omitempty"`
	Nonce       string `json:"nonce"`
}

// ProtocolBody contains the payload of a message.
type ProtocolBody struct {
	Intent        string `json:"intent"`
	Content       string `json:"content"`
	Capability    string `json:"capability,omitempty"`
	CorrelationID string `json:"correlationId,omitempty"`
}

// ProtocolSignature holds the signature over the canonical envelope.
type ProtocolSignature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"keyId"`
	Value string `json:"value"`
}

// ProtocolEnvelope is the top-level wire message.
type ProtocolEnvelope struct {
	Header    ProtocolHeader     `json:"header"`
	Body      ProtocolBody       `json:"body"`
	Signature *ProtocolSignature `json:"signature,omitempty"`
}

// Diagnostic reports a validation issue.
type Diagnostic struct {
	Level   string `json:"level"`
	Message string `json:"message"`
}

// encodeBase64Url encodes bytes as base64url without padding.
func encodeBase64Url(b []byte) string {
	s := base64.URLEncoding.EncodeToString(b)
	return strings.TrimRight(s, "=")
}

// decodeBase64Url decodes base64url, handling missing padding.
func decodeBase64Url(s string) ([]byte, error) {
	// Re-add padding
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// jsonStr JSON-encodes a string value (returns with surrounding quotes).
// Uses a non-HTML-escaping encoder to match TypeScript's JSON.stringify behavior
// (e.g. ">" stays as ">" rather than being escaped to ">").
func jsonStr(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	// Encode appends a newline; trim it
	return strings.TrimSuffix(buf.String(), "\n")
}

// generateNonce returns 16 random bytes as base64url.
func generateNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("protocol7h3: generateNonce: %v", err))
	}
	return encodeBase64Url(b)
}

// CanonicalizeEnvelope produces the canonical JSON string used for signing.
// The output is byte-identical to the TypeScript canonicalizeEnvelope function.
//
// Format: {"body":{...},"header":{...}}
//
// Header field order: messageId, nonce, recipient? (omit if empty), sender, timestampMs, ttlMs, version
// Body field order:   capability? (omit if empty), content, correlationId? (omit if empty), intent
func CanonicalizeEnvelope(h ProtocolHeader, b ProtocolBody) string {
	// Serialize header
	hParts := []string{
		fmt.Sprintf(`"messageId":%s`, jsonStr(h.MessageID)),
		fmt.Sprintf(`"nonce":%s`, jsonStr(h.Nonce)),
	}
	if h.Recipient != "" {
		hParts = append(hParts, fmt.Sprintf(`"recipient":%s`, jsonStr(h.Recipient)))
	}
	hParts = append(hParts,
		fmt.Sprintf(`"sender":%s`, jsonStr(h.Sender)),
		fmt.Sprintf(`"timestampMs":%d`, h.TimestampMs),
		fmt.Sprintf(`"ttlMs":%d`, h.TTLMs),
		fmt.Sprintf(`"version":%s`, jsonStr(h.Version)),
	)
	headerJSON := "{" + strings.Join(hParts, ",") + "}"

	// Serialize body
	var bParts []string
	if b.Capability != "" {
		bParts = append(bParts, fmt.Sprintf(`"capability":%s`, jsonStr(b.Capability)))
	}
	bParts = append(bParts, fmt.Sprintf(`"content":%s`, jsonStr(b.Content)))
	if b.CorrelationID != "" {
		bParts = append(bParts, fmt.Sprintf(`"correlationId":%s`, jsonStr(b.CorrelationID)))
	}
	bParts = append(bParts, fmt.Sprintf(`"intent":%s`, jsonStr(b.Intent)))
	bodyJSON := "{" + strings.Join(bParts, ",") + "}"

	return fmt.Sprintf(`{"body":%s,"header":%s}`, bodyJSON, headerJSON)
}

// GenerateKeypair generates an Ed25519 keypair.
// Returns publicKey as SPKI base64url and privateKey as PKCS8 base64url.
func GenerateKeypair() (publicKey, privateKey string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("protocol7h3: GenerateKeypair: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", fmt.Errorf("protocol7h3: marshal private key: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", fmt.Errorf("protocol7h3: marshal public key: %w", err)
	}

	return encodeBase64Url(pubDER), encodeBase64Url(privDER), nil
}

// CreateEnvelope creates a new unsigned ProtocolEnvelope.
func CreateEnvelope(sender, recipient string, ttlMs int64, body ProtocolBody) ProtocolEnvelope {
	nowMs := time.Now().UnixMilli()
	msgID := fmt.Sprintf("msg-%d-%s", nowMs, generateNonce()[:8])
	h := ProtocolHeader{
		Version:     WireVersion,
		MessageID:   msgID,
		TimestampMs: nowMs,
		TTLMs:       ttlMs,
		Sender:      sender,
		Recipient:   recipient,
		Nonce:       generateNonce(),
	}
	return ProtocolEnvelope{Header: h, Body: body}
}

// ValidateEnvelope validates the envelope and returns any diagnostics.
func ValidateEnvelope(env ProtocolEnvelope) []Diagnostic {
	var diags []Diagnostic
	h := env.Header

	if h.Version != WireVersion {
		diags = append(diags, Diagnostic{Level: "error", Message: fmt.Sprintf("Unsupported protocol version '%s'", h.Version)})
	}
	if strings.TrimSpace(h.MessageID) == "" {
		diags = append(diags, Diagnostic{Level: "error", Message: "Missing messageId"})
	}
	if strings.TrimSpace(h.Sender) == "" {
		diags = append(diags, Diagnostic{Level: "error", Message: "Missing sender identity"})
	}
	if strings.TrimSpace(h.Nonce) == "" {
		diags = append(diags, Diagnostic{Level: "error", Message: "Missing nonce — replay protection requires a unique nonce per message"})
	}
	if h.TTLMs <= 0 {
		diags = append(diags, Diagnostic{Level: "error", Message: "ttlMs must be greater than zero"})
	}
	if h.TTLMs > MaxTTLMs {
		diags = append(diags, Diagnostic{Level: "error", Message: fmt.Sprintf("ttlMs exceeds maximum allowed %d ms", MaxTTLMs)})
	}
	nowMs := time.Now().UnixMilli()
	if h.TimestampMs > nowMs+MaxClockSkewMs {
		diags = append(diags, Diagnostic{Level: "error", Message: fmt.Sprintf("timestampMs is more than %d ms in the future", MaxClockSkewMs)})
	}
	if h.TimestampMs+h.TTLMs < nowMs {
		diags = append(diags, Diagnostic{Level: "error", Message: "Message TTL expired"})
	}
	if strings.TrimSpace(env.Body.Content) == "" {
		diags = append(diags, Diagnostic{Level: "warning", Message: "Empty content payload"})
	}

	return diags
}

// deriveKeyID derives the keyId from a public key DER bytes (first 16 chars of base64url).
func deriveKeyID(pubDER []byte) string {
	s := encodeBase64Url(pubDER)
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

// SignEnvelopeEd25519 signs the envelope with an Ed25519 private key (PKCS8 base64url).
func SignEnvelopeEd25519(env ProtocolEnvelope, privateKeyPkcs8Base64Url string) (ProtocolEnvelope, error) {
	privDER, err := decodeBase64Url(privateKeyPkcs8Base64Url)
	if err != nil {
		return env, fmt.Errorf("protocol7h3: decode private key: %w", err)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return env, fmt.Errorf("protocol7h3: parse private key: %w", err)
	}

	edPriv, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return env, fmt.Errorf("protocol7h3: key is not Ed25519")
	}

	// Derive public key to get keyId
	edPub := edPriv.Public().(ed25519.PublicKey)
	pubDER, err := x509.MarshalPKIXPublicKey(edPub)
	if err != nil {
		return env, fmt.Errorf("protocol7h3: marshal public key: %w", err)
	}
	keyID := deriveKeyID(pubDER)

	// Canonicalize and sign
	payload := CanonicalizeEnvelope(env.Header, env.Body)
	sig := ed25519.Sign(edPriv, []byte(payload))

	signed := env
	signed.Signature = &ProtocolSignature{
		Alg:   "ED25519",
		KeyID: keyID,
		Value: encodeBase64Url(sig),
	}
	return signed, nil
}

// VerifyEnvelopeEd25519 verifies the envelope signature using an Ed25519 public key (SPKI base64url).
func VerifyEnvelopeEd25519(env ProtocolEnvelope, publicKeySpkiBase64Url string) (bool, error) {
	if env.Signature == nil {
		return false, nil
	}
	if env.Signature.Alg != "ED25519" {
		return false, nil
	}

	pubDER, err := decodeBase64Url(publicKeySpkiBase64Url)
	if err != nil {
		return false, fmt.Errorf("protocol7h3: decode public key: %w", err)
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		return false, fmt.Errorf("protocol7h3: parse public key: %w", err)
	}

	edPub, ok := pubKey.(ed25519.PublicKey)
	if !ok {
		return false, fmt.Errorf("protocol7h3: key is not Ed25519")
	}

	sigBytes, err := decodeBase64Url(env.Signature.Value)
	if err != nil {
		return false, fmt.Errorf("protocol7h3: decode signature: %w", err)
	}

	payload := CanonicalizeEnvelope(env.Header, env.Body)
	return ed25519.Verify(edPub, []byte(payload), sigBytes), nil
}

// SignEnvelopeHmac signs the envelope with HMAC-SHA256.
func SignEnvelopeHmac(env ProtocolEnvelope, secret, keyID string) (ProtocolEnvelope, error) {
	payload := CanonicalizeEnvelope(env.Header, env.Body)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := mac.Sum(nil)

	signed := env
	signed.Signature = &ProtocolSignature{
		Alg:   "HS256",
		KeyID: keyID,
		Value: encodeBase64Url(sig),
	}
	return signed, nil
}

// VerifyEnvelopeHmac verifies the envelope HMAC-SHA256 signature.
func VerifyEnvelopeHmac(env ProtocolEnvelope, secret string) (bool, error) {
	if env.Signature == nil {
		return false, nil
	}
	if env.Signature.Alg != "HS256" {
		return false, nil
	}

	sigBytes, err := decodeBase64Url(env.Signature.Value)
	if err != nil {
		return false, fmt.Errorf("protocol7h3: decode signature: %w", err)
	}

	payload := CanonicalizeEnvelope(env.Header, env.Body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)

	return hmac.Equal(expected, sigBytes), nil
}
