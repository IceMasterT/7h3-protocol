package protocol7h3

import (
	"encoding/json"
	"net/http"
)

// HTTPEnvelopeHeader is the default HTTP header name for the protocol envelope.
const HTTPEnvelopeHeader = "X-7h3-Envelope"

// VerifyFailReason describes why HTTP envelope verification failed.
type VerifyFailReason string

const (
	ReasonMissingHeader    VerifyFailReason = "missing_header"
	ReasonMalformed        VerifyFailReason = "malformed"
	ReasonUnknownSender    VerifyFailReason = "unknown_sender"
	ReasonInvalidSignature VerifyFailReason = "invalid_signature"
	ReasonExpired          VerifyFailReason = "expired"
)

// KeyRegistry looks up public keys by sender ID.
type KeyRegistry interface {
	GetPublicKey(senderID string) (string, bool)
}

// StaticKeyRegistry is a simple in-memory key registry.
type StaticKeyRegistry struct {
	Keys map[string]string
}

// GetPublicKey returns the public key for the given sender ID.
func (r *StaticKeyRegistry) GetPublicKey(senderID string) (string, bool) {
	k, ok := r.Keys[senderID]
	return k, ok
}

// HTTPVerifyResult is the result of verifying an HTTP envelope.
type HTTPVerifyResult struct {
	OK       bool
	Envelope *ProtocolEnvelope
	Reason   VerifyFailReason
	Detail   string
}

// headerName returns the header name to use (default: HTTPEnvelopeHeader).
func resolveHeaderName(names []string) string {
	if len(names) > 0 && names[0] != "" {
		return names[0]
	}
	return HTTPEnvelopeHeader
}

// VerifyHTTPEnvelope extracts and verifies the protocol envelope from an HTTP request.
func VerifyHTTPEnvelope(r *http.Request, registry KeyRegistry, headerName ...string) HTTPVerifyResult {
	hdr := resolveHeaderName(headerName)
	val := r.Header.Get(hdr)
	if val == "" {
		return HTTPVerifyResult{OK: false, Reason: ReasonMissingHeader, Detail: "header " + hdr + " not present"}
	}

	var env ProtocolEnvelope
	if err := json.Unmarshal([]byte(val), &env); err != nil {
		return HTTPVerifyResult{OK: false, Reason: ReasonMalformed, Detail: err.Error()}
	}

	// Check expiry
	diags := ValidateEnvelope(env)
	for _, d := range diags {
		if d.Message == "Message TTL expired" {
			return HTTPVerifyResult{OK: false, Envelope: &env, Reason: ReasonExpired, Detail: d.Message}
		}
	}

	// Check sender
	if env.Header.Sender == "" {
		return HTTPVerifyResult{OK: false, Envelope: &env, Reason: ReasonMalformed, Detail: "missing sender"}
	}

	pubKey, ok := registry.GetPublicKey(env.Header.Sender)
	if !ok {
		return HTTPVerifyResult{OK: false, Envelope: &env, Reason: ReasonUnknownSender, Detail: "no key for sender: " + env.Header.Sender}
	}

	if env.Signature == nil {
		return HTTPVerifyResult{OK: false, Envelope: &env, Reason: ReasonInvalidSignature, Detail: "no signature"}
	}

	var valid bool
	var verifyErr error
	switch env.Signature.Alg {
	case "ED25519":
		valid, verifyErr = VerifyEnvelopeEd25519(env, pubKey)
	case "HS256":
		valid, verifyErr = VerifyEnvelopeHmac(env, pubKey)
	default:
		return HTTPVerifyResult{OK: false, Envelope: &env, Reason: ReasonInvalidSignature, Detail: "unknown alg: " + env.Signature.Alg}
	}

	if verifyErr != nil {
		return HTTPVerifyResult{OK: false, Envelope: &env, Reason: ReasonInvalidSignature, Detail: verifyErr.Error()}
	}
	if !valid {
		return HTTPVerifyResult{OK: false, Envelope: &env, Reason: ReasonInvalidSignature, Detail: "signature mismatch"}
	}

	return HTTPVerifyResult{OK: true, Envelope: &env}
}

// SignHTTPRequest signs the envelope and returns the header name and JSON value to set.
func SignHTTPRequest(env ProtocolEnvelope, privateKey string, headerName ...string) (name, value string, err error) {
	signed, err := SignEnvelopeEd25519(env, privateKey)
	if err != nil {
		return "", "", err
	}

	b, err := json.Marshal(signed)
	if err != nil {
		return "", "", err
	}

	return resolveHeaderName(headerName), string(b), nil
}

// Middleware returns an http.Handler that verifies the protocol envelope before passing to next.
func Middleware(registry KeyRegistry, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := VerifyHTTPEnvelope(r, registry)
		if !result.OK {
			http.Error(w, string(result.Reason)+": "+result.Detail, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
