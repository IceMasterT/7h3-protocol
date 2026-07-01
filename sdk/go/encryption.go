// Package protocol7h3 — E2E Encryption using X25519 + ChaCha20-Poly1305.
//
// Uses only stdlib crypto/ecdh for X25519 and golang.org/x/crypto for ChaCha20-Poly1305
// and HKDF (no other external dependencies).
//
// EncryptedEnvelope = SignedEnvelope where body.Content is a base64url-encoded
// EncryptedPayload JSON, body.Intent = "ENCRYPTED",
// body.Capability = "x25519-chacha20poly1305"
package protocol7h3

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"crypto/sha256"
)

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// EncryptedPayload holds the fields serialized into body.Content for encrypted envelopes.
type EncryptedPayload struct {
	EphemeralPublic string `json:"ephemeralPublic"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
	Tag             string `json:"tag"`
}

// ---------------------------------------------------------------------------
// Key helpers
// ---------------------------------------------------------------------------

func encodeBase64UrlRaw(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeBase64UrlRaw(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// GenerateX25519KeyPair generates a fresh X25519 keypair.
// Returns publicKey and privateKey as raw 32-byte values encoded as base64url (no padding).
func GenerateX25519KeyPair() (publicKey, privateKey string, err error) {
	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("protocol7h3: GenerateX25519KeyPair: %w", err)
	}
	pubKey := privKey.PublicKey()

	// Raw bytes: private key = privKey.Bytes() (32 bytes), public key = pubKey.Bytes() (32 bytes)
	return encodeBase64UrlRaw(pubKey.Bytes()), encodeBase64UrlRaw(privKey.Bytes()), nil
}

// importX25519Private imports a raw 32-byte X25519 private key (base64url).
func importX25519Private(privRaw32Base64Url string) (*ecdh.PrivateKey, error) {
	rawBytes, err := decodeBase64UrlRaw(privRaw32Base64Url)
	if err != nil {
		return nil, fmt.Errorf("protocol7h3: decode X25519 private key: %w", err)
	}
	curve := ecdh.X25519()
	return curve.NewPrivateKey(rawBytes)
}

// importX25519Public imports a raw 32-byte X25519 public key (base64url).
func importX25519Public(pubRaw32Base64Url string) (*ecdh.PublicKey, error) {
	rawBytes, err := decodeBase64UrlRaw(pubRaw32Base64Url)
	if err != nil {
		return nil, fmt.Errorf("protocol7h3: decode X25519 public key: %w", err)
	}
	curve := ecdh.X25519()
	return curve.NewPublicKey(rawBytes)
}

// ---------------------------------------------------------------------------
// HKDF key derivation
// ---------------------------------------------------------------------------

// deriveEncryptionKey performs X25519 DH + HKDF-SHA256 to derive a 32-byte key.
// nonce is the base64url-encoded 12-byte ChaCha nonce used as HKDF salt.
func deriveEncryptionKey(privateKeyB64, peerPublicKeyB64, nonceB64 string) ([]byte, error) {
	privKey, err := importX25519Private(privateKeyB64)
	if err != nil {
		return nil, err
	}
	pubKey, err := importX25519Public(peerPublicKeyB64)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := privKey.ECDH(pubKey)
	if err != nil {
		return nil, fmt.Errorf("protocol7h3: X25519 ECDH: %w", err)
	}

	nonceBytes, err := decodeBase64UrlRaw(nonceB64)
	if err != nil {
		return nil, fmt.Errorf("protocol7h3: decode nonce: %w", err)
	}

	kdfReader := hkdf.New(sha256.New, sharedSecret, nonceBytes, []byte("7h3-enc/1"))
	key := make([]byte, 32)
	if _, err = io.ReadFull(kdfReader, key); err != nil {
		return nil, fmt.Errorf("protocol7h3: HKDF: %w", err)
	}
	return key, nil
}

// ---------------------------------------------------------------------------
// Body encryption / decryption
// ---------------------------------------------------------------------------

// encryptBody encrypts a ProtocolBody for the given recipient X25519 public key.
// Returns the EncryptedPayload struct.
func encryptBody(body ProtocolBody, recipientPublicB64 string) (EncryptedPayload, error) {
	// Generate ephemeral X25519 keypair for forward secrecy
	ephemeralPub, ephemeralPriv, err := GenerateX25519KeyPair()
	if err != nil {
		return EncryptedPayload{}, err
	}

	// Random 12-byte ChaCha nonce (also used as HKDF salt)
	nonce12 := make([]byte, chacha20poly1305.NonceSize) // 12 bytes
	if _, err = rand.Read(nonce12); err != nil {
		return EncryptedPayload{}, fmt.Errorf("protocol7h3: generate nonce: %w", err)
	}
	nonceB64 := encodeBase64UrlRaw(nonce12)

	// Derive encryption key
	key, err := deriveEncryptionKey(ephemeralPriv, recipientPublicB64, nonceB64)
	if err != nil {
		return EncryptedPayload{}, err
	}

	// Encrypt body as JSON
	plaintext, err := json.Marshal(body)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("protocol7h3: marshal body: %w", err)
	}

	// ChaCha20-Poly1305 (12-byte nonce variant, NOT XChaCha which uses 24 bytes)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return EncryptedPayload{}, fmt.Errorf("protocol7h3: create chacha20poly1305: %w", err)
	}

	// Seal appends ciphertext‖tag (tag is last 16 bytes)
	ctWithTag := aead.Seal(nil, nonce12, plaintext, nil)
	ciphertext := ctWithTag[:len(ctWithTag)-16]
	tag := ctWithTag[len(ctWithTag)-16:]

	return EncryptedPayload{
		EphemeralPublic: ephemeralPub,
		Nonce:           nonceB64,
		Ciphertext:      encodeBase64UrlRaw(ciphertext),
		Tag:             encodeBase64UrlRaw(tag),
	}, nil
}

// decryptBody decrypts an EncryptedPayload back to a ProtocolBody.
// Returns an error if AEAD tag verification fails.
func decryptBody(encryptedContentB64, recipientPrivateB64 string) (ProtocolBody, error) {
	payloadJSON, err := decodeBase64UrlRaw(encryptedContentB64)
	if err != nil {
		return ProtocolBody{}, fmt.Errorf("protocol7h3: decode encrypted content: %w", err)
	}

	var payload EncryptedPayload
	if err = json.Unmarshal(payloadJSON, &payload); err != nil {
		return ProtocolBody{}, fmt.Errorf("protocol7h3: unmarshal encrypted payload: %w", err)
	}

	key, err := deriveEncryptionKey(recipientPrivateB64, payload.EphemeralPublic, payload.Nonce)
	if err != nil {
		return ProtocolBody{}, err
	}

	nonce12, err := decodeBase64UrlRaw(payload.Nonce)
	if err != nil {
		return ProtocolBody{}, fmt.Errorf("protocol7h3: decode nonce: %w", err)
	}

	ciphertext, err := decodeBase64UrlRaw(payload.Ciphertext)
	if err != nil {
		return ProtocolBody{}, fmt.Errorf("protocol7h3: decode ciphertext: %w", err)
	}

	tag, err := decodeBase64UrlRaw(payload.Tag)
	if err != nil {
		return ProtocolBody{}, fmt.Errorf("protocol7h3: decode tag: %w", err)
	}

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return ProtocolBody{}, fmt.Errorf("protocol7h3: create chacha20poly1305: %w", err)
	}

	// Re-concatenate ciphertext‖tag for decryption (Open expects this format)
	ctWithTag := append(ciphertext, tag...)
	plaintext, err := aead.Open(nil, nonce12, ctWithTag, nil)
	if err != nil {
		return ProtocolBody{}, fmt.Errorf("protocol7h3: decrypt: %w", err)
	}

	var body ProtocolBody
	if err = json.Unmarshal(plaintext, &body); err != nil {
		return ProtocolBody{}, fmt.Errorf("protocol7h3: unmarshal decrypted body: %w", err)
	}
	return body, nil
}

// ---------------------------------------------------------------------------
// Envelope-level seal / open
// ---------------------------------------------------------------------------

// SealEnvelope encrypts the envelope body and signs the result with Ed25519.
//
// The original body is encrypted; the envelope body is replaced with:
//
//	{ Intent: "ENCRYPTED", Content: <encrypted-payload>, Capability: "x25519-chacha20poly1305" }
//
// The modified envelope is then signed with Ed25519.
func SealEnvelope(env ProtocolEnvelope, recipientX25519Public, senderEd25519Private string) (ProtocolEnvelope, error) {
	encPayload, err := encryptBody(env.Body, recipientX25519Public)
	if err != nil {
		return env, err
	}

	payloadJSON, err := json.Marshal(encPayload)
	if err != nil {
		return env, fmt.Errorf("protocol7h3: marshal encrypted payload: %w", err)
	}
	encryptedContent := encodeBase64UrlRaw(payloadJSON)

	encBody := ProtocolBody{
		Intent:        "ENCRYPTED",
		Content:       encryptedContent,
		Capability:    "x25519-chacha20poly1305",
		CorrelationID: env.Body.CorrelationID,
	}

	encEnv := ProtocolEnvelope{
		Header: env.Header,
		Body:   encBody,
	}

	return SignEnvelopeEd25519(encEnv, senderEd25519Private)
}

// OpenEnvelope verifies the Ed25519 signature and decrypts the envelope body.
//
// Signature is verified FIRST — decryption only proceeds if valid.
// Returns the signed envelope (with encrypted body) and the decrypted original body.
func OpenEnvelope(env ProtocolEnvelope, recipientX25519Private, senderEd25519Public string) (ProtocolEnvelope, ProtocolBody, error) {
	// 1. Verify Ed25519 signature FIRST
	valid, err := VerifyEnvelopeEd25519(env, senderEd25519Public)
	if err != nil {
		return env, ProtocolBody{}, fmt.Errorf("protocol7h3: signature verification error: %w", err)
	}
	if !valid {
		return env, ProtocolBody{}, errors.New("protocol7h3: Ed25519 signature verification failed")
	}

	// 2. Decrypt body
	body, err := decryptBody(env.Body.Content, recipientX25519Private)
	if err != nil {
		return env, ProtocolBody{}, err
	}

	return env, body, nil
}
