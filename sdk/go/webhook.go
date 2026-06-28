package protocol7h3

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strconv"
	"time"
)

// WebhookSigHeader is the HTTP header carrying the webhook signature.
const WebhookSigHeader = "X-7h3-Sig"

// WebhookTsHeader is the HTTP header carrying the webhook timestamp.
const WebhookTsHeader = "X-7h3-Ts"

// WebhookDefaultTTLMs is the default maximum age for webhook signatures.
const WebhookDefaultTTLMs int64 = 300_000

// webhookPayload constructs the signed payload: "<tsMs>.<body>"
func webhookPayload(tsMs int64, body string) string {
	return fmt.Sprintf("%d.%s", tsMs, body)
}

// SignWebhook signs a webhook body with an Ed25519 private key (PKCS8 base64url).
// Returns sig (base64url) and tsMs (string timestamp milliseconds).
func SignWebhook(body, privateKeyPkcs8Base64Url string) (sig, tsMs string, err error) {
	privDER, err := decodeBase64Url(privateKeyPkcs8Base64Url)
	if err != nil {
		return "", "", fmt.Errorf("protocol7h3: decode private key: %w", err)
	}

	privKey, err := x509.ParsePKCS8PrivateKey(privDER)
	if err != nil {
		return "", "", fmt.Errorf("protocol7h3: parse private key: %w", err)
	}

	edPriv, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return "", "", fmt.Errorf("protocol7h3: key is not Ed25519")
	}

	nowMs := time.Now().UnixMilli()
	payload := webhookPayload(nowMs, body)
	sigBytes := ed25519.Sign(edPriv, []byte(payload))

	return encodeBase64Url(sigBytes), strconv.FormatInt(nowMs, 10), nil
}

// VerifyWebhook verifies a webhook signature.
// maxAgeMs defaults to WebhookDefaultTTLMs if not provided.
func VerifyWebhook(body, sig, tsStr, publicKeySpkiBase64Url string, maxAgeMs ...int64) (bool, error) {
	tsMs, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false, fmt.Errorf("protocol7h3: invalid timestamp: %w", err)
	}

	maxAge := WebhookDefaultTTLMs
	if len(maxAgeMs) > 0 {
		maxAge = maxAgeMs[0]
	}

	nowMs := time.Now().UnixMilli()
	if nowMs-tsMs > maxAge {
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

	sigBytes, err := decodeBase64Url(sig)
	if err != nil {
		return false, fmt.Errorf("protocol7h3: decode signature: %w", err)
	}

	payload := webhookPayload(tsMs, body)
	return ed25519.Verify(edPub, []byte(payload), sigBytes), nil
}

// SignWebhookHmac signs a webhook body with HMAC-SHA256.
// Returns sig (base64url) and tsMs (string timestamp milliseconds).
func SignWebhookHmac(body, secret string) (sig, tsMs string, err error) {
	nowMs := time.Now().UnixMilli()
	payload := webhookPayload(nowMs, body)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sigBytes := mac.Sum(nil)

	return encodeBase64Url(sigBytes), strconv.FormatInt(nowMs, 10), nil
}

// VerifyWebhookHmac verifies a webhook HMAC-SHA256 signature.
// maxAgeMs defaults to WebhookDefaultTTLMs if not provided.
func VerifyWebhookHmac(body, sig, tsStr, secret string, maxAgeMs ...int64) (bool, error) {
	tsMs, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false, fmt.Errorf("protocol7h3: invalid timestamp: %w", err)
	}

	maxAge := WebhookDefaultTTLMs
	if len(maxAgeMs) > 0 {
		maxAge = maxAgeMs[0]
	}

	nowMs := time.Now().UnixMilli()
	if nowMs-tsMs > maxAge {
		return false, nil
	}

	sigBytes, err := decodeBase64Url(sig)
	if err != nil {
		return false, fmt.Errorf("protocol7h3: decode signature: %w", err)
	}

	payload := webhookPayload(tsMs, body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)

	return hmac.Equal(expected, sigBytes), nil
}
