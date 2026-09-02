# Install: Go

```bash
go get github.com/IceMasterT/7h3-protocol/sdk/go
```

**Requires** Go 1.21+.

## Sign and verify

Verified against this repository:

```go
package main

import (
	"fmt"

	p "github.com/IceMasterT/7h3-protocol/sdk/go"
)

func main() {
	pub, priv, err := p.GenerateKeypair()
	if err != nil {
		panic(err)
	}

	env := p.CreateEnvelope(
		"agent@example.com",  // sender
		"peer@example.com",   // recipient
		60_000,               // ttlMs
		p.ProtocolBody{Intent: "TASK", Content: "process order #42"},
	)

	signed, err := p.SignEnvelopeEd25519(env, priv)
	if err != nil {
		panic(err)
	}

	ok, err := p.VerifyEnvelopeEd25519(signed, pub)
	if err != nil {
		panic(err)
	}

	fmt.Println("verified:", ok, "diagnostics:", len(p.ValidateEnvelope(signed)))
	// verified: true diagnostics: 0
}
```

Note `CreateEnvelope(sender, recipient, ttlMs, body)` — the body is a
`ProtocolBody` struct, and `ttlMs` comes before it.

HMAC works the same way via `SignEnvelopeHmac` / `VerifyEnvelopeHmac`.

## Validation

`ValidateEnvelope(env)` returns `[]Diagnostic` and takes no clock argument — it
always evaluates against `time.Now()`. It enforces the wire version, presence of
MessageID / Sender / Nonce, the 24h `MaxTTLMs` ceiling, the 30s
`MaxClockSkewMs` future-timestamp ceiling, and expiry.

## Run the tests

```bash
cd sdk/go && go test ./...
```
