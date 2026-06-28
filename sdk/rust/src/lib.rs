use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolHeader {
    pub version: String,
    #[serde(rename = "messageId")]
    pub message_id: String,
    #[serde(rename = "timestampMs")]
    pub timestamp_ms: i64,
    #[serde(rename = "ttlMs")]
    pub ttl_ms: i64,
    pub sender: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolBody {
    pub intent: String,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(rename = "correlationId", skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolSignature {
    pub alg: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolEnvelope {
    pub header: ProtocolHeader,
    pub body: ProtocolBody,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<ProtocolSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolDiagnostic {
    pub level: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompactSignature {
    #[serde(skip_serializing_if = "Option::is_none")]
    a: Option<String>,
    k: String,
    v: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompactEnvelope {
    v: String,
    mid: String,
    ts: i64,
    ttl: i64,
    s: String,
    n: String,
    i: String,
    c: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    r: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cap: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sig: Option<CompactSignature>,
}

fn json_string<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).expect("json serialization should not fail")
}

pub fn canonicalize_envelope(envelope: &ProtocolEnvelope) -> String {
    let mut body_parts: Vec<String> = Vec::new();
    if let Some(capability) = &envelope.body.capability {
        body_parts.push(format!("\"capability\":{}", json_string(capability)));
    }
    body_parts.push(format!(
        "\"content\":{}",
        json_string(&envelope.body.content)
    ));
    if let Some(correlation_id) = &envelope.body.correlation_id {
        body_parts.push(format!("\"correlationId\":{}", json_string(correlation_id)));
    }
    body_parts.push(format!("\"intent\":{}", json_string(&envelope.body.intent)));

    let mut header_parts: Vec<String> = vec![
        format!("\"messageId\":{}", json_string(&envelope.header.message_id)),
        format!("\"nonce\":{}", json_string(&envelope.header.nonce)),
    ];
    if let Some(recipient) = &envelope.header.recipient {
        header_parts.push(format!("\"recipient\":{}", json_string(recipient)));
    }
    header_parts.push(format!(
        "\"sender\":{}",
        json_string(&envelope.header.sender)
    ));
    header_parts.push(format!("\"timestampMs\":{}", envelope.header.timestamp_ms));
    header_parts.push(format!("\"ttlMs\":{}", envelope.header.ttl_ms));
    header_parts.push(format!(
        "\"version\":{}",
        json_string(&envelope.header.version)
    ));

    format!(
        "{{\"body\":{{{}}},\"header\":{{{}}}}}",
        body_parts.join(","),
        header_parts.join(",")
    )
}

pub fn sign_canonical_payload_hmac(canonical_payload: &str, secret: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC key should be valid");
    mac.update(canonical_payload.as_bytes());
    let digest = mac.finalize().into_bytes();
    URL_SAFE_NO_PAD.encode(digest)
}

pub fn verify_canonical_payload_hmac(
    canonical_payload: &str,
    signature: &str,
    secret: &str,
) -> bool {
    let expected = sign_canonical_payload_hmac(canonical_payload, secret);
    expected == signature
}

pub fn sign_canonical_payload_ed25519(
    canonical_payload: &str,
    private_key_pkcs8_base64url: &str,
) -> Result<String, String> {
    let private_der = URL_SAFE_NO_PAD
        .decode(private_key_pkcs8_base64url)
        .map_err(|_| "Invalid ED25519 private key encoding".to_string())?;
    let signing_key = SigningKey::from_pkcs8_der(&private_der)
        .map_err(|_| "Invalid ED25519 private key".to_string())?;
    let signature = signing_key.sign(canonical_payload.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(signature.to_bytes()))
}

pub fn verify_canonical_payload_ed25519(
    canonical_payload: &str,
    signature_base64url: &str,
    public_key_spki_base64url: &str,
) -> Result<bool, String> {
    let public_der = URL_SAFE_NO_PAD
        .decode(public_key_spki_base64url)
        .map_err(|_| "Invalid ED25519 public key encoding".to_string())?;
    let verifying_key = VerifyingKey::from_public_key_der(&public_der)
        .map_err(|_| "Invalid ED25519 public key".to_string())?;

    let signature_raw = URL_SAFE_NO_PAD
        .decode(signature_base64url)
        .map_err(|_| "Invalid ED25519 signature encoding".to_string())?;
    let signature = Ed25519Signature::from_slice(&signature_raw)
        .map_err(|_| "Invalid ED25519 signature".to_string())?;

    Ok(verifying_key
        .verify(canonical_payload.as_bytes(), &signature)
        .is_ok())
}

pub fn sign_envelope_hmac(
    envelope: &ProtocolEnvelope,
    secret: &str,
    key_id: &str,
) -> ProtocolEnvelope {
    let mut unsigned = envelope.clone();
    unsigned.signature = None;
    let canonical = canonicalize_envelope(&unsigned);
    let signature = sign_canonical_payload_hmac(&canonical, secret);
    let mut signed = unsigned;
    signed.signature = Some(ProtocolSignature {
        alg: "HS256".to_string(),
        key_id: key_id.to_string(),
        value: signature,
    });
    signed
}

pub fn verify_envelope_hmac(envelope: &ProtocolEnvelope, secret: &str) -> bool {
    let Some(signature) = &envelope.signature else {
        return false;
    };
    if signature.alg != "HS256" {
        return false;
    }
    let mut unsigned = envelope.clone();
    unsigned.signature = None;
    let canonical = canonicalize_envelope(&unsigned);
    verify_canonical_payload_hmac(&canonical, &signature.value, secret)
}

pub fn sign_envelope_ed25519(
    envelope: &ProtocolEnvelope,
    private_key_pkcs8_base64url: &str,
    key_id: &str,
) -> Result<ProtocolEnvelope, String> {
    let mut unsigned = envelope.clone();
    unsigned.signature = None;
    let canonical = canonicalize_envelope(&unsigned);
    let signature = sign_canonical_payload_ed25519(&canonical, private_key_pkcs8_base64url)?;
    let mut signed = unsigned;
    signed.signature = Some(ProtocolSignature {
        alg: "ED25519".to_string(),
        key_id: key_id.to_string(),
        value: signature,
    });
    Ok(signed)
}

pub fn verify_envelope_ed25519(
    envelope: &ProtocolEnvelope,
    public_key_spki_base64url: &str,
) -> Result<bool, String> {
    let Some(signature) = &envelope.signature else {
        return Ok(false);
    };
    if signature.alg != "ED25519" {
        return Ok(false);
    }
    let mut unsigned = envelope.clone();
    unsigned.signature = None;
    let canonical = canonicalize_envelope(&unsigned);
    verify_canonical_payload_ed25519(&canonical, &signature.value, public_key_spki_base64url)
}

pub fn encode_envelope_compact(envelope: &ProtocolEnvelope) -> String {
    let compact = CompactEnvelope {
        v: envelope.header.version.clone(),
        mid: envelope.header.message_id.clone(),
        ts: envelope.header.timestamp_ms,
        ttl: envelope.header.ttl_ms,
        s: envelope.header.sender.clone(),
        n: envelope.header.nonce.clone(),
        i: envelope.body.intent.clone(),
        c: envelope.body.content.clone(),
        r: envelope.header.recipient.clone(),
        cap: envelope.body.capability.clone(),
        cid: envelope.body.correlation_id.clone(),
        sig: envelope.signature.as_ref().map(|sig| CompactSignature {
            a: Some(sig.alg.clone()),
            k: sig.key_id.clone(),
            v: sig.value.clone(),
        }),
    };
    serde_json::to_string(&compact).expect("compact envelope serialization should not fail")
}

pub fn decode_envelope(raw: &str) -> Result<ProtocolEnvelope, String> {
    let parsed: Value =
        serde_json::from_str(raw).map_err(|_| "Invalid JSON payload".to_string())?;

    if parsed.get("header").is_some() && parsed.get("body").is_some() {
        return serde_json::from_value(parsed)
            .map_err(|_| "Envelope JSON shape is not recognized".to_string());
    }

    let compact: CompactEnvelope = serde_json::from_value(parsed)
        .map_err(|_| "Envelope JSON shape is not recognized".to_string())?;
    if compact.v != "7h3/0.1" {
        return Err("Envelope JSON shape is not recognized".to_string());
    }

    Ok(ProtocolEnvelope {
        header: ProtocolHeader {
            version: compact.v,
            message_id: compact.mid,
            timestamp_ms: compact.ts,
            ttl_ms: compact.ttl,
            sender: compact.s,
            recipient: compact.r,
            nonce: compact.n,
        },
        body: ProtocolBody {
            intent: compact.i,
            content: compact.c,
            capability: compact.cap,
            correlation_id: compact.cid,
        },
        signature: compact.sig.map(|sig| ProtocolSignature {
            alg: sig.a.unwrap_or_else(|| "HS256".to_string()),
            key_id: sig.k,
            value: sig.v,
        }),
    })
}

pub fn validate_envelope(
    envelope: &ProtocolEnvelope,
    now_ms: Option<i64>,
) -> Vec<ProtocolDiagnostic> {
    let mut diagnostics: Vec<ProtocolDiagnostic> = Vec::new();

    if envelope.header.version != "7h3/0.1" {
        diagnostics.push(ProtocolDiagnostic {
            level: "error".to_string(),
            message: format!("Unsupported protocol version '{}'", envelope.header.version),
        });
    }
    if envelope.header.message_id.trim().is_empty() {
        diagnostics.push(ProtocolDiagnostic {
            level: "error".to_string(),
            message: "Missing messageId".to_string(),
        });
    }
    if envelope.header.sender.trim().is_empty() {
        diagnostics.push(ProtocolDiagnostic {
            level: "error".to_string(),
            message: "Missing sender identity".to_string(),
        });
    }
    if envelope.header.ttl_ms <= 0 {
        diagnostics.push(ProtocolDiagnostic {
            level: "error".to_string(),
            message: "ttlMs must be greater than zero".to_string(),
        });
    }
    if let Some(now) = now_ms {
        if envelope.header.timestamp_ms + envelope.header.ttl_ms < now {
            diagnostics.push(ProtocolDiagnostic {
                level: "error".to_string(),
                message: "Message TTL expired".to_string(),
            });
        }
    }
    if envelope.body.content.trim().is_empty() {
        diagnostics.push(ProtocolDiagnostic {
            level: "warning".to_string(),
            message: "Empty content payload".to_string(),
        });
    }

    diagnostics
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum JsonRpcId {
    Null,
    String(String),
    Number(i64),
}

impl JsonRpcId {
    fn as_string(&self) -> String {
        match self {
            JsonRpcId::Null => "null".to_string(),
            JsonRpcId::String(value) => value.clone(),
            JsonRpcId::Number(value) => value.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcRequestLike {
    pub jsonrpc: String,
    pub id: JsonRpcId,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JsonRpcResponseLike {
    pub jsonrpc: String,
    pub id: JsonRpcId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcPolicyContext {
    pub intent: String,
    pub recipient: Option<String>,
    pub capability: String,
    pub correlation_id: String,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone)]
pub struct JsonRpcBridgeConfig {
    pub recipient: Option<String>,
    pub allowed_methods: Option<Vec<String>>,
    pub capability_prefix: String,
}

impl Default for JsonRpcBridgeConfig {
    fn default() -> Self {
        Self {
            recipient: None,
            allowed_methods: None,
            capability_prefix: "mcp.".to_string(),
        }
    }
}

pub fn create_envelope(
    sender: &str,
    recipient: Option<&str>,
    intent: &str,
    content: &str,
    capability: Option<&str>,
    correlation_id: Option<&str>,
    now_ms: i64,
    ttl_ms: i64,
) -> ProtocolEnvelope {
    ProtocolEnvelope {
        header: ProtocolHeader {
            version: "7h3/0.1".to_string(),
            message_id: format!("msg-{}-{}", now_ms, sender),
            timestamp_ms: now_ms,
            ttl_ms,
            sender: sender.to_string(),
            recipient: recipient.map(|value| value.to_string()),
            nonce: format!("n-{}", now_ms),
        },
        body: ProtocolBody {
            intent: intent.to_string(),
            content: content.to_string(),
            capability: capability.map(|value| value.to_string()),
            correlation_id: correlation_id.map(|value| value.to_string()),
        },
        signature: None,
    }
}

pub fn create_signed_task_from_jsonrpc<F, G>(
    request: &JsonRpcRequestLike,
    sender: &str,
    secret: &str,
    key_id: &str,
    now_ms: i64,
    config: &JsonRpcBridgeConfig,
    authorize: Option<F>,
    rate_limit: Option<G>,
) -> Result<ProtocolEnvelope, String>
where
    F: Fn(&JsonRpcRequestLike, &JsonRpcPolicyContext) -> bool,
    G: Fn(&str, &JsonRpcRequestLike, &JsonRpcPolicyContext) -> bool,
{
    if request.jsonrpc != "2.0" {
        return Err("JSON-RPC request must have jsonrpc='2.0'".to_string());
    }
    if request.method.trim().is_empty() {
        return Err("JSON-RPC request must include method".to_string());
    }
    if let Some(allowlist) = &config.allowed_methods {
        if !allowlist.iter().any(|method| method == &request.method) {
            return Err(format!(
                "JSON-RPC method '{}' is not allowed",
                request.method
            ));
        }
    }

    let correlation_id = request.id.as_string();
    let capability = format!("{}{}", config.capability_prefix, request.method);
    let context = JsonRpcPolicyContext {
        intent: "TASK".to_string(),
        recipient: config.recipient.clone(),
        capability: capability.clone(),
        correlation_id: correlation_id.clone(),
        created_at_ms: now_ms,
    };

    if let Some(authorize_fn) = authorize {
        if !authorize_fn(request, &context) {
            return Err(format!(
                "JSON-RPC method '{}' is not authorized",
                request.method
            ));
        }
    }

    let rate_key = request.method.clone();
    if let Some(rate_limit_fn) = rate_limit {
        if !rate_limit_fn(&rate_key, request, &context) {
            return Err(format!(
                "JSON-RPC method '{}' is rate-limited",
                request.method
            ));
        }
    }

    let content = json_string(&serde_json::json!({
        "method": request.method,
        "params": request.params.clone().unwrap_or(Value::Null),
    }));
    let envelope = create_envelope(
        sender,
        config.recipient.as_deref(),
        "TASK",
        &content,
        Some(&capability),
        Some(&correlation_id),
        now_ms,
        60_000,
    );
    Ok(sign_envelope_hmac(&envelope, secret, key_id))
}

pub fn jsonrpc_response_from_envelope(
    envelope: &ProtocolEnvelope,
    id: JsonRpcId,
) -> JsonRpcResponseLike {
    if envelope.body.intent == "ERROR" {
        return JsonRpcResponseLike {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code: -32000,
                message: envelope.body.content.clone(),
                data: Some(serde_json::json!({
                    "capability": envelope.body.capability,
                    "correlationId": envelope.body.correlation_id,
                })),
            }),
        };
    }

    let result = serde_json::from_str::<Value>(&envelope.body.content)
        .unwrap_or_else(|_| Value::String(envelope.body.content.clone()));
    JsonRpcResponseLike {
        jsonrpc: "2.0".to_string(),
        id,
        result: Some(result),
        error: None,
    }
}

#[derive(Debug, Clone)]
pub struct AipMcpGatewayOptions {
    pub shared_secret: String,
    pub gateway_agent_id: String,
    pub worker_agent_id: String,
    pub allowed_methods: Vec<String>,
    pub capability_prefix: String,
}

impl Default for AipMcpGatewayOptions {
    fn default() -> Self {
        Self {
            shared_secret: "mcp-gateway-secret".to_string(),
            gateway_agent_id: "agent.gateway".to_string(),
            worker_agent_id: "agent.worker".to_string(),
            allowed_methods: vec![
                "tools/call".to_string(),
                "resources/read".to_string(),
                "prompts/get".to_string(),
            ],
            capability_prefix: "mcp.".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AipMcpGatewayRuntime {
    options: AipMcpGatewayOptions,
}

pub fn create_aip_mcp_gateway_runtime(options: AipMcpGatewayOptions) -> AipMcpGatewayRuntime {
    AipMcpGatewayRuntime { options }
}

impl AipMcpGatewayRuntime {
    fn error_response(id: Option<JsonRpcId>, code: i64, message: &str) -> String {
        let response = JsonRpcResponseLike {
            jsonrpc: "2.0".to_string(),
            id: id.unwrap_or(JsonRpcId::Null),
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.to_string(),
                data: None,
            }),
        };
        json_string(&response)
    }

    pub fn handle_line(&self, line: &str, now_ms: i64) -> Option<String> {
        let raw = line.trim();
        if raw.is_empty() {
            return None;
        }

        let request: JsonRpcRequestLike = match serde_json::from_str(raw) {
            Ok(parsed) => parsed,
            Err(_) => {
                return Some(Self::error_response(None, -32600, "Invalid Request"));
            }
        };

        let bridge_config = JsonRpcBridgeConfig {
            recipient: Some(self.options.worker_agent_id.clone()),
            allowed_methods: Some(self.options.allowed_methods.clone()),
            capability_prefix: self.options.capability_prefix.clone(),
        };

        let outbound = match create_signed_task_from_jsonrpc(
            &request,
            &self.options.gateway_agent_id,
            &self.options.shared_secret,
            "gateway-k1",
            now_ms,
            &bridge_config,
            Option::<fn(&JsonRpcRequestLike, &JsonRpcPolicyContext) -> bool>::None,
            Option::<fn(&str, &JsonRpcRequestLike, &JsonRpcPolicyContext) -> bool>::None,
        ) {
            Ok(envelope) => envelope,
            Err(message) => {
                let code = if message.contains("not allowed") {
                    -32601
                } else if message.contains("not authorized") {
                    -32001
                } else if message.contains("rate-limited") {
                    -32002
                } else {
                    -32603
                };
                return Some(Self::error_response(Some(request.id), code, &message));
            }
        };

        let worker_payload = serde_json::json!({
            "ok": true,
            "capability": outbound.body.capability,
            "content": outbound.body.content,
        });
        let worker_envelope = create_envelope(
            &self.options.worker_agent_id,
            Some(&self.options.gateway_agent_id),
            "RESULT",
            &json_string(&worker_payload),
            outbound.body.capability.as_deref(),
            outbound.body.correlation_id.as_deref(),
            now_ms,
            60_000,
        );
        let signed_worker =
            sign_envelope_hmac(&worker_envelope, &self.options.shared_secret, "worker-k1");

        if !verify_envelope_hmac(&signed_worker, &self.options.shared_secret) {
            return Some(Self::error_response(
                Some(request.id),
                -32603,
                "AIP verification failed",
            ));
        }

        let response = jsonrpc_response_from_envelope(&signed_worker, request.id);
        Some(json_string(&response))
    }
}
