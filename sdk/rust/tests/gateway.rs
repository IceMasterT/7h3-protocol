use protocol_7h3::{
    create_aip_mcp_gateway_runtime, create_signed_task_from_jsonrpc,
    jsonrpc_response_from_envelope, AipMcpGatewayOptions, JsonRpcBridgeConfig, JsonRpcId,
    JsonRpcRequestLike,
};
use serde_json::json;

#[test]
fn jsonrpc_bridge_creates_signed_task_with_capability() {
    let request = JsonRpcRequestLike {
        jsonrpc: "2.0".to_string(),
        id: JsonRpcId::Number(7),
        method: "tools/call".to_string(),
        params: Some(json!({"name":"planner"})),
    };

    let config = JsonRpcBridgeConfig {
        recipient: Some("agent.worker".to_string()),
        allowed_methods: Some(vec!["tools/call".to_string()]),
        capability_prefix: "mcp.".to_string(),
    };

    let envelope = create_signed_task_from_jsonrpc(
        &request,
        "agent.gateway",
        "secret",
        "gateway-k1",
        1_700_000_000_000,
        &config,
        Option::<fn(&JsonRpcRequestLike, &protocol_7h3::JsonRpcPolicyContext) -> bool>::None,
        Option::<fn(&str, &JsonRpcRequestLike, &protocol_7h3::JsonRpcPolicyContext) -> bool>::None,
    )
    .expect("bridge should produce envelope");

    assert_eq!(envelope.body.intent, "TASK");
    assert_eq!(envelope.body.capability.as_deref(), Some("mcp.tools/call"));
    assert_eq!(envelope.body.correlation_id.as_deref(), Some("7"));
    assert!(envelope.signature.is_some());
}

#[test]
fn jsonrpc_bridge_blocks_disallowed_method() {
    let request = JsonRpcRequestLike {
        jsonrpc: "2.0".to_string(),
        id: JsonRpcId::String("abc".to_string()),
        method: "resources/read".to_string(),
        params: None,
    };

    let config = JsonRpcBridgeConfig {
        recipient: Some("agent.worker".to_string()),
        allowed_methods: Some(vec!["tools/call".to_string()]),
        capability_prefix: "mcp.".to_string(),
    };

    let error = create_signed_task_from_jsonrpc(
        &request,
        "agent.gateway",
        "secret",
        "gateway-k1",
        1_700_000_000_000,
        &config,
        Option::<fn(&JsonRpcRequestLike, &protocol_7h3::JsonRpcPolicyContext) -> bool>::None,
        Option::<fn(&str, &JsonRpcRequestLike, &protocol_7h3::JsonRpcPolicyContext) -> bool>::None,
    )
    .expect_err("bridge should reject disallowed methods");

    assert!(error.contains("not allowed"));
}

#[test]
fn gateway_runtime_handles_line_success_and_errors() {
    let options = AipMcpGatewayOptions {
        shared_secret: "gateway-secret".to_string(),
        ..AipMcpGatewayOptions::default()
    };
    let runtime = create_aip_mcp_gateway_runtime(options);

    let ok_line = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name":"planner"}
    })
    .to_string();
    let ok_response = runtime
        .handle_line(&ok_line, 1_700_000_000_000)
        .expect("non-empty response expected");
    let ok_json: serde_json::Value =
        serde_json::from_str(&ok_response).expect("valid json response");
    assert_eq!(ok_json["jsonrpc"], "2.0");
    assert_eq!(ok_json["id"], 1);
    assert!(ok_json.get("result").is_some());

    let bad_line = json!({"bad":true}).to_string();
    let bad_response = runtime
        .handle_line(&bad_line, 1_700_000_000_001)
        .expect("error response expected");
    let bad_json: serde_json::Value =
        serde_json::from_str(&bad_response).expect("valid json response");
    assert_eq!(bad_json["error"]["code"], -32600);
}

#[test]
fn jsonrpc_response_maps_error_intent() {
    let envelope = protocol_7h3::ProtocolEnvelope {
        header: protocol_7h3::ProtocolHeader {
            version: "7h3/0.1".to_string(),
            message_id: "m1".to_string(),
            timestamp_ms: 1,
            ttl_ms: 1,
            sender: "agent.worker".to_string(),
            recipient: Some("agent.gateway".to_string()),
            nonce: "n1".to_string(),
        },
        body: protocol_7h3::ProtocolBody {
            intent: "ERROR".to_string(),
            content: "permission denied".to_string(),
            capability: Some("mcp.tools/call".to_string()),
            correlation_id: Some("7".to_string()),
        },
        signature: None,
    };

    let response = jsonrpc_response_from_envelope(&envelope, JsonRpcId::Number(7));
    assert_eq!(response.jsonrpc, "2.0");
    assert_eq!(response.id, JsonRpcId::Number(7));
    assert!(response.result.is_none());
    assert_eq!(response.error.expect("error expected").code, -32000);
}
