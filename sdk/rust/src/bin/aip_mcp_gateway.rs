use protocol_7h3::{create_aip_mcp_gateway_runtime, AipMcpGatewayOptions};
use std::io::{self, BufRead, Write};
use std::time::{SystemTime, UNIX_EPOCH};

fn current_time_ms() -> i64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    i64::try_from(millis).unwrap_or(i64::MAX)
}

fn parse_allowed_methods_from_env() -> Vec<String> {
    std::env::var("AIP_ALLOWED_METHODS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(|item| item.trim().to_string())
                .filter(|item| !item.is_empty())
                .collect::<Vec<_>>()
        })
        .filter(|items| !items.is_empty())
        .unwrap_or_else(|| {
            vec![
                "tools/call".to_string(),
                "resources/read".to_string(),
                "prompts/get".to_string(),
            ]
        })
}

fn main() {
    let shared_secret =
        std::env::var("AIP_SHARED_SECRET").unwrap_or_else(|_| "mcp-gateway-secret".to_string());
    let runtime = create_aip_mcp_gateway_runtime(AipMcpGatewayOptions {
        shared_secret,
        allowed_methods: parse_allowed_methods_from_env(),
        ..AipMcpGatewayOptions::default()
    });

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line_result in stdin.lock().lines() {
        let line = match line_result {
            Ok(value) => value,
            Err(_) => break,
        };

        if let Some(response) = runtime.handle_line(&line, current_time_ms()) {
            if writeln!(stdout, "{}", response).is_err() {
                break;
            }
            if stdout.flush().is_err() {
                break;
            }
        }
    }
}
