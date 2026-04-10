//! Core async proxy loop.
//!
//! Reads newline-delimited JSON-RPC from stdin, intercepts `tools/call`
//! requests, evaluates them against the loaded Aegis policy, and either:
//! - returns a policy-violation error to the client (Deny verdict), or
//! - forwards the message to the upstream MCP server and relays the response.
//!
//! All other message types (initialize, notifications, ping, etc.) are
//! forwarded transparently.
//!
//! # Concurrency model
//!
//! Three concurrent tasks:
//! 1. **Writer** — drains a `mpsc` channel and writes bytes to stdout.
//!    This serialises writes from the intercept path (deny responses) and
//!    the relay path (upstream responses) so they never interleave.
//! 2. **Relay** — reads lines from upstream stdout and pushes them onto
//!    the writer channel.
//! 3. **Intercept** (main task) — reads lines from stdin, checks policy,
//!    either writes a denial onto the writer channel or forwards the line
//!    to upstream stdin.

use std::sync::Arc;

use aegis_compiler::ast::Verdict;
use aegis_compiler::ir::CompiledPolicy;
use aegis_runtime::engine::PolicyEngine;
use serde_json::Value as JsonValue;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::{mpsc, Mutex};

use crate::bridge::mcp_tool_call_to_event;
use crate::error::{Error, Result};
use crate::jsonrpc::{Message, POLICY_VIOLATION_CODE};

/// Run the proxy until the client (stdin) disconnects or the upstream exits.
///
/// `verbose` enables per-message logging to stderr.
pub async fn run(
    policy: CompiledPolicy,
    mut child: Child,
    upstream_stdin: ChildStdin,
    upstream_stdout: ChildStdout,
    verbose: bool,
) -> Result<()> {
    let engine = Arc::new(Mutex::new(PolicyEngine::new(policy)));

    // Channel serialising all writes to our stdout.
    let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(256);

    let writer_task = spawn_writer(out_rx);
    let relay_task = spawn_relay(upstream_stdout, out_tx.clone());

    intercept_loop(engine, upstream_stdin, out_tx, verbose).await?;

    // Tidy shutdown: wait for relay and writer to drain.
    relay_task.await.ok();
    writer_task.await.ok();
    child.wait().await.ok();

    Ok(())
}

// ── Writer task ───────────────────────────────────────────────────────────────

/// Spawn a task that drains `out_rx` and writes each chunk to stdout.
fn spawn_writer(mut out_rx: mpsc::Receiver<Vec<u8>>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(bytes) = out_rx.recv().await {
            if stdout.write_all(&bytes).await.is_err() {
                break;
            }
            // Flush after every message so the client sees it immediately.
            let _ = stdout.flush().await;
        }
    })
}

// ── Relay task ────────────────────────────────────────────────────────────────

/// Spawn a task that copies lines from `upstream_stdout` to `out_tx`.
fn spawn_relay(
    upstream_stdout: ChildStdout,
    out_tx: mpsc::Sender<Vec<u8>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut reader = BufReader::new(upstream_stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break, // upstream closed or errored
                Ok(_) => {
                    if out_tx.send(line.as_bytes().to_vec()).await.is_err() {
                        break; // writer has shut down
                    }
                }
            }
        }
    })
}

// ── Intercept loop ────────────────────────────────────────────────────────────

/// Read from stdin, check policy on `tools/call`, forward everything else.
async fn intercept_loop(
    engine: Arc<Mutex<PolicyEngine>>,
    mut upstream_stdin: ChildStdin,
    out_tx: mpsc::Sender<Vec<u8>>,
    verbose: bool,
) -> Result<()> {
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut line = String::new();

    loop {
        line.clear();
        match stdin.read_line(&mut line).await {
            Ok(0) => break, // client (MCP host) disconnected — clean exit
            Err(e) => {
                eprintln!("[automaguard] stdin read error: {e}");
                break;
            }
            Ok(_) => {}
        }

        // Skip blank lines (MCP does not send them, but be defensive).
        if line.trim().is_empty() {
            upstream_stdin
                .write_all(line.as_bytes())
                .await
                .map_err(Error::UpstreamWrite)?;
            continue;
        }

        let msg: Message = match serde_json::from_str(line.trim()) {
            Ok(m) => m,
            Err(e) => {
                // Not valid JSON-RPC — log and forward as-is (best-effort).
                eprintln!("[automaguard] malformed JSON-RPC (forwarding): {e}");
                upstream_stdin
                    .write_all(line.as_bytes())
                    .await
                    .map_err(Error::UpstreamWrite)?;
                continue;
            }
        };

        if verbose {
            eprintln!(
                "[automaguard] ← client: method={} id={:?}",
                msg.method.as_deref().unwrap_or("<response>"),
                msg.id
            );
        }

        // Only intercept `tools/call` requests (not notifications).
        if msg.method.as_deref() == Some("tools/call") && msg.is_request() {
            let (tool_name, arguments) = extract_tool_call(&msg);

            let event = mcp_tool_call_to_event(&tool_name, &arguments);
            let result = engine.lock().await.evaluate(&event);

            eprintln!(
                "[automaguard] tool={tool_name} verdict={:?} latency={}μs",
                result.verdict, result.eval_time_us,
            );

            if result.verdict == Verdict::Deny {
                let reason = result.reason.as_deref().unwrap_or("policy violation");

                let denial = Message::error_response(
                    msg.id,
                    POLICY_VIOLATION_CODE,
                    format!("AutomaGuard: {reason}"),
                    None,
                );
                let mut bytes = serde_json::to_vec(&denial).map_err(Error::Serialize)?;
                bytes.push(b'\n');

                out_tx.send(bytes).await.map_err(|_| Error::OutputClosed)?;
                continue; // do not forward to upstream
            }

            if result.verdict == Verdict::Audit {
                eprintln!("[automaguard] AUDIT tool={tool_name}");
            }
        }

        // Forward the original line (including any trailing `\n`) to upstream.
        upstream_stdin
            .write_all(line.as_bytes())
            .await
            .map_err(Error::UpstreamWrite)?;
    }

    // Drop the upstream write handle so the server sees EOF.
    drop(upstream_stdin);
    drop(out_tx);

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract `(tool_name, arguments)` from a `tools/call` request message.
///
/// Returns `("unknown", {})` if the expected fields are absent — the policy
/// engine will still evaluate the event, which may produce an Audit verdict.
fn extract_tool_call(msg: &Message) -> (String, JsonValue) {
    let params = msg.params.as_ref().cloned().unwrap_or(JsonValue::Null);

    let tool_name = params
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();

    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| JsonValue::Object(Default::default()));

    (tool_name, arguments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_compiler::{lower, parser};
    use serde_json::json;

    fn make_tools_call_msg(name: &str, args: JsonValue) -> Message {
        Message {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: Some("tools/call".into()),
            params: Some(json!({
                "name": name,
                "arguments": args,
            })),
            result: None,
            error: None,
        }
    }

    fn no_params_msg() -> Message {
        Message {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: Some("tools/call".into()),
            params: None,
            result: None,
            error: None,
        }
    }

    // ── extract_tool_call ─────────────────────────────────────────────────

    #[test]
    fn extract_tool_call_returns_name_and_arguments() {
        let msg = make_tools_call_msg("http_get", json!({"url": "https://example.com"}));
        let (name, args) = extract_tool_call(&msg);
        assert_eq!(name, "http_get");
        assert_eq!(args["url"], json!("https://example.com"));
    }

    #[test]
    fn extract_tool_call_no_params_returns_unknown() {
        let msg = no_params_msg();
        let (name, args) = extract_tool_call(&msg);
        assert_eq!(name, "unknown");
        assert_eq!(args, JsonValue::Object(Default::default()));
    }

    #[test]
    fn extract_tool_call_missing_name_field_returns_unknown() {
        let mut msg = make_tools_call_msg("http_get", json!({}));
        // Remove the name field from params.
        if let Some(params) = msg.params.as_mut() {
            if let Some(obj) = params.as_object_mut() {
                obj.remove("name");
            }
        }
        let (name, _) = extract_tool_call(&msg);
        assert_eq!(name, "unknown");
    }

    #[test]
    fn extract_tool_call_missing_arguments_returns_empty_object() {
        let mut msg = make_tools_call_msg("http_get", json!({}));
        // Remove the arguments field.
        if let Some(params) = msg.params.as_mut() {
            if let Some(obj) = params.as_object_mut() {
                obj.remove("arguments");
            }
        }
        let (_, args) = extract_tool_call(&msg);
        assert_eq!(args, JsonValue::Object(Default::default()));
    }

    #[test]
    fn extract_tool_call_with_empty_arguments() {
        let msg = make_tools_call_msg("list_files", json!({}));
        let (name, args) = extract_tool_call(&msg);
        assert_eq!(name, "list_files");
        assert_eq!(args, json!({}));
    }

    #[test]
    fn extract_tool_call_with_nested_arguments() {
        let msg = make_tools_call_msg(
            "query_db",
            json!({"table": "users", "filter": {"active": true}}),
        );
        let (name, args) = extract_tool_call(&msg);
        assert_eq!(name, "query_db");
        assert_eq!(args["filter"]["active"], json!(true));
    }

    // ── Policy-driven intercept decisions ─────────────────────────────────
    //
    // These tests exercise the bridge → engine → verdict pipeline that
    // `intercept_loop` runs on every `tools/call` message.  They do not
    // test async I/O but do validate the core enforcement logic.

    fn engine_from_source(source: &str) -> PolicyEngine {
        let (program, parse_diags) = parser::parse_source(source, "test.aegis");
        assert!(!parse_diags.has_errors(), "parse error");
        let (compiled, compile_diags) = lower::compile(&program);
        assert!(!compile_diags.has_errors(), "compile error");
        PolicyEngine::new(compiled.into_iter().next().unwrap())
    }

    fn simulate_intercept(engine: &mut PolicyEngine, msg: &Message) -> Verdict {
        let (tool_name, arguments) = extract_tool_call(msg);
        let event = crate::bridge::mcp_tool_call_to_event(&tool_name, &arguments);
        engine.evaluate(&event).verdict
    }

    #[test]
    fn deny_policy_blocks_matching_tool() {
        let mut engine = engine_from_source(
            "policy P { on tool_call { when event.tool_name == \"exec\"\n deny } }",
        );
        let msg = make_tools_call_msg("exec", json!({}));
        assert_eq!(simulate_intercept(&mut engine, &msg), Verdict::Deny);
    }

    #[test]
    fn deny_policy_allows_non_matching_tool() {
        let mut engine = engine_from_source(
            "policy P { on tool_call { when event.tool_name == \"exec\"\n deny } }",
        );
        let msg = make_tools_call_msg("search", json!({}));
        assert_eq!(simulate_intercept(&mut engine, &msg), Verdict::Allow);
    }

    #[test]
    fn audit_policy_does_not_block() {
        let mut engine = engine_from_source(r#"policy P { on tool_call { audit } }"#);
        let msg = make_tools_call_msg("anything", json!({}));
        assert_eq!(simulate_intercept(&mut engine, &msg), Verdict::Audit);
    }

    #[test]
    fn deny_on_argument_field_value() {
        // Policies can match on flattened argument fields (e.g., event.url).
        let mut engine = engine_from_source(
            r#"
            policy P {
                on tool_call {
                    when event.url == "file:///etc/passwd"
                    deny with "path traversal"
                }
            }
        "#,
        );
        let allowed = make_tools_call_msg("read_file", json!({"url": "https://safe.example.com"}));
        let blocked = make_tools_call_msg("read_file", json!({"url": "file:///etc/passwd"}));
        assert_eq!(simulate_intercept(&mut engine, &allowed), Verdict::Allow);
        assert_eq!(simulate_intercept(&mut engine, &blocked), Verdict::Deny);
    }

    #[test]
    fn rate_limit_triggers_deny_after_budget_exhausted() {
        let mut engine = engine_from_source(r#"policy P { rate_limit tool_call: 2 per 1m }"#);
        let msg = make_tools_call_msg("search", json!({}));
        assert_eq!(simulate_intercept(&mut engine, &msg), Verdict::Allow);
        assert_eq!(simulate_intercept(&mut engine, &msg), Verdict::Allow);
        assert_eq!(simulate_intercept(&mut engine, &msg), Verdict::Deny);
    }

    #[test]
    fn never_invariant_permanently_blocks_after_violation() {
        let mut engine = engine_from_source(
            r#"
            policy P {
                proof Safety {
                    invariant NoExec { never(event.tool_name == "exec") }
                }
            }
        "#,
        );
        let exec = make_tools_call_msg("exec", json!({}));
        let safe = make_tools_call_msg("search", json!({}));
        simulate_intercept(&mut engine, &exec); // violate
        assert_eq!(simulate_intercept(&mut engine, &safe), Verdict::Deny);
    }

    #[test]
    fn deny_response_uses_policy_violation_error_code() {
        // Build the error response the same way intercept_loop does and
        // verify it carries the documented JSON-RPC error code.
        let denial = Message::error_response(
            Some(json!(42)),
            POLICY_VIOLATION_CODE,
            "AutomaGuard: test denial".to_string(),
            None,
        );
        let serialised = serde_json::to_value(&denial).unwrap();
        assert_eq!(serialised["error"]["code"], json!(POLICY_VIOLATION_CODE));
        assert_eq!(serialised["id"], json!(42));
        assert!(serialised["error"]["message"]
            .as_str()
            .unwrap()
            .contains("AutomaGuard"));
    }

    #[test]
    fn non_tools_call_message_is_identified_correctly() {
        // intercept_loop only intercepts messages where method == "tools/call"
        // AND is_request() is true.  Verify both conditions for other types.
        let initialize = Message {
            jsonrpc: "2.0".into(),
            id: Some(json!(1)),
            method: Some("initialize".into()),
            params: None,
            result: None,
            error: None,
        };
        assert!(initialize.is_request());
        assert_ne!(initialize.method.as_deref(), Some("tools/call"));

        let notification = Message {
            jsonrpc: "2.0".into(),
            id: None, // notifications have no id
            method: Some("tools/call".into()),
            params: None,
            result: None,
            error: None,
        };
        assert!(!notification.is_request()); // must NOT be intercepted
    }
}
