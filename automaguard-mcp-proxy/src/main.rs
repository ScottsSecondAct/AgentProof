//! AutomaGuard MCP proxy — CLI entry point.
//!
//! Runs as a sidecar between an MCP host (e.g., Claude Desktop, an agent
//! framework) and an upstream MCP server.  Every `tools/call` request is
//! evaluated against a compiled Aegis policy before being forwarded.
//!
//! # Usage
//!
//! ```text
//! automaguard-mcp-proxy --policy guard.aegisc -- npx -y @modelcontextprotocol/server-filesystem /workspace
//! ```
//!
//! The proxy speaks the MCP stdio transport on its own stdin/stdout, and
//! speaks to the upstream server via a spawned subprocess.  The client
//! configures `automaguard-mcp-proxy` exactly where it would configure the
//! upstream server — no client-side code changes required.
//!
//! # Verdict behaviour
//!
//! | Verdict | Action |
//! |---------|--------|
//! | Allow   | Forward to upstream, relay response |
//! | Deny    | Return JSON-RPC error (-32001); upstream never sees the call |
//! | Audit   | Forward to upstream, log to stderr |
//! | Redact  | Forward to upstream (field redaction planned for v2) |
//!
//! All non-`tools/call` messages (initialize, notifications, etc.) are
//! forwarded transparently.

use std::path::PathBuf;
use std::process::Stdio;

use clap::Parser;
use tokio::process::Command;

mod bridge;
mod error;
mod jsonrpc;
mod proxy;

use error::{Error, Result};

/// AutomaGuard MCP proxy — policy enforcement sidecar for MCP agents.
#[derive(Parser)]
#[command(name = "automaguard-mcp-proxy", version)]
#[command(
    long_about = "Sits between an MCP host and an MCP server.  Intercepts every \
    tools/call request and evaluates it against a compiled Aegis policy before \
    forwarding.  Zero client-side code changes required — configure the proxy \
    in place of the upstream server command."
)]
struct Cli {
    /// Path to the compiled Aegis policy file (.aegisc).
    #[arg(long, short, value_name = "FILE")]
    policy: PathBuf,

    /// Emit per-message trace logs to stderr.
    #[arg(long, short)]
    verbose: bool,

    /// Upstream MCP server command and its arguments.
    ///
    /// Separate with `--` to prevent argument ambiguity:
    ///   automaguard-mcp-proxy --policy guard.aegisc -- npx server-name /path
    #[arg(last = true, required = true, value_name = "CMD [ARGS...]")]
    upstream: Vec<String>,
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("[automaguard] error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();

    // ── Load policy ───────────────────────────────────────────────────────────
    let policy_bytes = std::fs::read(&cli.policy).map_err(Error::PolicyRead)?;
    let policy = aegis_compiler::bytecode::from_bytecode(&policy_bytes)
        .map_err(Error::PolicyLoad)?;

    eprintln!(
        "[automaguard] policy loaded: \"{}\" ({} rules, {} state machines)",
        policy.name,
        policy.rules.len(),
        policy.state_machines.len(),
    );

    // ── Spawn upstream MCP server ─────────────────────────────────────────────
    if cli.upstream.is_empty() {
        // clap's `required = true` prevents this, but be defensive.
        eprintln!("[automaguard] no upstream command specified");
        std::process::exit(1);
    }

    let upstream_cmd = &cli.upstream[0];
    let upstream_args = &cli.upstream[1..];

    eprintln!(
        "[automaguard] spawning upstream: {} {}",
        upstream_cmd,
        upstream_args.join(" "),
    );

    let mut child = Command::new(upstream_cmd)
        .args(upstream_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // upstream stderr → our stderr (visible to user)
        .spawn()
        .map_err(Error::Spawn)?;

    let upstream_stdin = child.stdin.take().expect("child stdin is piped");
    let upstream_stdout = child.stdout.take().expect("child stdout is piped");

    // ── Run proxy ─────────────────────────────────────────────────────────────
    proxy::run(policy, child, upstream_stdin, upstream_stdout, cli.verbose).await
}
