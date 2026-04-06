//! Customer Data Assistant — AutomaGuard Rust SDK example.
//!
//! Demonstrates `AsyncPolicyEngine` enforcement on a simulated agent
//! tool-call loop (no LLM API key required — events are canned).
//!
//! # Usage
//!
//! ```
//! cargo run -- --safe      # aggregate query, all events allowed/audited
//! cargo run -- --unsafe    # PII exfiltration attempt, blocked
//! cargo run -- --stress    # canned scenario suite, no LLM required
//! ```

mod prompts;
mod tools;

use std::path::PathBuf;
use std::process;

use automaguard::{AsyncPolicyEngine, Verdict};

use crate::tools::AgentEvent;

// ── Policy path ───────────────────────────────────────────────────────────────

fn policy_path() -> PathBuf {
    // examples/rust/ → examples/ → customer_data_guard.aegisc
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../customer_data_guard.aegisc");
    p
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    let path = policy_path();
    if !path.exists() {
        eprintln!(
            "Policy bytecode not found at {}.\n\
             Compile it first:\n  \
             aegisc compile examples/customer_data_guard.aegis \
             -o examples/customer_data_guard.aegisc",
            path.display()
        );
        process::exit(1);
    }

    let engine = AsyncPolicyEngine::from_file(&path)?;

    if args.iter().any(|a| a == "--stress") {
        run_stress(&engine).await?;
    } else {
        let safe = args.iter().any(|a| a == "--safe");
        let mode = if safe { "safe" } else { "unsafe" };
        let prompt = if safe {
            prompts::SAFE_PROMPT
        } else {
            prompts::UNSAFE_PROMPT
        };
        let events = if safe {
            tools::safe_events()
        } else {
            tools::unsafe_events()
        };

        println!("\n=== AutomaGuard Rust Example ({mode} run) ===\n");
        println!("Prompt: {prompt}\n");

        run_agent(&engine, &events).await?;
    }

    Ok(())
}

// ── Agent simulation ──────────────────────────────────────────────────────────

/// Simulate the agent tool-call loop: evaluate each event and stop on deny.
async fn run_agent(engine: &AsyncPolicyEngine, events: &[AgentEvent]) -> anyhow::Result<()> {
    for event in events {
        let result = engine
            .evaluate(&event.event_type, event.fields.clone())
            .await?;

        match result.verdict() {
            Verdict::Allow => {
                println!("  [allow]  {}", event.description);
            }
            Verdict::Audit => {
                println!(
                    "  [audit]  {} — {}",
                    event.description,
                    result.reason().unwrap_or("no reason")
                );
            }
            Verdict::Deny => {
                eprintln!(
                    "\nBLOCKED by AutomaGuard policy:\n  \
                     Event:  {}\n  \
                     Reason: {}",
                    event.description,
                    result.reason().unwrap_or("no reason given"),
                );
                for v in result.violations() {
                    eprintln!(
                        "  Invariant violation: {}/{}: {}",
                        v.proof_name, v.invariant_name, v.message
                    );
                }
                for cv in result.constraint_violations() {
                    eprintln!(
                        "  Constraint violation: {:?} on '{}' — {}/{} in {}ms window",
                        cv.kind, cv.target, cv.current, cv.limit, cv.window_ms
                    );
                }
                process::exit(1);
            }
            Verdict::Redact => {
                println!("  [redact] {}", event.description);
            }
        }
    }

    println!(
        "\n[engine] {} events evaluated on policy '{}'",
        engine.event_count(),
        engine.policy_name(),
    );

    Ok(())
}

// ── Stress test ───────────────────────────────────────────────────────────────

async fn run_stress(engine: &AsyncPolicyEngine) -> anyhow::Result<()> {
    println!("\n=== AutomaGuard Rust Stress Test ===\n");

    let mut passed: u32 = 0;
    let mut failed: u32 = 0;

    // ── 1. DDL denial ─────────────────────────────────────────────────────────
    println!("[1] DDL denial");
    engine.event("tool_call").field("tool_name", "drop_table").evaluate().await
        .map(|r| {
            if r.verdict() == Verdict::Deny {
                println!("  \u{2713} drop_table \u{2192} deny"); passed += 1;
            } else {
                eprintln!("  \u{2717} drop_table: expected deny, got {:?}", r.verdict()); failed += 1;
            }
        })?;
    engine.event("tool_call").field("tool_name", "query_tickets").evaluate().await
        .map(|r| {
            if r.verdict() == Verdict::Allow {
                println!("  \u{2713} query_tickets \u{2192} allow"); passed += 1;
            } else {
                eprintln!("  \u{2717} query_tickets: expected allow, got {:?}", r.verdict()); failed += 1;
            }
        })?;

    // ── 2. PII audit ──────────────────────────────────────────────────────────
    println!("\n[2] PII data access");
    // Need a fresh engine for each scenario to reset state machines
    let engine2 = AsyncPolicyEngine::from_file(&policy_path())?;
    engine2.event("data_access")
        .field("classification", "PII")
        .field("record_id", "10042")
        .evaluate().await
        .map(|r| {
            if r.verdict() == Verdict::Audit {
                println!("  \u{2713} data_access PII \u{2192} audit"); passed += 1;
            } else {
                eprintln!("  \u{2717} data_access PII: expected audit, got {:?}", r.verdict()); failed += 1;
            }
        })?;

    // ── 3. PII exfiltration ───────────────────────────────────────────────────
    println!("\n[3] PII exfiltration (temporal invariant)");
    let engine3 = AsyncPolicyEngine::from_file(&policy_path())?;
    engine3.event("data_access")
        .field("classification", "PII")
        .field("record_id", "10042")
        .evaluate().await?; // audit step — result not checked
    engine3.event("external_request")
        .field("domain", "external-firm.com")
        .field("method", "POST")
        .evaluate().await
        .map(|r| {
            if r.verdict() == Verdict::Deny {
                println!("  \u{2713} external_request unapproved \u{2192} deny"); passed += 1;
            } else {
                eprintln!("  \u{2717} external_request: expected deny, got {:?}", r.verdict()); failed += 1;
            }
        })?;

    // ── 4. Approved external request ─────────────────────────────────────────
    println!("\n[4] Approved external request");
    let engine4 = AsyncPolicyEngine::from_file(&policy_path())?;
    engine4.event("external_request")
        .field("domain", "reports.internal.corp")
        .field("method", "POST")
        .evaluate().await
        .map(|r| {
            if r.verdict() == Verdict::Allow {
                println!("  \u{2713} reports.internal.corp \u{2192} allow"); passed += 1;
            } else {
                eprintln!("  \u{2717} external_request approved: expected allow, got {:?}", r.verdict()); failed += 1;
            }
        })?;

    // ── 5. Rate limiting ──────────────────────────────────────────────────────
    println!("\n[5] Rate limiting (20 allowed, 21st denied)");
    let engine5 = AsyncPolicyEngine::from_file(&policy_path())?;
    let mut all_ok = true;
    for i in 1u32..=20 {
        let r = engine5.event("data_access")
            .field("classification", "aggregate")
            .field("record_id", i.to_string().as_str())
            .evaluate().await?;
        if r.verdict() != Verdict::Allow {
            eprintln!("  \u{2717} event {i}: expected allow, got {:?}", r.verdict());
            failed += 1;
            all_ok = false;
        }
    }
    if all_ok {
        println!("  \u{2713} events 1\u{2013}20 \u{2192} allow");
        passed += 20;
    }
    let r21 = engine5.event("data_access")
        .field("classification", "aggregate")
        .field("record_id", "21")
        .evaluate().await?;
    if r21.verdict() == Verdict::Deny {
        println!("  \u{2713} event 21 \u{2192} deny (rate limit)"); passed += 1;
    } else {
        eprintln!("  \u{2717} event 21: expected deny, got {:?}", r21.verdict()); failed += 1;
    }

    // ── 6. Delete without approval ────────────────────────────────────────────
    println!("\n[6] Delete without prior human approval");
    let engine6 = AsyncPolicyEngine::from_file(&policy_path())?;
    engine6.event("tool_call")
        .field("tool_name", "delete_record")
        .field("account_id", "10042")
        .evaluate().await
        .map(|r| {
            if r.verdict() == Verdict::Deny {
                println!("  \u{2713} delete_record without approval \u{2192} deny"); passed += 1;
            } else {
                eprintln!("  \u{2717} delete_record: expected deny, got {:?}", r.verdict()); failed += 1;
            }
        })?;

    // ── Summary ───────────────────────────────────────────────────────────────
    println!("\n{}", "─".repeat(40));
    println!("Stress test: {passed} passed, {failed} failed");
    if failed > 0 {
        process::exit(1);
    }

    Ok(())
}
