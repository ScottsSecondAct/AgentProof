//! `aegisc` — the Aegis policy compiler and evaluator (AutomaGuard).
//!
//! This binary lives in `automaguard-rs` (which depends on both
//! `aegis-compiler` and `aegis-runtime`) so that the `eval` command can
//! load a compiled `.aegisc` policy and simulate events against it.
//!
//! All compiler subcommands (`compile`, `check`, `dump`, `inspect`) delegate
//! to `aegis_compiler::cli::*`.  The `eval` command is implemented here.

use std::collections::HashMap;
use std::path::Path;

use smol_str::SmolStr;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = cli_main(&args);
    std::process::exit(code);
}

fn cli_main(args: &[String]) -> i32 {
    if args.len() < 2 {
        print_usage();
        return 1;
    }

    match args[1].as_str() {
        "compile" => aegis_compiler::cli::cmd_compile(&args[2..]),
        "check" => aegis_compiler::cli::cmd_check(&args[2..]),
        "dump" => aegis_compiler::cli::cmd_dump(&args[2..]),
        "inspect" => aegis_compiler::cli::cmd_inspect(&args[2..]),
        "eval" => cmd_eval(&args[2..]),
        "version" | "--version" | "-V" => {
            println!(
                "aegisc {} (Aegis policy compiler + evaluator)",
                env!("CARGO_PKG_VERSION")
            );
            0
        }
        "help" | "--help" | "-h" => {
            print_usage();
            0
        }
        other => {
            eprintln!("error: unknown command `{other}`");
            eprintln!("Run `aegisc help` for usage.");
            1
        }
    }
}

fn print_usage() {
    eprintln!(
        "\
aegisc — the Aegis policy compiler (AutomaGuard)

USAGE:
    aegisc <command> [options] <file>

COMMANDS:
    compile <file.aegis> [-o output.aegisc]              Compile to bytecode
    check   [--json] <file.aegis | ->                    Type-check only
    dump    <file.aegis>                                  Dump compiled IR as JSON
    inspect <file.aegisc>                                 Inspect bytecode header
    eval    [--json] <file.aegisc> <event-type> [k=v ...] Simulate an event
    version                                               Show version
    help                                                  Show this message

OPTIONS (check, eval):
    --json    Output machine-readable JSON instead of human text

EXAMPLES:
    aegisc compile policies/guard.aegis -o guard.aegisc
    aegisc check policies/guard.aegis
    aegisc check --json policies/guard.aegis
    aegisc check -                                   # read from stdin
    aegisc dump policies/guard.aegis | jq '.state_machines'
    aegisc inspect guard.aegisc
    aegisc eval guard.aegisc tool_call tool_name=exec
    aegisc eval --json guard.aegisc data_access classification=PII record_id=42"
    );
}

// ── eval command ──────────────────────────────────────────────────────────────

fn cmd_eval(args: &[String]) -> i32 {
    // Parse --json flag
    let (json_out, rest) = if args.first().map(|s| s.as_str()) == Some("--json") {
        (true, &args[1..])
    } else {
        (false, &args[..])
    };

    if rest.len() < 2 {
        eprintln!("usage: aegisc eval [--json] <policy.aegisc> <event-type> [key=value ...]");
        eprintln!("example: aegisc eval guard.aegisc tool_call tool_name=exec");
        return 1;
    }

    let policy_path = Path::new(&rest[0]);
    let event_type = &rest[1];
    let field_args = &rest[2..];

    // Load compiled policy from the .aegisc bytecode file.
    let compiled = match aegis_compiler::bytecode::read_file(policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot load `{}`: {e}", policy_path.display());
            return 1;
        }
    };

    let policy_name = compiled.name.clone();

    // Parse key=value field arguments, auto-coercing types.
    let mut fields: HashMap<SmolStr, aegis_runtime::event::Value> = HashMap::new();
    for arg in field_args {
        if let Some((key, val)) = arg.split_once('=') {
            let value = if let Ok(i) = val.parse::<i64>() {
                aegis_runtime::event::Value::Int(i)
            } else if let Ok(f) = val.parse::<f64>() {
                aegis_runtime::event::Value::Float(f)
            } else if val == "true" {
                aegis_runtime::event::Value::Bool(true)
            } else if val == "false" {
                aegis_runtime::event::Value::Bool(false)
            } else {
                aegis_runtime::event::Value::String(SmolStr::new(val))
            };
            fields.insert(SmolStr::new(key), value);
        } else {
            eprintln!("warning: ignoring `{arg}` (expected key=value format)");
        }
    }

    let event =
        aegis_runtime::event::Event::new(event_type.as_str()).with_fields(fields);

    let mut engine = aegis_runtime::engine::PolicyEngine::new(compiled);
    let result = engine.evaluate(&event);

    let verdict_str = format!("{:?}", result.verdict).to_lowercase();

    if json_out {
        let violations: Vec<serde_json::Value> = result
            .violations
            .iter()
            .map(|v| {
                serde_json::json!({
                    "proof": v.proof_name.as_str(),
                    "invariant": v.invariant_name.as_str(),
                    "message": v.message,
                })
            })
            .collect();
        let constraint_violations: Vec<serde_json::Value> = result
            .constraint_violations
            .iter()
            .map(|v| {
                serde_json::json!({
                    "target": v.target.as_str(),
                    "limit": v.limit,
                    "current": v.current,
                    "window_ms": v.window_ms,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "verdict": verdict_str,
                "reason": result.reason,
                "triggered_rules": result.triggered_rules,
                "violations": violations,
                "constraint_violations": constraint_violations,
                "eval_time_us": result.eval_time_us,
            }))
            .unwrap()
        );
    } else {
        eprintln!("  Policy:  {policy_name}");
        eprintln!("  Event:   {event_type}");
        println!("Verdict: {verdict_str}");
        if let Some(ref reason) = result.reason {
            println!("Reason:  {reason}");
        }
        if !result.triggered_rules.is_empty() {
            println!("Rules:   {:?}", result.triggered_rules);
        }
        for v in &result.violations {
            println!(
                "Violated: {}/{} — {}",
                v.proof_name, v.invariant_name, v.message
            );
        }
        for cv in &result.constraint_violations {
            println!(
                "Rate limit exceeded: {} ({}/{} per {}ms)",
                cv.target, cv.current, cv.limit, cv.window_ms
            );
        }
        println!("Latency: {}μs", result.eval_time_us);
    }

    // Exit code: deny → 1, allow/audit/redact → 0.
    // Useful for scripting: `aegisc eval guard.aegisc tool_call tool_name=exec || echo "blocked"`
    if result.verdict == aegis_compiler::ast::Verdict::Deny {
        1
    } else {
        0
    }
}
