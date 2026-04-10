//! `aegisc` — the Aegis policy compiler CLI.
//!
//! # Usage
//!
//! ```sh
//! # Compile a policy to bytecode
//! aegisc compile policy.aegis -o policy.aegisc
//!
//! # Type-check only (no output file)
//! aegisc check policy.aegis
//! aegisc check -                      # read from stdin
//! aegisc check --json policy.aegis    # machine-readable JSON output
//!
//! # Dump compiled IR as JSON (for debugging)
//! aegisc dump policy.aegis
//!
//! # Inspect a compiled .aegisc file header
//! aegisc inspect policy.aegisc
//!
//! # Simulate an event against a compiled policy
//! aegisc eval guard.aegisc tool_call tool_name=exec
//! aegisc eval --json guard.aegisc data_access classification=PII
//! ```

use std::path::{Path, PathBuf};

/// CLI entry point. In a real build, this would be `fn main()` in
/// `src/bin/aegisc.rs`. Here it's a library function for testability.
pub fn cli_main(args: &[String]) -> i32 {
    if args.len() < 2 {
        print_usage();
        return 1;
    }

    match args[1].as_str() {
        "compile" => cmd_compile(&args[2..]),
        "check" => cmd_check(&args[2..]),
        "dump" => cmd_dump(&args[2..]),
        "inspect" => cmd_inspect(&args[2..]),
        "version" | "--version" | "-V" => {
            println!(
                "aegisc {} (Aegis policy compiler)",
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
    check   [--json] <file.aegis|->`                      Type-check only
    dump    <file.aegis>                                   Dump compiled IR as JSON
    inspect <file.aegisc>                                  Inspect bytecode header
    eval    [--json] <file.aegisc> <event-type> [k=v...]  Simulate an event
    version                                                Show version
    help                                                   Show this message

OPTIONS (check, eval):
    --json    Output machine-readable JSON instead of human text

EXAMPLES:
    aegisc compile policies/guard.aegis -o guard.aegisc
    aegisc check policies/guard.aegis
    aegisc check --json policies/guard.aegis
    aegisc check -                               # read policy from stdin
    aegisc dump policies/guard.aegis | jq '.state_machines'
    aegisc inspect guard.aegisc
    aegisc eval guard.aegisc tool_call tool_name=exec
    aegisc eval --json guard.aegisc data_access classification=PII"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Commands
// ═══════════════════════════════════════════════════════════════════════

pub fn cmd_compile(args: &[String]) -> i32 {
    let (input, output) = match parse_compile_args(args) {
        Some(v) => v,
        None => {
            eprintln!("usage: aegisc compile <file.aegis> [-o output.aegisc]");
            return 1;
        }
    };

    // Read source
    let source = match std::fs::read_to_string(&input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read `{}`: {e}", input.display());
            return 1;
        }
    };

    let filename = input.to_string_lossy();

    eprintln!("  Compiling {filename}...");

    let result = run_pipeline(&source, &filename);

    match result {
        Ok(policies) => {
            // If the source had no policy declarations, write a placeholder empty policy
            // so the output file is always created (consistent with `aegisc compile` semantics).
            let effective_policies: Vec<crate::ir::CompiledPolicy> = if policies.is_empty() {
                vec![empty_policy()]
            } else {
                policies
            };

            for policy in &effective_policies {
                let out_path = if effective_policies.len() == 1 {
                    output.clone()
                } else {
                    output.with_file_name(format!(
                        "{}_{}.aegisc",
                        output.file_stem().unwrap_or_default().to_string_lossy(),
                        policy.name
                    ))
                };

                match crate::bytecode::write_file(&out_path, policy) {
                    Ok(bytes) => {
                        eprintln!(
                            "  Wrote {} ({} bytes, {} rules, {} state machines)",
                            out_path.display(),
                            bytes,
                            policy.rules.len(),
                            policy.state_machines.len()
                        );
                    }
                    Err(e) => {
                        eprintln!("error: cannot write `{}`: {e}", out_path.display());
                        return 1;
                    }
                }
            }
            eprintln!("  Done.");
            0
        }
        Err(error_output) => {
            eprint!("{error_output}");
            1
        }
    }
}

pub fn cmd_check(args: &[String]) -> i32 {
    // Parse --json flag
    let (json_out, rest) = if args.first().map(|s| s.as_str()) == Some("--json") {
        (true, &args[1..])
    } else {
        (false, &args[..])
    };

    if rest.is_empty() {
        eprintln!("usage: aegisc check [--json] <file.aegis | ->");
        return 1;
    }

    let (source, filename) = if rest[0] == "-" {
        // Read from stdin.
        use std::io::Read;
        let mut s = String::new();
        if let Err(e) = std::io::stdin().read_to_string(&mut s) {
            eprintln!("error: cannot read stdin: {e}");
            return 1;
        }
        (s, "<stdin>".to_string())
    } else {
        let input = Path::new(&rest[0]);
        match std::fs::read_to_string(input) {
            Ok(s) => (s, input.to_string_lossy().into_owned()),
            Err(e) => {
                eprintln!("error: cannot read `{}`: {e}", input.display());
                return 1;
            }
        }
    };

    if !json_out {
        eprintln!("  Checking {filename}...");
    }

    match run_pipeline_with_diags(&source, &filename) {
        Ok(policies) => {
            if json_out {
                let summary: Vec<serde_json::Value> = policies
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "name": p.name.as_str(),
                            "rules": p.rules.len(),
                            "invariants": p.state_machines.len(),
                            "constraints": p.constraints.len(),
                        })
                    })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "file": filename,
                        "policies": summary,
                        "errors": [],
                        "warnings": [],
                    }))
                    .unwrap()
                );
            } else {
                let total_rules: usize = policies.iter().map(|p| p.rules.len()).sum();
                let total_sms: usize = policies.iter().map(|p| p.state_machines.len()).sum();
                eprintln!(
                    "  OK: {} policies, {} rules, {} invariants verified",
                    policies.len(),
                    total_rules,
                    total_sms
                );
            }
            0
        }
        Err((error_output, diags, _source)) => {
            if json_out {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": false,
                        "file": filename,
                        "policies": [],
                        "errors": diags.iter().map(|d| {
                            serde_json::json!({
                                "code": format!("{:?}", d.code),
                                "message": d.message,
                            })
                        }).collect::<Vec<_>>(),
                        "warnings": [],
                    }))
                    .unwrap()
                );
            } else {
                eprint!("{error_output}");
            }
            1
        }
    }
}

pub fn cmd_dump(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: aegisc dump <file.aegis>");
        return 1;
    }

    let input = Path::new(&args[0]);
    let source = match std::fs::read_to_string(input) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: cannot read `{}`: {e}", input.display());
            return 1;
        }
    };

    let filename = input.to_string_lossy();

    match run_pipeline(&source, &filename) {
        Ok(policies) => {
            for policy in &policies {
                match crate::bytecode::to_json(policy) {
                    Ok(json) => println!("{json}"),
                    Err(e) => {
                        eprintln!("error: JSON serialization failed: {e}");
                        return 1;
                    }
                }
            }
            0
        }
        Err(error_output) => {
            eprint!("{error_output}");
            1
        }
    }
}

pub fn cmd_inspect(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: aegisc inspect <file.aegisc>");
        return 1;
    }

    let path = Path::new(&args[0]);

    match crate::bytecode::inspect_header(path) {
        Ok(info) => {
            println!("File: {}", path.display());
            print!("{info}");

            // Try to read the full policy for summary
            match crate::bytecode::read_file(path) {
                Ok(policy) => {
                    println!("  Policy:  {}", policy.name);
                    println!("  Severity: {:?}", policy.severity);
                    println!("  Scopes:  {}", policy.scopes.join(", "));
                    println!("  Rules:   {}", policy.rules.len());
                    println!("  Constraints: {}", policy.constraints.len());
                    println!("  State machines: {}", policy.state_machines.len());
                    for sm in &policy.state_machines {
                        println!(
                            "    - {} ({:?}, {} states, {} transitions)",
                            sm.invariant_name,
                            sm.kind,
                            sm.states.len(),
                            sm.transitions.len()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("  (could not read payload: {e})");
                }
            }
            0
        }
        Err(e) => {
            eprintln!("error: cannot inspect `{}`: {e}", path.display());
            1
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Argument parsing
// ═══════════════════════════════════════════════════════════════════════

fn parse_compile_args(args: &[String]) -> Option<(PathBuf, PathBuf)> {
    if args.is_empty() {
        return None;
    }

    let input = PathBuf::from(&args[0]);

    let output = if args.len() >= 3 && args[1] == "-o" {
        PathBuf::from(&args[2])
    } else {
        input.with_extension("aegisc")
    };

    Some((input, output))
}

// ═══════════════════════════════════════════════════════════════════════
//  Real pipeline — parse → type-check → lower
// ═══════════════════════════════════════════════════════════════════════

/// Run the full compiler pipeline, returning compiled policies or a formatted
/// error string suitable for terminal output.
pub fn run_pipeline(source: &str, filename: &str) -> Result<Vec<crate::ir::CompiledPolicy>, String> {
    run_pipeline_with_diags(source, filename).map_err(|(msg, _, _)| msg)
}

/// Run the full compiler pipeline, returning compiled policies on success, or
/// `(formatted_error, diagnostics, source_copy)` on failure (for JSON output).
pub fn run_pipeline_with_diags(
    source: &str,
    filename: &str,
) -> Result<
    Vec<crate::ir::CompiledPolicy>,
    (String, Vec<crate::diagnostics::Diagnostic>, String),
> {
    use crate::checker::TypeChecker;
    // 1. Parse source into AST
    let (program, parse_diag) = crate::parser::parse_source(source, filename);

    if parse_diag.has_errors() {
        let count = parse_diag.error_count();
        let rendered = format!(
            "{}\nerror: aborting due to {} parse error(s)\n",
            parse_diag.render(source, filename),
            count
        );
        let diags = parse_diag.into_diagnostics();
        return Err((rendered, diags, source.to_string()));
    }

    if parse_diag.warning_count() > 0 {
        eprint!("{}", parse_diag.render(source, filename));
    }

    // 2. Type-check
    let mut checker = TypeChecker::new();
    checker.check_program(&program);

    let check_diag = checker.into_diagnostics();
    if check_diag.has_errors() {
        let count = check_diag.error_count();
        let rendered = format!(
            "{}\nerror: aborting due to {} error(s)\n",
            check_diag.render(source, filename),
            count
        );
        let diags = check_diag.into_diagnostics();
        return Err((rendered, diags, source.to_string()));
    }

    if check_diag.warning_count() > 0 {
        eprint!("{}", check_diag.render(source, filename));
    }

    // 3. Lower to IR
    let (policies, lower_diag) = crate::lower::compile(&program);
    if lower_diag.has_errors() {
        let count = lower_diag.error_count();
        let rendered = format!(
            "{}\nerror: lowering failed with {} error(s)\n",
            lower_diag.render(source, filename),
            count
        );
        let diags = lower_diag.into_diagnostics();
        return Err((rendered, diags, source.to_string()));
    }

    Ok(policies)
}

/// Return a minimal empty [`CompiledPolicy`] used as a placeholder when the
/// source file contains no policy declarations (e.g., a comment-only stub).
fn empty_policy() -> crate::ir::CompiledPolicy {
    use crate::ast::SeverityLevel;
    use crate::ir::{CompiledPolicy, PolicyMetadata};
    use smol_str::SmolStr;

    CompiledPolicy {
        name: SmolStr::new("__empty__"),
        severity: SeverityLevel::Info,
        scopes: vec![],
        rules: vec![],
        constraints: vec![],
        state_machines: vec![],
        metadata: PolicyMetadata {
            annotations: vec![],
            source_hash: 0,
            compiler_version: SmolStr::new(env!("CARGO_PKG_VERSION")),
        },
    }
}
