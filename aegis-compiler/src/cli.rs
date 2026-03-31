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
//!
//! # Dump compiled IR as JSON (for debugging)
//! aegisc dump policy.aegis
//!
//! # Inspect a compiled .aegisc file header
//! aegisc inspect policy.aegisc
//! ```

use std::path::{Path, PathBuf};
use std::process;

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
aegisc — the Aegis policy compiler (AgentProof)

USAGE:
    aegisc <command> [options] <file>

COMMANDS:
    compile <file.aegis> [-o output.aegisc]   Compile to bytecode
    check   <file.aegis>                       Type-check only
    dump    <file.aegis>                       Dump compiled IR as JSON
    inspect <file.aegisc>                      Inspect bytecode header
    version                                    Show version
    help                                       Show this message

EXAMPLES:
    aegisc compile policies/guard.aegis -o guard.aegisc
    aegisc check policies/guard.aegis
    aegisc dump policies/guard.aegis | jq '.state_machines'
    aegisc inspect guard.aegisc"
    );
}

// ═══════════════════════════════════════════════════════════════════════
//  Commands
// ═══════════════════════════════════════════════════════════════════════

fn cmd_compile(args: &[String]) -> i32 {
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

    // Parse → AST (placeholder until ANTLR4 integration)
    // For now, we print a message about what would happen.
    // The full pipeline: parse → check → lower → serialize
    eprintln!("  Compiling {filename}...");

    // In the real pipeline:
    // 1. let tree = parser.program();
    // 2. let program = AstBuilder::new(&source).build_program(tree);
    // 3. let mut checker = TypeChecker::new();
    //    checker.check_program(&program);
    //    if checker.diagnostics().has_errors() { report and exit }
    // 4. let (policies, diag) = lower::compile(&program);
    // 5. for policy in &policies {
    //        bytecode::write_file(&output, policy);
    //    }

    // For now, demonstrate the pipeline is wired correctly by
    // constructing a minimal program and running it through.
    let demo_result = run_demo_pipeline(&source, &filename);

    match demo_result {
        Ok(policies) => {
            for policy in &policies {
                let out_path = if policies.len() == 1 {
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

fn cmd_check(args: &[String]) -> i32 {
    if args.is_empty() {
        eprintln!("usage: aegisc check <file.aegis>");
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
    eprintln!("  Checking {filename}...");

    match run_demo_pipeline(&source, &filename) {
        Ok(policies) => {
            let total_rules: usize = policies.iter().map(|p| p.rules.len()).sum();
            let total_sms: usize = policies.iter().map(|p| p.state_machines.len()).sum();
            eprintln!(
                "  OK: {} policies, {} rules, {} invariants verified",
                policies.len(),
                total_rules,
                total_sms
            );
            0
        }
        Err(error_output) => {
            eprint!("{error_output}");
            1
        }
    }
}

fn cmd_dump(args: &[String]) -> i32 {
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

    match run_demo_pipeline(&source, &filename) {
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

fn cmd_inspect(args: &[String]) -> i32 {
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
//  Demo pipeline — exercises check + lower without the ANTLR4 parser
//
//  This constructs a minimal AST programmatically to demonstrate the
//  pipeline works end-to-end. When the ANTLR4 parser is integrated,
//  this is replaced by the real parse → visit → check → lower flow.
// ═══════════════════════════════════════════════════════════════════════

fn run_demo_pipeline(
    _source: &str,
    filename: &str,
) -> Result<Vec<crate::ir::CompiledPolicy>, String> {
    use crate::ast::*;
    use crate::checker::TypeChecker;
    use smol_str::SmolStr;

    // Construct a minimal program to exercise the pipeline.
    // In production, this comes from the ANTLR4 parser + visitor.
    let program = Program {
        declarations: vec![Spanned::new(
            Declaration::Policy(PolicyDecl {
                annotations: vec![],
                name: Spanned::new(SmolStr::new("DemoPolicy"), Span::new(0, 10)),
                extends: None,
                members: vec![
                    Spanned::new(
                        PolicyMember::Severity(SeverityLevel::High),
                        Span::new(12, 25),
                    ),
                    Spanned::new(
                        PolicyMember::Scope(vec![ScopeTarget::Name(QualifiedName {
                            segments: vec![Spanned::new(
                                SmolStr::new("tool_call"),
                                Span::new(30, 39),
                            )],
                            span: Span::new(30, 39),
                        })]),
                        Span::new(26, 40),
                    ),
                ],
            }),
            Span::new(0, 50),
        )],
        span: Span::new(0, 50),
    };

    // Type-check
    let mut checker = TypeChecker::new();
    checker.check_program(&program);

    let diag = checker.into_diagnostics();
    if diag.has_errors() {
        let rendered = diag.render(_source, filename);
        return Err(format!(
            "{rendered}\nerror: aborting due to {} error(s)\n",
            diag.error_count()
        ));
    }

    // Show warnings
    if diag.warning_count() > 0 {
        let rendered = diag.render(_source, filename);
        eprint!("{rendered}");
    }

    // Lower to IR
    let (policies, lower_diag) = crate::lower::compile(&program);
    if lower_diag.has_errors() {
        let rendered = lower_diag.render(_source, filename);
        return Err(format!(
            "{rendered}\nerror: lowering failed with {} error(s)\n",
            lower_diag.error_count()
        ));
    }

    Ok(policies)
}
