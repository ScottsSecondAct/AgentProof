//! CLI subcommand tests.
//!
//! Exercises `cli_main` with the full range of arguments: missing args,
//! unknown commands, valid/invalid file paths, and round-trip
//! compile → inspect flows.

use aegis_compiler::cli::cli_main;
use std::path::PathBuf;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Convert `&[&str]` to the `Vec<String>` that `cli_main` expects.
fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

/// Return a temp path with a test-unique name so parallel tests don't collide.
fn tmp(label: &str, ext: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("aegisc_test__{}__{}", label, ext));
    p
}

/// Write a trivial `.aegis` stub to disk (content is ignored by the demo
/// pipeline, but the file must exist for `fs::read_to_string` to succeed).
fn write_stub_aegis(label: &str) -> PathBuf {
    let path = tmp(label, "aegis");
    std::fs::write(&path, "// stub\n").expect("write stub .aegis");
    path
}

/// Write a realistic multi-rule `.aegis` policy to disk.
///
/// Write a realistic multi-rule `.aegis` policy to disk.
///
/// Uses `event.field` expressions in `when` clauses to exercise the full
/// type-checker pipeline, including the multi-segment identifier resolution
/// that handles `qualified_name`-based field access.
fn write_rich_aegis(label: &str) -> PathBuf {
    let path = tmp(label, "aegis");
    let content = r#"
policy DataGuard {
    severity high
    scope tool_call, data_access

    on tool_call {
        when event.tool_name == "http_get"
        deny with "External HTTP calls blocked"
    }

    on data_access {
        when event.resource_type == "pii"
        audit with "PII access logged"
    }

    proof NoDataLeaks {
        invariant InternalOnly {
            always(true)
        }
        invariant NoExfil {
            never(false)
        }
    }

    rate_limit calls: 100 per 1m
}
"#;
    std::fs::write(&path, content).expect("write rich .aegis");
    path
}

// ── No-args / usage ───────────────────────────────────────────────────────────

#[test]
fn no_args_returns_1() {
    assert_eq!(cli_main(&[]), 1);
}

#[test]
fn only_program_name_returns_1() {
    assert_eq!(cli_main(&args(&["aegisc"])), 1);
}

// ── Unknown command ───────────────────────────────────────────────────────────

#[test]
fn unknown_command_returns_1() {
    assert_eq!(cli_main(&args(&["aegisc", "frobnicate"])), 1);
}

#[test]
fn typo_in_command_returns_1() {
    assert_eq!(cli_main(&args(&["aegisc", "compil"])), 1);
}

// ── version / help ────────────────────────────────────────────────────────────

#[test]
fn version_returns_0() {
    assert_eq!(cli_main(&args(&["aegisc", "version"])), 0);
}

#[test]
fn version_flag_returns_0() {
    assert_eq!(cli_main(&args(&["aegisc", "--version"])), 0);
}

#[test]
fn version_short_flag_returns_0() {
    assert_eq!(cli_main(&args(&["aegisc", "-V"])), 0);
}

#[test]
fn help_returns_0() {
    assert_eq!(cli_main(&args(&["aegisc", "help"])), 0);
}

#[test]
fn help_flag_returns_0() {
    assert_eq!(cli_main(&args(&["aegisc", "--help"])), 0);
}

#[test]
fn help_short_flag_returns_0() {
    assert_eq!(cli_main(&args(&["aegisc", "-h"])), 0);
}

// ── compile ───────────────────────────────────────────────────────────────────

#[test]
fn compile_no_args_returns_1() {
    assert_eq!(cli_main(&args(&["aegisc", "compile"])), 1);
}

#[test]
fn compile_missing_file_returns_1() {
    assert_eq!(
        cli_main(&args(&[
            "aegisc",
            "compile",
            "/nonexistent/path/policy.aegis"
        ])),
        1
    );
}

#[test]
fn compile_valid_file_returns_0() {
    let src = write_stub_aegis("compile_valid");
    let out = tmp("compile_valid", "aegisc");
    let code = cli_main(&args(&[
        "aegisc",
        "compile",
        src.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]));
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&out);
    assert_eq!(code, 0);
}

#[test]
fn compile_writes_aegisc_file() {
    let src = write_stub_aegis("compile_writes");
    let out = tmp("compile_writes", "aegisc");
    cli_main(&args(&[
        "aegisc",
        "compile",
        src.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]));
    let exists = out.exists();
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&out);
    assert!(exists, ".aegisc output file should be created");
}

#[test]
fn compile_default_output_name_is_aegisc() {
    // Without `-o`, the output should be the input path with `.aegisc` extension.
    let src = write_stub_aegis("compile_default_out");
    let expected_out = src.with_extension("aegisc");
    cli_main(&args(&["aegisc", "compile", src.to_str().unwrap()]));
    let exists = expected_out.exists();
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&expected_out);
    assert!(exists, "default output should be <input>.aegisc");
}

#[test]
fn compile_output_is_valid_bytecode() {
    // The compiled output should be readable by `bytecode::read_file`.
    let src = write_stub_aegis("compile_bytecode");
    let out = tmp("compile_bytecode", "aegisc");
    cli_main(&args(&[
        "aegisc",
        "compile",
        src.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]));
    let result = aegis_compiler::bytecode::read_file(&out);
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&out);
    assert!(
        result.is_ok(),
        "compiled output should parse as valid bytecode"
    );
}

// ── check ─────────────────────────────────────────────────────────────────────

#[test]
fn check_no_args_returns_1() {
    assert_eq!(cli_main(&args(&["aegisc", "check"])), 1);
}

#[test]
fn check_missing_file_returns_1() {
    assert_eq!(
        cli_main(&args(&[
            "aegisc",
            "check",
            "/nonexistent/path/policy.aegis"
        ])),
        1
    );
}

#[test]
fn check_valid_file_returns_0() {
    let src = write_stub_aegis("check_valid");
    let code = cli_main(&args(&["aegisc", "check", src.to_str().unwrap()]));
    let _ = std::fs::remove_file(&src);
    assert_eq!(code, 0);
}

// ── dump ──────────────────────────────────────────────────────────────────────

#[test]
fn dump_no_args_returns_1() {
    assert_eq!(cli_main(&args(&["aegisc", "dump"])), 1);
}

#[test]
fn dump_missing_file_returns_1() {
    assert_eq!(
        cli_main(&args(&["aegisc", "dump", "/nonexistent/path/policy.aegis"])),
        1
    );
}

#[test]
fn dump_valid_file_returns_0() {
    let src = write_stub_aegis("dump_valid");
    let code = cli_main(&args(&["aegisc", "dump", src.to_str().unwrap()]));
    let _ = std::fs::remove_file(&src);
    assert_eq!(code, 0);
}

// ── inspect ───────────────────────────────────────────────────────────────────

#[test]
fn inspect_no_args_returns_1() {
    assert_eq!(cli_main(&args(&["aegisc", "inspect"])), 1);
}

#[test]
fn inspect_missing_file_returns_1() {
    assert_eq!(
        cli_main(&args(&[
            "aegisc",
            "inspect",
            "/nonexistent/path/policy.aegisc"
        ])),
        1
    );
}

#[test]
fn inspect_corrupt_file_still_returns_0() {
    // inspect_header succeeds even for corrupt files — it reports "INVALID" magic
    // and returns 0 so callers can see the raw header. Only a missing file gives 1.
    let path = tmp("inspect_invalid", "aegisc");
    std::fs::write(&path, b"not a valid bytecode file").expect("write garbage");
    let code = cli_main(&args(&["aegisc", "inspect", path.to_str().unwrap()]));
    let _ = std::fs::remove_file(&path);
    assert_eq!(code, 0);
}

#[test]
fn inspect_valid_aegisc_returns_0() {
    // Produce a real .aegisc via compile, then inspect it.
    let src = write_stub_aegis("inspect_valid");
    let aegisc = tmp("inspect_valid", "aegisc");
    cli_main(&args(&[
        "aegisc",
        "compile",
        src.to_str().unwrap(),
        "-o",
        aegisc.to_str().unwrap(),
    ]));
    let code = cli_main(&args(&["aegisc", "inspect", aegisc.to_str().unwrap()]));
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&aegisc);
    assert_eq!(code, 0);
}

#[test]
fn compile_then_inspect_round_trip() {
    // Full round-trip: compile a stub, then inspect. Both should succeed.
    let src = write_stub_aegis("round_trip");
    let aegisc = tmp("round_trip", "aegisc");
    let compile_code = cli_main(&args(&[
        "aegisc",
        "compile",
        src.to_str().unwrap(),
        "-o",
        aegisc.to_str().unwrap(),
    ]));
    let inspect_code = cli_main(&args(&["aegisc", "inspect", aegisc.to_str().unwrap()]));
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&aegisc);
    assert_eq!(compile_code, 0, "compile should succeed");
    assert_eq!(inspect_code, 0, "inspect of compiled output should succeed");
}

// ── Semantically rich policy files ───────────────────────────────────────────

#[test]
fn compile_rich_policy_returns_0() {
    let src = write_rich_aegis("rich_compile");
    let out = tmp("rich_compile", "aegisc");
    let code = cli_main(&args(&[
        "aegisc",
        "compile",
        src.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]));
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&out);
    assert_eq!(code, 0, "rich policy should compile cleanly");
}

#[test]
fn compile_rich_policy_produces_valid_bytecode() {
    let src = write_rich_aegis("rich_bytecode");
    let out = tmp("rich_bytecode", "aegisc");
    cli_main(&args(&[
        "aegisc",
        "compile",
        src.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]));
    let result = aegis_compiler::bytecode::read_file(&out);
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&out);
    assert!(result.is_ok(), "rich policy bytecode should be readable");
}

#[test]
fn check_rich_policy_returns_0() {
    let src = write_rich_aegis("rich_check");
    let code = cli_main(&args(&["aegisc", "check", src.to_str().unwrap()]));
    let _ = std::fs::remove_file(&src);
    assert_eq!(code, 0, "rich policy should type-check cleanly");
}

#[test]
fn dump_rich_policy_returns_0() {
    // `dump` takes the .aegis source, compiles it, and prints the IR as JSON.
    let src = write_rich_aegis("rich_dump");
    let code = cli_main(&args(&["aegisc", "dump", src.to_str().unwrap()]));
    let _ = std::fs::remove_file(&src);
    assert_eq!(code, 0, "dump of rich policy should succeed");
}

#[test]
fn inspect_rich_policy_returns_0() {
    let src = write_rich_aegis("rich_inspect");
    let out = tmp("rich_inspect", "aegisc");
    cli_main(&args(&[
        "aegisc",
        "compile",
        src.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]));
    let code = cli_main(&args(&["aegisc", "inspect", out.to_str().unwrap()]));
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&out);
    assert_eq!(code, 0, "inspect of rich policy should succeed");
}

#[test]
fn rich_policy_bytecode_contains_state_machines() {
    // The rich policy has two temporal invariants → two state machines.
    let src = write_rich_aegis("rich_sm_count");
    let out = tmp("rich_sm_count", "aegisc");
    cli_main(&args(&[
        "aegisc",
        "compile",
        src.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]));
    let policy = aegis_compiler::bytecode::read_file(&out).expect("read bytecode");
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        policy.state_machines.len(),
        2,
        "two invariants should produce two state machines"
    );
}

#[test]
fn rich_policy_bytecode_has_expected_name() {
    let src = write_rich_aegis("rich_name");
    let out = tmp("rich_name", "aegisc");
    cli_main(&args(&[
        "aegisc",
        "compile",
        src.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]));
    let policy = aegis_compiler::bytecode::read_file(&out).expect("read bytecode");
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&out);
    assert_eq!(policy.name.as_str(), "DataGuard");
}

#[test]
fn rich_policy_bytecode_has_two_rules() {
    // DataGuard has two `on` rules: tool_call and data_access.
    let src = write_rich_aegis("rich_rules");
    let out = tmp("rich_rules", "aegisc");
    cli_main(&args(&[
        "aegisc",
        "compile",
        src.to_str().unwrap(),
        "-o",
        out.to_str().unwrap(),
    ]));
    let policy = aegis_compiler::bytecode::read_file(&out).expect("read bytecode");
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&out);
    assert_eq!(
        policy.rules.len(),
        2,
        "DataGuard should have exactly two compiled rules"
    );
}
