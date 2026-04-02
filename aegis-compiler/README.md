# aegis-compiler

The compiler for the [Aegis policy language](https://github.com/ScottsSecondAct/agentproof). Transforms `.aegis` source files into `.aegisc` bytecode containing compiled state machines, flattened rules, and verification metadata.

This crate is part of [AgentProof](https://github.com/ScottsSecondAct/agentproof) — formally verified policy enforcement for AI agents.

## What It Does

The compiler takes human-readable Aegis policies and produces an efficient binary representation that the [runtime verifier](../aegis-runtime/) can load and evaluate in <10ms. The key transformation: temporal logic invariants (`always`, `eventually`, `until`, `never`) are compiled into deterministic state machines at build time, so the runtime does zero interpretation.

### Pipeline

```
.aegis source
  → pest PEG parser (src/aegis.pest)
  → Typed AST with real source spans
  → Two-pass type checker (forward references supported)
  → IR lowering (flatten inheritance, compile temporals to automata)
  → .aegisc bytecode serialization
```

## Usage

### As a CLI

```bash
# Compile a policy to bytecode
aegisc compile guard.aegis -o guard.aegisc

# Type-check without producing output
aegisc check guard.aegis

# Dump compiled IR as JSON (pipe to jq for exploration)
aegisc dump guard.aegisc | jq '.state_machines'

# Inspect a .aegisc file header
aegisc inspect guard.aegisc
```

### As a Library

```rust
use aegis_compiler::{cli, bytecode};

// Compile from source
let policies = cli::compile_source(source_code, "guard.aegis")?;

// Serialize to bytecode
let bytes = bytecode::to_bytecode(&policies[0])?;

// Write to file
bytecode::write_file("guard.aegisc", &policies[0])?;

// Read back
let policy = bytecode::read_file("guard.aegisc")?;
```

## Building

```bash
cargo build --release
cargo test
```

No nightly features required. Minimum supported Rust version: stable.

## Bytecode Format

The `.aegisc` file format:

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 bytes | Magic number (`0xAE915C01`) |
| 4 | 2 bytes | Format version |
| 6 | 2 bytes | Flags |
| 8 | 4 bytes | Payload length |
| 12 | variable | JSON-serialized `CompiledPolicy` |

The JSON payload means compiled policies can also be transmitted over HTTP — useful for dashboard integration and remote policy loading.

## Key Design Decisions

- **Two-pass type checker** so forward references work naturally. First pass registers all declarations, second pass checks bodies.
- **Exhaustive match everywhere.** Adding a new AST node triggers compile errors in every pass that needs updating. This is intentional.
- **`SmolStr` for identifiers.** Inline-able for short strings, cheap to clone. Consistent across the compiler and runtime.
- **Temporal operators restricted to `proof`/`invariant` blocks.** Prevents nonsensical constructs like temporal checks in pattern match arms.
- **No nested temporals in v1.** `always(eventually(φ))` is rejected with a clear error suggesting decomposition into separate invariants.

## License

Apache 2.0