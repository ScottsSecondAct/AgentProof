//! Bytecode serializer for compiled Aegis policies.
//!
//! Writes [`CompiledPolicy`] to `.aegisc` binary files that the Rust
//! runtime verifier loads at startup. Also supports JSON output for
//! debugging and inspection.
//!
//! # File format
//!
//! ```text
//! ┌──────────────┬─────────┬──────────┬───────────┬──────────────┐
//! │ Magic (4B)   │ Ver (2B)│ Flags(2B)│ Len (4B)  │ Payload (NB) │
//! │ 0xAE 0x91 0x5C 0x01   │          │           │              │
//! └──────────────┴─────────┴──────────┴───────────┴──────────────┘
//! ```
//!
//! - Magic bytes: `0xAE915C01` ("AEGIS" + version nibble)
//! - Version: format version (currently 1.0)
//! - Flags: reserved (compression, etc.)
//! - Len: payload length in bytes (u32 LE)
//! - Payload: bincode-serialized `CompiledPolicy`

use std::io::{self, Read, Write};

use crate::ir::CompiledPolicy;

/// Magic bytes identifying an `.aegisc` file.
const MAGIC: [u8; 4] = [0xAE, 0x91, 0x5C, 0x01];

/// Current bytecode format version.
const FORMAT_VERSION: u16 = 1;

/// Flags (reserved for future use: compression, encryption, etc.)
const FLAGS_NONE: u16 = 0;

/// Errors that can occur during serialization/deserialization.
#[derive(Debug)]
pub enum BytecodeError {
    /// I/O error during read/write
    Io(io::Error),
    /// Serialization/deserialization error
    Serde(String),
    /// Invalid magic bytes — not an .aegisc file
    InvalidMagic,
    /// Unsupported format version
    UnsupportedVersion { found: u16, expected: u16 },
    /// Payload length mismatch (possible corruption)
    LengthMismatch { expected: u32, actual: u32 },
}

impl From<io::Error> for BytecodeError {
    fn from(e: io::Error) -> Self {
        BytecodeError::Io(e)
    }
}

impl std::error::Error for BytecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BytecodeError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl std::fmt::Display for BytecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BytecodeError::Io(e) => write!(f, "I/O error: {e}"),
            BytecodeError::Serde(e) => write!(f, "serialization error: {e}"),
            BytecodeError::InvalidMagic => write!(f, "not a valid .aegisc file (bad magic bytes)"),
            BytecodeError::UnsupportedVersion { found, expected } => {
                write!(
                    f,
                    "unsupported format version {found} (expected {expected})"
                )
            }
            BytecodeError::LengthMismatch { expected, actual } => {
                write!(
                    f,
                    "payload length mismatch: header says {expected} bytes, got {actual}"
                )
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Writing
// ═══════════════════════════════════════════════════════════════════════

/// Serialize a compiled policy to the `.aegisc` binary format.
pub fn write_bytecode<W: Write>(
    writer: &mut W,
    policy: &CompiledPolicy,
) -> Result<usize, BytecodeError> {
    // Serialize the payload
    let payload = serde_json::to_vec(policy).map_err(|e| BytecodeError::Serde(e.to_string()))?;

    let payload_len = payload.len() as u32;

    // Write header
    writer.write_all(&MAGIC)?;
    writer.write_all(&FORMAT_VERSION.to_le_bytes())?;
    writer.write_all(&FLAGS_NONE.to_le_bytes())?;
    writer.write_all(&payload_len.to_le_bytes())?;

    // Write payload
    writer.write_all(&payload)?;

    // Total bytes written: header (12) + payload
    Ok(12 + payload.len())
}

/// Serialize a compiled policy to `.aegisc` bytes in memory.
pub fn to_bytecode(policy: &CompiledPolicy) -> Result<Vec<u8>, BytecodeError> {
    let mut buf = Vec::new();
    write_bytecode(&mut buf, policy)?;
    Ok(buf)
}

// ═══════════════════════════════════════════════════════════════════════
//  Reading
// ═══════════════════════════════════════════════════════════════════════

/// Deserialize a compiled policy from the `.aegisc` binary format.
pub fn read_bytecode<R: Read>(reader: &mut R) -> Result<CompiledPolicy, BytecodeError> {
    // Read and validate magic
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(BytecodeError::InvalidMagic);
    }

    // Read version
    let mut version_bytes = [0u8; 2];
    reader.read_exact(&mut version_bytes)?;
    let version = u16::from_le_bytes(version_bytes);
    if version != FORMAT_VERSION {
        return Err(BytecodeError::UnsupportedVersion {
            found: version,
            expected: FORMAT_VERSION,
        });
    }

    // Read flags (currently unused)
    let mut flags_bytes = [0u8; 2];
    reader.read_exact(&mut flags_bytes)?;

    // Read payload length
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let payload_len = u32::from_le_bytes(len_bytes);

    // Read payload
    let mut payload = vec![0u8; payload_len as usize];
    reader.read_exact(&mut payload)?;

    // Deserialize
    let policy: CompiledPolicy =
        serde_json::from_slice(&payload).map_err(|e| BytecodeError::Serde(e.to_string()))?;

    Ok(policy)
}

/// Deserialize a compiled policy from in-memory `.aegisc` bytes.
pub fn from_bytecode(bytes: &[u8]) -> Result<CompiledPolicy, BytecodeError> {
    let mut cursor = io::Cursor::new(bytes);
    read_bytecode(&mut cursor)
}

// ═══════════════════════════════════════════════════════════════════════
//  Debug / JSON output
// ═══════════════════════════════════════════════════════════════════════

/// Serialize a compiled policy to pretty-printed JSON (for debugging).
pub fn to_json(policy: &CompiledPolicy) -> Result<String, BytecodeError> {
    serde_json::to_string_pretty(policy).map_err(|e| BytecodeError::Serde(e.to_string()))
}

/// Serialize a compiled policy to compact JSON.
pub fn to_json_compact(policy: &CompiledPolicy) -> Result<String, BytecodeError> {
    serde_json::to_string(policy).map_err(|e| BytecodeError::Serde(e.to_string()))
}

// ═══════════════════════════════════════════════════════════════════════
//  File helpers
// ═══════════════════════════════════════════════════════════════════════

/// Write a compiled policy to a `.aegisc` file.
pub fn write_file(path: &std::path::Path, policy: &CompiledPolicy) -> Result<usize, BytecodeError> {
    let mut file = std::fs::File::create(path)?;
    write_bytecode(&mut file, policy)
}

/// Read a compiled policy from a `.aegisc` file.
pub fn read_file(path: &std::path::Path) -> Result<CompiledPolicy, BytecodeError> {
    let mut file = std::fs::File::open(path)?;
    read_bytecode(&mut file)
}

/// Inspect a `.aegisc` file header without loading the full payload.
pub fn inspect_header(path: &std::path::Path) -> Result<FileInfo, BytecodeError> {
    let mut file = std::fs::File::open(path)?;

    let mut magic = [0u8; 4];
    file.read_exact(&mut magic)?;
    let valid_magic = magic == MAGIC;

    let mut version_bytes = [0u8; 2];
    file.read_exact(&mut version_bytes)?;
    let version = u16::from_le_bytes(version_bytes);

    let mut flags_bytes = [0u8; 2];
    file.read_exact(&mut flags_bytes)?;
    let flags = u16::from_le_bytes(flags_bytes);

    let mut len_bytes = [0u8; 4];
    file.read_exact(&mut len_bytes)?;
    let payload_len = u32::from_le_bytes(len_bytes);

    let file_size = std::fs::metadata(path)?.len();

    Ok(FileInfo {
        valid_magic,
        version,
        flags,
        payload_len,
        file_size,
    })
}

/// Summary information about a `.aegisc` file.
#[derive(Debug)]
pub struct FileInfo {
    pub valid_magic: bool,
    pub version: u16,
    pub flags: u16,
    pub payload_len: u32,
    pub file_size: u64,
}

impl std::fmt::Display for FileInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "  Magic:   {}",
            if self.valid_magic { "valid" } else { "INVALID" }
        )?;
        writeln!(f, "  Version: {}", self.version)?;
        writeln!(f, "  Flags:   0x{:04x}", self.flags)?;
        writeln!(f, "  Payload: {} bytes", self.payload_len)?;
        writeln!(f, "  File:    {} bytes total", self.file_size)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Literal, SeverityLevel};
    use crate::ir::{CompiledPolicy, IRExpr, PolicyMetadata, StateMachineBuilder, TemporalKind};
    use smol_str::SmolStr;

    fn minimal_policy() -> CompiledPolicy {
        CompiledPolicy {
            name: SmolStr::new("TestPolicy"),
            severity: SeverityLevel::Medium,
            scopes: vec![],
            rules: vec![],
            constraints: vec![],
            state_machines: vec![],
            metadata: PolicyMetadata {
                annotations: vec![],
                source_hash: 0,
                compiler_version: SmolStr::new("0.1.0"),
            },
        }
    }

    // ── Header format ────────────────────────────────────────────────────

    #[test]
    fn bytecode_starts_with_magic_bytes() {
        let bytes = to_bytecode(&minimal_policy()).unwrap();
        assert_eq!(&bytes[..4], &[0xAE, 0x91, 0x5C, 0x01]);
    }

    #[test]
    fn bytecode_version_field_is_1() {
        let bytes = to_bytecode(&minimal_policy()).unwrap();
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        assert_eq!(version, 1);
    }

    #[test]
    fn bytecode_flags_field_is_zero() {
        let bytes = to_bytecode(&minimal_policy()).unwrap();
        let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
        assert_eq!(flags, 0);
    }

    #[test]
    fn bytecode_payload_length_matches_actual_payload() {
        let bytes = to_bytecode(&minimal_policy()).unwrap();
        let declared = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let actual = (bytes.len() - 12) as u32; // header is 12 bytes
        assert_eq!(declared, actual);
    }

    #[test]
    fn write_bytecode_returns_total_bytes_written() {
        let policy = minimal_policy();
        let mut buf = Vec::new();
        let n = write_bytecode(&mut buf, &policy).unwrap();
        assert_eq!(n, buf.len());
        assert!(n > 12, "should be more than just the header");
    }

    // ── Round-trip ───────────────────────────────────────────────────────

    #[test]
    fn round_trip_minimal_policy() {
        let policy = minimal_policy();
        let bytes = to_bytecode(&policy).unwrap();
        let restored = from_bytecode(&bytes).unwrap();
        assert_eq!(restored.name, policy.name);
        assert_eq!(restored.severity, policy.severity);
        assert!(restored.rules.is_empty());
        assert!(restored.state_machines.is_empty());
    }

    #[test]
    fn round_trip_preserves_metadata() {
        let mut policy = minimal_policy();
        policy.metadata.source_hash = 0xDEADBEEF;
        policy.metadata.compiler_version = SmolStr::new("1.2.3");
        let restored = from_bytecode(&to_bytecode(&policy).unwrap()).unwrap();
        assert_eq!(restored.metadata.source_hash, 0xDEADBEEF);
        assert_eq!(restored.metadata.compiler_version.as_str(), "1.2.3");
    }

    #[test]
    fn round_trip_preserves_scopes() {
        let mut policy = minimal_policy();
        policy.scopes = vec![SmolStr::new("tool_call"), SmolStr::new("data_access")];
        let restored = from_bytecode(&to_bytecode(&policy).unwrap()).unwrap();
        assert_eq!(restored.scopes, policy.scopes);
    }

    #[test]
    fn round_trip_with_state_machine() {
        let mut policy = minimal_policy();
        let mut builder = StateMachineBuilder::new();
        let sm = builder.compile_always(
            SmolStr::new("NoHTTP"),
            SmolStr::new("InternalOnly"),
            IRExpr::Literal(Literal::Bool(true)),
            None,
        );
        policy.state_machines.push(sm);

        let restored = from_bytecode(&to_bytecode(&policy).unwrap()).unwrap();
        assert_eq!(restored.state_machines.len(), 1);
        assert_eq!(restored.state_machines[0].name.as_str(), "NoHTTP");
        assert_eq!(restored.state_machines[0].kind, TemporalKind::Always);
        assert_eq!(restored.state_machines[0].states.len(), 2);
        assert_eq!(restored.state_machines[0].transitions.len(), 2);
    }

    #[test]
    fn round_trip_multiple_state_machines() {
        let mut policy = minimal_policy();
        let mut builder = StateMachineBuilder::new();
        policy.state_machines.push(builder.compile_always(
            SmolStr::new("m1"),
            SmolStr::new("i1"),
            IRExpr::Literal(Literal::Bool(true)),
            None,
        ));
        policy.state_machines.push(builder.compile_eventually(
            SmolStr::new("m2"),
            SmolStr::new("i2"),
            IRExpr::Literal(Literal::Bool(false)),
            Some(60_000),
        ));

        let restored = from_bytecode(&to_bytecode(&policy).unwrap()).unwrap();
        assert_eq!(restored.state_machines.len(), 2);
        assert_eq!(restored.state_machines[0].kind, TemporalKind::Always);
        assert_eq!(restored.state_machines[1].kind, TemporalKind::Eventually);
        assert_eq!(restored.state_machines[1].deadline_millis, Some(60_000));
    }

    // ── Error cases ──────────────────────────────────────────────────────

    #[test]
    fn invalid_magic_byte_returns_invalid_magic_error() {
        let mut bytes = to_bytecode(&minimal_policy()).unwrap();
        bytes[0] = 0x00;
        assert!(matches!(
            from_bytecode(&bytes),
            Err(BytecodeError::InvalidMagic)
        ));
    }

    #[test]
    fn all_magic_bytes_must_match() {
        for i in 0..4 {
            let mut bytes = to_bytecode(&minimal_policy()).unwrap();
            bytes[i] ^= 0xFF; // flip all bits in one magic byte
            assert!(
                matches!(from_bytecode(&bytes), Err(BytecodeError::InvalidMagic)),
                "expected InvalidMagic when byte {i} is corrupted"
            );
        }
    }

    #[test]
    fn unsupported_version_returns_error_with_values() {
        let mut bytes = to_bytecode(&minimal_policy()).unwrap();
        let bad_version: u16 = 99;
        bytes[4..6].copy_from_slice(&bad_version.to_le_bytes());
        match from_bytecode(&bytes) {
            Err(BytecodeError::UnsupportedVersion { found, expected }) => {
                assert_eq!(found, 99);
                assert_eq!(expected, 1);
            }
            other => panic!("expected UnsupportedVersion, got {:?}", other),
        }
    }

    #[test]
    fn empty_input_returns_io_error() {
        assert!(matches!(from_bytecode(&[]), Err(BytecodeError::Io(_))));
    }

    #[test]
    fn truncated_header_returns_io_error() {
        // Only 3 bytes — not even a full magic
        assert!(matches!(
            from_bytecode(&[0xAE, 0x91, 0x5C]),
            Err(BytecodeError::Io(_))
        ));
    }

    #[test]
    fn truncated_payload_returns_io_error() {
        let mut bytes = to_bytecode(&minimal_policy()).unwrap();
        // Claim payload is larger than what's actually there
        let inflated: u32 = bytes.len() as u32 * 2;
        bytes[8..12].copy_from_slice(&inflated.to_le_bytes());
        assert!(matches!(from_bytecode(&bytes), Err(BytecodeError::Io(_))));
    }

    #[test]
    fn corrupted_json_payload_returns_serde_error() {
        let mut bytes = to_bytecode(&minimal_policy()).unwrap();
        // Overwrite payload with garbage (keep correct length in header)
        let payload_start = 12;
        for b in bytes[payload_start..].iter_mut() {
            *b = b'!';
        }
        assert!(matches!(
            from_bytecode(&bytes),
            Err(BytecodeError::Serde(_))
        ));
    }

    // ── JSON output ──────────────────────────────────────────────────────

    #[test]
    fn to_json_produces_valid_json_with_policy_name() {
        let policy = minimal_policy();
        let json = to_json(&policy).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["name"], "TestPolicy");
    }

    #[test]
    fn to_json_compact_produces_valid_json() {
        let policy = minimal_policy();
        let json = to_json_compact(&policy).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["name"], "TestPolicy");
    }

    #[test]
    fn to_json_is_pretty_printed() {
        let policy = minimal_policy();
        let pretty = to_json(&policy).unwrap();
        let compact = to_json_compact(&policy).unwrap();
        // Pretty version should have newlines; compact should not have leading spaces
        assert!(pretty.contains('\n'));
        assert!(pretty.len() > compact.len());
    }

    // ── File I/O ─────────────────────────────────────────────────────────

    #[test]
    fn write_file_creates_a_readable_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("automaguard_test_write_file.aegisc");
        let policy = minimal_policy();
        let bytes_written = write_file(&path, &policy).unwrap();
        assert!(path.exists(), "file should have been created");
        assert!(bytes_written > 12, "should have written header + payload");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_file_round_trips_policy() {
        let dir = std::env::temp_dir();
        let path = dir.join("automaguard_test_read_file.aegisc");
        let policy = minimal_policy();
        write_file(&path, &policy).unwrap();
        let restored = read_file(&path).unwrap();
        assert_eq!(restored.name, policy.name);
        assert_eq!(restored.severity, policy.severity);
        assert_eq!(restored.metadata.source_hash, policy.metadata.source_hash);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_file_preserves_state_machines() {
        let dir = std::env::temp_dir();
        let path = dir.join("automaguard_test_read_file_sm.aegisc");
        let mut policy = minimal_policy();
        let sm = StateMachineBuilder::new().compile_always(
            SmolStr::new("TestSM"),
            SmolStr::new("Inv"),
            IRExpr::Literal(Literal::Bool(true)),
            None,
        );
        policy.state_machines.push(sm);
        write_file(&path, &policy).unwrap();
        let restored = read_file(&path).unwrap();
        assert_eq!(restored.state_machines.len(), 1);
        assert_eq!(restored.state_machines[0].name.as_str(), "TestSM");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn write_file_returns_byte_count_matching_file_size() {
        let dir = std::env::temp_dir();
        let path = dir.join("automaguard_test_bytecount.aegisc");
        let policy = minimal_policy();
        let bytes_written = write_file(&path, &policy).unwrap();
        let file_size = std::fs::metadata(&path).unwrap().len() as usize;
        assert_eq!(bytes_written, file_size);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_file_missing_path_returns_io_error() {
        let path = std::path::Path::new("/tmp/automaguard_definitely_missing_file.aegisc");
        assert!(matches!(read_file(path), Err(BytecodeError::Io(_))));
    }

    #[test]
    fn read_file_corrupt_magic_returns_invalid_magic_error() {
        let dir = std::env::temp_dir();
        let path = dir.join("automaguard_test_corrupt_magic.aegisc");
        let mut bytes = to_bytecode(&minimal_policy()).unwrap();
        bytes[0] = 0x00; // corrupt first magic byte
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(read_file(&path), Err(BytecodeError::InvalidMagic)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inspect_header_returns_valid_info_for_good_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("automaguard_test_inspect.aegisc");
        let policy = minimal_policy();
        write_file(&path, &policy).unwrap();
        let info = inspect_header(&path).unwrap();
        assert!(info.valid_magic, "magic should be valid");
        assert_eq!(info.version, 1);
        assert_eq!(info.flags, 0);
        assert!(info.payload_len > 0);
        assert!(info.file_size > 12);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn inspect_header_missing_file_returns_io_error() {
        let path = std::path::Path::new("/tmp/automaguard_missing_inspect.aegisc");
        assert!(matches!(inspect_header(path), Err(BytecodeError::Io(_))));
    }

    #[test]
    fn inspect_header_file_size_matches_write() {
        let dir = std::env::temp_dir();
        let path = dir.join("automaguard_test_inspect_size.aegisc");
        let policy = minimal_policy();
        let bytes_written = write_file(&path, &policy).unwrap();
        let info = inspect_header(&path).unwrap();
        assert_eq!(info.file_size as usize, bytes_written);
        let _ = std::fs::remove_file(&path);
    }
}
