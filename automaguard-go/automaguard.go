// Package automaguard provides Go bindings for the AutomaGuard policy engine.
//
// AutomaGuard enforces compiled temporal policies — expressed in the Aegis
// Policy Language and compiled to .aegisc bytecode — against AI agent tool
// calls at runtime.  Policies can express per-event constraints, rate limits,
// and sequence-level temporal invariants that compile to state machines.
//
// # Quick start
//
//	engine, err := automaguard.NewEngine("guard.aegisc")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer engine.Close()
//
//	result, err := engine.Evaluate("tool_call", map[string]any{
//	    "tool_name": "send_email",
//	    "arguments": map[string]any{"to": "user@external.com"},
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//	if result.Verdict == automaguard.VerdictDeny {
//	    log.Fatalf("blocked: %s", result.ReasonOrDefault())
//	}
//
// # Native library
//
// This package uses cgo to call libaegis (the C ABI layer from aegis-ffi).
// Before running, place the platform-specific shared library in:
//
//	native/linux_amd64/libaegis.so     (Linux x86-64)
//	native/darwin_arm64/libaegis.dylib  (macOS Apple Silicon)
//	native/darwin_amd64/libaegis.dylib  (macOS Intel)
//	native/windows_amd64/aegis.dll      (Windows x86-64)
//
// Build the library from the aegis-ffi crate:
//
//	cd aegis-ffi && cargo build --release
//	cp target/release/libaegis.so ../automaguard-go/native/linux_amd64/
//
// When CGO_ENABLED=0 the package compiles but NewEngine returns an error.
package automaguard

// EnforcementError is returned when policy evaluation yields a Deny verdict.
// The full PolicyResult is attached so callers can inspect triggered rules,
// invariant violations, and the denial reason.
type EnforcementError struct {
	Result *PolicyResult
}

func (e *EnforcementError) Error() string {
	if e.Result.Reason != nil {
		return "automaguard: policy denied: " + *e.Result.Reason
	}
	return "automaguard: policy denied"
}
