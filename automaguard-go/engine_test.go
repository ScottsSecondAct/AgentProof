//go:build cgo

package automaguard_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	automaguard "github.com/automaguard/automaguard-go"
)

// policyPath locates the compiled customer_data_guard.aegisc relative to this
// file so tests work regardless of the working directory.
func policyPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// automaguard-go/engine_test.go → ../../examples/customer_data_guard.aegisc
	p := filepath.Join(filepath.Dir(file), "..", "examples", "customer_data_guard.aegisc")
	if _, err := os.Stat(p); os.IsNotExist(err) {
		t.Skipf("compiled policy not found at %s — compile with: "+
			"aegisc compile examples/customer_data_guard.aegis -o examples/customer_data_guard.aegisc", p)
	}
	return p
}

func TestNewEngine_LoadsPolicy(t *testing.T) {
	engine, err := automaguard.NewEngine(policyPath(t))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()
}

func TestNewEngine_NonExistentFile(t *testing.T) {
	_, err := automaguard.NewEngine("/nonexistent/guard.aegisc")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestEvaluate_DDLDeny(t *testing.T) {
	engine, err := automaguard.NewEngine(policyPath(t))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	result, err := engine.Evaluate("tool_call", map[string]any{
		"tool_name": "drop_table",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Verdict != automaguard.VerdictDeny {
		t.Errorf("drop_table: got %q, want deny", result.Verdict)
	}
}

func TestEvaluate_SafeToolCallAllow(t *testing.T) {
	engine, err := automaguard.NewEngine(policyPath(t))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	result, err := engine.Evaluate("tool_call", map[string]any{
		"tool_name": "query_tickets",
		"arguments": "region=EMEA",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Verdict != automaguard.VerdictAllow {
		t.Errorf("query_tickets: got %q, want allow", result.Verdict)
	}
}

func TestEvaluate_PIIDataAccessAudit(t *testing.T) {
	engine, err := automaguard.NewEngine(policyPath(t))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	result, err := engine.Evaluate("data_access", map[string]any{
		"classification": "PII",
		"record_id":      "10042",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Verdict != automaguard.VerdictAudit {
		t.Errorf("PII data_access: got %q, want audit", result.Verdict)
	}
}

func TestEvaluate_PIIExfiltrationDeny(t *testing.T) {
	engine, err := automaguard.NewEngine(policyPath(t))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	// Step 1: PII access (audited, advances state machine)
	_, err = engine.Evaluate("data_access", map[string]any{
		"classification": "PII",
		"record_id":      "10042",
	})
	if err != nil {
		t.Fatalf("Evaluate data_access: %v", err)
	}

	// Step 2: External request to unapproved domain → deny
	result, err := engine.Evaluate("external_request", map[string]any{
		"domain": "external-firm.com",
		"method": "POST",
	})
	if err != nil {
		t.Fatalf("Evaluate external_request: %v", err)
	}
	if result.Verdict != automaguard.VerdictDeny {
		t.Errorf("exfiltration attempt: got %q, want deny", result.Verdict)
	}
}

func TestEvaluate_ApprovedExternalRequestAllow(t *testing.T) {
	engine, err := automaguard.NewEngine(policyPath(t))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	result, err := engine.Evaluate("external_request", map[string]any{
		"domain": "reports.internal.corp",
		"method": "POST",
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if result.Verdict != automaguard.VerdictAllow {
		t.Errorf("approved external request: got %q, want allow", result.Verdict)
	}
}

func TestEvaluate_RateLimit(t *testing.T) {
	engine, err := automaguard.NewEngine(policyPath(t))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	// First 20 events should be allowed; the 21st should be denied.
	for i := range 20 {
		r, err := engine.Evaluate("data_access", map[string]any{
			"classification": "aggregate",
			"record_id":      i,
		})
		if err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		if r.Verdict != automaguard.VerdictAllow {
			t.Errorf("event %d: got %q, want allow", i, r.Verdict)
		}
	}

	r21, err := engine.Evaluate("data_access", map[string]any{
		"classification": "aggregate",
		"record_id":      21,
	})
	if err != nil {
		t.Fatalf("event 21: %v", err)
	}
	if r21.Verdict != automaguard.VerdictDeny {
		t.Errorf("event 21 (rate limit): got %q, want deny", r21.Verdict)
	}
}

func TestEvaluateOrErr_DenyReturnsEnforcementError(t *testing.T) {
	engine, err := automaguard.NewEngine(policyPath(t))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	_, err = engine.EvaluateOrErr("tool_call", map[string]any{
		"tool_name": "drop_table",
	})
	if err == nil {
		t.Fatal("expected EnforcementError")
	}
	var ee *automaguard.EnforcementError
	if ok := isEnforcementError(err, &ee); !ok {
		t.Fatalf("error type: got %T, want *EnforcementError", err)
	}
	if ee.Result.Verdict != automaguard.VerdictDeny {
		t.Errorf("result verdict: got %q", ee.Result.Verdict)
	}
}

func TestEngine_CloseIsIdempotent(t *testing.T) {
	engine, err := automaguard.NewEngine(policyPath(t))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	engine.Close()
	engine.Close() // must not panic or crash
}

func TestEngine_EvaluateAfterClose(t *testing.T) {
	engine, err := automaguard.NewEngine(policyPath(t))
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	engine.Close()

	_, err = engine.Evaluate("tool_call", nil)
	if err == nil {
		t.Fatal("expected error after Close")
	}
}

// isEnforcementError is a type-assertion helper that avoids direct dependency
// on errors.As (available since Go 1.13, fine here, but kept explicit for
// clarity in tests).
func isEnforcementError(err error, target **automaguard.EnforcementError) bool {
	if ee, ok := err.(*automaguard.EnforcementError); ok {
		*target = ee
		return true
	}
	return false
}
