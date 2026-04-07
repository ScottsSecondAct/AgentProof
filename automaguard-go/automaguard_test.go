package automaguard_test

import (
	"encoding/json"
	"strings"
	"testing"

	automaguard "github.com/automaguard/automaguard-go"
)

// ── PolicyResult JSON deserialisation ─────────────────────────────────────────

func TestParseResult_Allow(t *testing.T) {
	const jsonStr = `{
		"verdict":               "allow",
		"reason":                null,
		"triggered_rules":       [],
		"violations":            [],
		"constraint_violations": [],
		"latency_us":            3
	}`
	var r automaguard.PolicyResult
	if err := json.Unmarshal([]byte(jsonStr), &r); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if r.Verdict != automaguard.VerdictAllow {
		t.Errorf("verdict: got %q, want %q", r.Verdict, automaguard.VerdictAllow)
	}
	if r.Reason != nil {
		t.Errorf("reason: got %v, want nil", r.Reason)
	}
	if len(r.TriggeredRules) != 0 {
		t.Errorf("triggered_rules: got %v, want []", r.TriggeredRules)
	}
	if r.LatencyUs != 3 {
		t.Errorf("latency_us: got %d, want 3", r.LatencyUs)
	}
	if !r.IsAllowed() {
		t.Error("IsAllowed() should be true")
	}
}

func TestParseResult_DenyWithReason(t *testing.T) {
	reason := "DDL operations are prohibited"
	const jsonStr = `{
		"verdict":               "deny",
		"reason":                "DDL operations are prohibited",
		"triggered_rules":       [0],
		"violations":            [],
		"constraint_violations": [],
		"latency_us":            4
	}`
	var r automaguard.PolicyResult
	if err := json.Unmarshal([]byte(jsonStr), &r); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if r.Verdict != automaguard.VerdictDeny {
		t.Errorf("verdict: got %q, want %q", r.Verdict, automaguard.VerdictDeny)
	}
	if r.Reason == nil || *r.Reason != reason {
		t.Errorf("reason: got %v, want %q", r.Reason, reason)
	}
	if len(r.TriggeredRules) != 1 || r.TriggeredRules[0] != 0 {
		t.Errorf("triggered_rules: got %v, want [0]", r.TriggeredRules)
	}
	if !r.IsDenied() {
		t.Error("IsDenied() should be true")
	}
	if r.ReasonOrDefault() != reason {
		t.Errorf("ReasonOrDefault(): got %q, want %q", r.ReasonOrDefault(), reason)
	}
}

func TestParseResult_AuditVerdict(t *testing.T) {
	const jsonStr = `{
		"verdict":               "audit",
		"reason":                "PII record accessed",
		"triggered_rules":       [1],
		"violations":            [],
		"constraint_violations": [],
		"latency_us":            2
	}`
	var r automaguard.PolicyResult
	if err := json.Unmarshal([]byte(jsonStr), &r); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !r.IsAudited() {
		t.Error("IsAudited() should be true")
	}
}

func TestParseResult_RedactVerdict(t *testing.T) {
	const jsonStr = `{
		"verdict":               "redact",
		"reason":                "PII in output",
		"triggered_rules":       [2],
		"violations":            [],
		"constraint_violations": [],
		"latency_us":            5
	}`
	var r automaguard.PolicyResult
	if err := json.Unmarshal([]byte(jsonStr), &r); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !r.IsRedacted() {
		t.Error("IsRedacted() should be true")
	}
}

func TestParseResult_WithViolation(t *testing.T) {
	const jsonStr = `{
		"verdict":               "deny",
		"reason":                "NoPIIExfiltration violated",
		"triggered_rules":       [0],
		"violations":            [
			{"proof":"ExfiltrationGuard","invariant":"NoPIIExfiltration",
			 "message":"PII accessed then external request sent"}
		],
		"constraint_violations": [],
		"latency_us":            6
	}`
	var r automaguard.PolicyResult
	if err := json.Unmarshal([]byte(jsonStr), &r); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(r.Violations) != 1 {
		t.Fatalf("violations: got %d, want 1", len(r.Violations))
	}
	v := r.Violations[0]
	if v.Proof != "ExfiltrationGuard" {
		t.Errorf("proof: got %q", v.Proof)
	}
	if v.Invariant != "NoPIIExfiltration" {
		t.Errorf("invariant: got %q", v.Invariant)
	}
}

func TestParseResult_WithConstraintViolation(t *testing.T) {
	const jsonStr = `{
		"verdict":               "deny",
		"reason":                "Rate limit exceeded",
		"triggered_rules":       [],
		"violations":            [],
		"constraint_violations": [
			{"kind":"RateLimit","target":"data_access","limit":20,"current":21,"window_ms":60000}
		],
		"latency_us":            7
	}`
	var r automaguard.PolicyResult
	if err := json.Unmarshal([]byte(jsonStr), &r); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(r.ConstraintViolations) != 1 {
		t.Fatalf("constraint_violations: got %d, want 1", len(r.ConstraintViolations))
	}
	cv := r.ConstraintViolations[0]
	if cv.Kind != "RateLimit" {
		t.Errorf("kind: got %q", cv.Kind)
	}
	if cv.Target != "data_access" {
		t.Errorf("target: got %q", cv.Target)
	}
	if cv.Limit != 20 || cv.Current != 21 || cv.WindowMs != 60000 {
		t.Errorf("counts: limit=%d current=%d window_ms=%d", cv.Limit, cv.Current, cv.WindowMs)
	}
}

// ── Verdict constants ─────────────────────────────────────────────────────────

func TestVerdictConstants(t *testing.T) {
	cases := []struct {
		v    automaguard.Verdict
		want string
	}{
		{automaguard.VerdictAllow, "allow"},
		{automaguard.VerdictDeny, "deny"},
		{automaguard.VerdictAudit, "audit"},
		{automaguard.VerdictRedact, "redact"},
	}
	for _, tc := range cases {
		if string(tc.v) != tc.want {
			t.Errorf("Verdict %q: got %q", tc.want, tc.v)
		}
	}
}

// ── EnforcementError ──────────────────────────────────────────────────────────

func TestEnforcementError_WithReason(t *testing.T) {
	reason := "Tool exec is not allowed"
	r := &automaguard.PolicyResult{
		Verdict: automaguard.VerdictDeny,
		Reason:  &reason,
	}
	err := &automaguard.EnforcementError{Result: r}
	if !strings.Contains(err.Error(), reason) {
		t.Errorf("Error() = %q, want to contain %q", err.Error(), reason)
	}
}

func TestEnforcementError_WithoutReason(t *testing.T) {
	r := &automaguard.PolicyResult{Verdict: automaguard.VerdictDeny}
	err := &automaguard.EnforcementError{Result: r}
	if err.Error() == "" {
		t.Error("Error() should not be empty")
	}
}

func TestReasonOrDefault_NilReason(t *testing.T) {
	r := &automaguard.PolicyResult{Verdict: automaguard.VerdictDeny}
	got := r.ReasonOrDefault()
	if got != "deny" {
		t.Errorf("ReasonOrDefault() = %q, want %q", got, "deny")
	}
}

// ── NoCgo stub (only relevant when CGO_ENABLED=0) ────────────────────────────

func TestNewEngine_ReturnsError(t *testing.T) {
	// When cgo is enabled this will succeed (or fail because the library
	// isn't present); when cgo is disabled it always returns an error.
	// Either way, NewEngine must not panic.
	_, err := automaguard.NewEngine("/nonexistent/guard.aegisc")
	if err == nil {
		t.Log("NewEngine succeeded (cgo+library available)")
	} else {
		t.Logf("NewEngine returned expected error: %v", err)
	}
}
