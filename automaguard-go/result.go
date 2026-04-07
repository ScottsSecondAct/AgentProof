package automaguard

import "encoding/json"

// Verdict is the outcome of evaluating an agent event against a loaded policy.
type Verdict string

const (
	// VerdictAllow means the event may proceed.
	VerdictAllow Verdict = "allow"
	// VerdictDeny means the event must be blocked before execution.
	VerdictDeny Verdict = "deny"
	// VerdictAudit means the event is allowed but logged for compliance review.
	VerdictAudit Verdict = "audit"
	// VerdictRedact means the event is allowed but response fields must be sanitised.
	VerdictRedact Verdict = "redact"
)

// Violation describes a temporal invariant that reached a violated terminal
// state during event evaluation.
type Violation struct {
	// Proof is the name of the proof block that owns this invariant.
	Proof string `json:"proof"`
	// Invariant is the name of the violated invariant.
	Invariant string `json:"invariant"`
	// Message is a human-readable description of the violation.
	Message string `json:"message"`
}

// ConstraintViolation describes a rate-limit or quota constraint that was
// exceeded during event evaluation.
type ConstraintViolation struct {
	// Kind identifies the constraint type (e.g. "RateLimit").
	Kind string `json:"kind"`
	// Target is the event type the constraint applies to.
	Target string `json:"target"`
	// Limit is the configured maximum event count within the window.
	Limit uint64 `json:"limit"`
	// Current is the observed event count within the current window.
	Current uint64 `json:"current"`
	// WindowMs is the sliding window duration in milliseconds.
	WindowMs uint64 `json:"window_ms"`
}

// PolicyResult is the full outcome of evaluating one agent event against a
// loaded policy.  Obtain via Engine.Evaluate.
type PolicyResult struct {
	// Verdict is the final policy decision.
	Verdict Verdict `json:"verdict"`
	// Reason is the human-readable denial reason, or nil if none was supplied.
	Reason *string `json:"reason"`
	// TriggeredRules lists the IDs of the rules that matched this event.
	TriggeredRules []uint32 `json:"triggered_rules"`
	// Violations lists temporal invariant violations detected during evaluation.
	Violations []Violation `json:"violations"`
	// ConstraintViolations lists rate-limit or quota violations.
	ConstraintViolations []ConstraintViolation `json:"constraint_violations"`
	// LatencyUs is the evaluation latency in microseconds.
	LatencyUs uint64 `json:"latency_us"`
}

// IsAllowed reports whether the verdict is VerdictAllow.
func (r *PolicyResult) IsAllowed() bool { return r.Verdict == VerdictAllow }

// IsDenied reports whether the verdict is VerdictDeny.
func (r *PolicyResult) IsDenied() bool { return r.Verdict == VerdictDeny }

// IsAudited reports whether the verdict is VerdictAudit.
func (r *PolicyResult) IsAudited() bool { return r.Verdict == VerdictAudit }

// IsRedacted reports whether the verdict is VerdictRedact.
func (r *PolicyResult) IsRedacted() bool { return r.Verdict == VerdictRedact }

// ReasonOrDefault returns Reason if non-nil, otherwise a generic denial message.
func (r *PolicyResult) ReasonOrDefault() string {
	if r.Reason != nil {
		return *r.Reason
	}
	return string(r.Verdict)
}

// parseResult deserialises a PolicyResult from the JSON string returned by the
// native engine.
func parseResult(jsonStr string) (*PolicyResult, error) {
	var r PolicyResult
	if err := json.Unmarshal([]byte(jsonStr), &r); err != nil {
		return nil, err
	}
	return &r, nil
}
