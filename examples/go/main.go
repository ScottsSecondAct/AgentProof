// Customer Data Assistant — AutomaGuard Go SDK example.
//
// Demonstrates AutomaGuard policy enforcement on a simulated agent tool-call
// loop (no LLM API key required — events are canned).
//
// Usage:
//
//	go run . --safe      # aggregate query, all events allowed/audited
//	go run . --unsafe    # PII exfiltration attempt, blocked
//	go run . --stress    # canned scenario suite, prints pass/fail for each
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	automaguard "github.com/automaguard/automaguard-go"
)

// ── Policy path ───────────────────────────────────────────────────────────────

func policyPath() string {
	// examples/go/main.go → examples/customer_data_guard.aegisc
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "customer_data_guard.aegisc")
}

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	path := policyPath()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr,
			"Policy bytecode not found at %s\nCompile it first:\n"+
				"  aegisc compile examples/customer_data_guard.aegis"+
				" -o examples/customer_data_guard.aegisc\n", path)
		os.Exit(1)
	}

	engine, err := automaguard.NewEngine(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to load engine:", err)
		os.Exit(1)
	}
	defer engine.Close()

	args := os.Args[1:]
	switch {
	case contains(args, "--stress"):
		runStress(engine)
	case contains(args, "--safe"):
		run(engine, "safe", safePrompt, safeEvents())
	default:
		run(engine, "unsafe", unsafePrompt, unsafeEvents())
	}
}

// ── Normal agent run ──────────────────────────────────────────────────────────

func run(engine *automaguard.Engine, mode, prompt string, events []agentEvent) {
	fmt.Printf("\n=== AutomaGuard Go Example (%s run) ===\n\n", mode)
	fmt.Println("Prompt:", prompt, "\n")

	for _, ev := range events {
		result, err := engine.Evaluate(ev.eventType, ev.fields)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Evaluate error:", err)
			os.Exit(1)
		}

		switch result.Verdict {
		case automaguard.VerdictAllow:
			fmt.Printf("  [allow]  %s\n", ev.description)
		case automaguard.VerdictAudit:
			fmt.Printf("  [audit]  %s — %s\n", ev.description, result.ReasonOrDefault())
		case automaguard.VerdictDeny:
			fmt.Fprintf(os.Stderr, "\nBLOCKED by AutomaGuard policy:\n")
			fmt.Fprintf(os.Stderr, "  Event:  %s\n", ev.description)
			fmt.Fprintf(os.Stderr, "  Reason: %s\n", result.ReasonOrDefault())
			for _, v := range result.Violations {
				fmt.Fprintf(os.Stderr, "  Invariant: %s/%s: %s\n",
					v.Proof, v.Invariant, v.Message)
			}
			for _, cv := range result.ConstraintViolations {
				fmt.Fprintf(os.Stderr, "  Constraint: %s on '%s': %d/%d in %dms window\n",
					cv.Kind, cv.Target, cv.Current, cv.Limit, cv.WindowMs)
			}
			os.Exit(1)
		case automaguard.VerdictRedact:
			fmt.Printf("  [redact] %s\n", ev.description)
		}
	}
}

// ── Stress test ───────────────────────────────────────────────────────────────

func runStress(engine *automaguard.Engine) {
	fmt.Println("\n=== AutomaGuard Go Stress Test ===\n")

	var passed, failed int

	check := func(label string, verdict automaguard.Verdict, want automaguard.Verdict) {
		if verdict == want {
			fmt.Printf("  ✓ %s → %s\n", label, verdict)
			passed++
		} else {
			fmt.Fprintf(os.Stderr, "  ✗ %s: got %s, want %s\n", label, verdict, want)
			failed++
		}
	}

	newEngine := func() *automaguard.Engine {
		e, err := automaguard.NewEngine(policyPath())
		if err != nil {
			fmt.Fprintln(os.Stderr, "newEngine:", err)
			os.Exit(1)
		}
		return e
	}

	// ── 1. DDL denial ─────────────────────────────────────────────────────────
	fmt.Println("[1] DDL denial")
	{
		e := newEngine()
		r, _ := e.Evaluate("tool_call", map[string]any{"tool_name": "drop_table"})
		check("drop_table", r.Verdict, automaguard.VerdictDeny)
		r2, _ := e.Evaluate("tool_call", map[string]any{"tool_name": "query_tickets"})
		check("query_tickets", r2.Verdict, automaguard.VerdictAllow)
		e.Close()
	}

	// ── 2. PII access audit ────────────────────────────────────────────────────
	fmt.Println("\n[2] PII data access")
	{
		e := newEngine()
		r, _ := e.Evaluate("data_access", map[string]any{
			"classification": "PII", "record_id": "10042",
		})
		check("data_access PII", r.Verdict, automaguard.VerdictAudit)
		e.Close()
	}

	// ── 3. PII exfiltration temporal invariant ─────────────────────────────────
	fmt.Println("\n[3] PII exfiltration (temporal invariant)")
	{
		e := newEngine()
		e.Evaluate("data_access", map[string]any{ //nolint:errcheck
			"classification": "PII", "record_id": "10042",
		})
		r, _ := e.Evaluate("external_request", map[string]any{
			"domain": "external-firm.com", "method": "POST",
		})
		check("external_request unapproved after PII", r.Verdict, automaguard.VerdictDeny)
		e.Close()
	}

	// ── 4. Approved external request ──────────────────────────────────────────
	fmt.Println("\n[4] Approved external request")
	{
		e := newEngine()
		r, _ := e.Evaluate("external_request", map[string]any{
			"domain": "reports.internal.corp", "method": "POST",
		})
		check("reports.internal.corp", r.Verdict, automaguard.VerdictAllow)
		e.Close()
	}

	// ── 5. Rate limiting ───────────────────────────────────────────────────────
	fmt.Println("\n[5] Rate limiting (20 allowed, 21st denied)")
	{
		e := newEngine()
		allOK := true
		for i := range 20 {
			r, _ := e.Evaluate("data_access", map[string]any{
				"classification": "aggregate", "record_id": i,
			})
			if r.Verdict != automaguard.VerdictAllow {
				fmt.Fprintf(os.Stderr, "  ✗ event %d: got %s, want allow\n", i, r.Verdict)
				failed++
				allOK = false
			}
		}
		if allOK {
			fmt.Printf("  ✓ events 1–20 → allow\n")
			passed += 20
		}
		r21, _ := e.Evaluate("data_access", map[string]any{
			"classification": "aggregate", "record_id": 21,
		})
		check("event 21 (rate limit)", r21.Verdict, automaguard.VerdictDeny)
		e.Close()
	}

	// ── 6. Delete without approval ─────────────────────────────────────────────
	fmt.Println("\n[6] Delete without prior human approval")
	{
		e := newEngine()
		r, _ := e.Evaluate("tool_call", map[string]any{
			"tool_name": "delete_record", "account_id": "10042",
		})
		check("delete_record without approval", r.Verdict, automaguard.VerdictDeny)
		e.Close()
	}

	fmt.Printf("\n%s\n", "────────────────────────────────────────")
	fmt.Printf("Stress test: %d passed, %d failed\n", passed, failed)
	if failed > 0 {
		os.Exit(1)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
