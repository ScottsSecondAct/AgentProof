//go:build !cgo

package automaguard

import "errors"

// errCgoRequired is returned by all engine operations when the package is
// built without cgo (CGO_ENABLED=0).
var errCgoRequired = errors.New(
	"automaguard: cgo is required; rebuild with CGO_ENABLED=1 and libaegis in native/<platform>/",
)

// Engine is a stub that satisfies the package API when cgo is disabled.
// All methods return errCgoRequired.
type Engine struct{}

// NewEngine is a no-op stub that always returns errCgoRequired.
func NewEngine(_ string) (*Engine, error) { return nil, errCgoRequired }

// NewEngineFromBytes is a no-op stub that always returns errCgoRequired.
func NewEngineFromBytes(_ []byte) (*Engine, error) { return nil, errCgoRequired }

// Evaluate is a no-op stub that always returns errCgoRequired.
func (e *Engine) Evaluate(_ string, _ map[string]any) (*PolicyResult, error) {
	return nil, errCgoRequired
}

// EvaluateOrErr is a no-op stub that always returns errCgoRequired.
func (e *Engine) EvaluateOrErr(_ string, _ map[string]any) (*PolicyResult, error) {
	return nil, errCgoRequired
}

// Close is a no-op.
func (e *Engine) Close() {}
