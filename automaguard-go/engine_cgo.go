package automaguard

/*
#cgo linux,amd64   LDFLAGS: -L${SRCDIR}/native/linux_amd64   -laegis -Wl,-rpath,${SRCDIR}/native/linux_amd64
#cgo darwin,arm64  LDFLAGS: -L${SRCDIR}/native/darwin_arm64  -laegis -Wl,-rpath,${SRCDIR}/native/darwin_arm64
#cgo darwin,amd64  LDFLAGS: -L${SRCDIR}/native/darwin_amd64  -laegis -Wl,-rpath,${SRCDIR}/native/darwin_amd64
#cgo windows,amd64 LDFLAGS: -L${SRCDIR}/native/windows_amd64 -laegis
#cgo CFLAGS: -I${SRCDIR}/include
#include "aegis.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"unsafe"
)

// Engine is a loaded AutomaGuard policy engine.
//
// Load once at agent startup with NewEngine or NewEngineFromBytes, then call
// Evaluate for each agent event.  Engine is safe for concurrent use — all C
// calls are serialised by an internal mutex.
//
// Always call Close when done to release the native handle.
type Engine struct {
	ptr  *C.struct_AegisEngine
	mu   sync.Mutex
	name string
}

// NewEngine loads a compiled .aegisc policy from the given file path.
func NewEngine(path string) (*Engine, error) {
	cpath := C.CString(path)
	defer C.free(unsafe.Pointer(cpath))

	ptr := C.aegis_engine_from_file(cpath)
	if ptr == nil {
		return nil, fmt.Errorf("automaguard: failed to load policy from %q: %s",
			path, lastError())
	}

	return &Engine{ptr: ptr, name: path}, nil
}

// NewEngineFromBytes loads a compiled .aegisc policy from an in-memory byte
// slice.  Useful when the policy is embedded with //go:embed.
func NewEngineFromBytes(data []byte) (*Engine, error) {
	if len(data) == 0 {
		return nil, errors.New("automaguard: policy data must not be empty")
	}
	ptr := C.aegis_engine_from_bytes(
		(*C.uchar)(unsafe.Pointer(&data[0])),
		C.uintptr_t(len(data)),
	)
	if ptr == nil {
		return nil, fmt.Errorf("automaguard: failed to load policy from bytes: %s",
			lastError())
	}
	return &Engine{ptr: ptr, name: "<bytes>"}, nil
}

// Evaluate evaluates a single agent event against the loaded policy.
//
//   - eventType is the event kind string, e.g. "tool_call", "data_access",
//     "external_request".
//   - fields is an optional map of event-specific metadata.  Values must be
//     JSON-serialisable.  Pass nil or an empty map for events with no fields.
//
// Returns the PolicyResult on success, or an error if the native call fails.
// A Deny verdict is returned as a normal result (not an error); callers that
// want automatic error propagation can use EvaluateOrErr.
func (e *Engine) Evaluate(eventType string, fields map[string]any) (*PolicyResult, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.ptr == nil {
		return nil, errors.New("automaguard: engine has been closed")
	}

	cEventType := C.CString(eventType)
	defer C.free(unsafe.Pointer(cEventType))

	var cFieldsJSON *C.char
	if len(fields) > 0 {
		b, err := json.Marshal(fields)
		if err != nil {
			return nil, fmt.Errorf("automaguard: failed to marshal fields: %w", err)
		}
		cFieldsJSON = C.CString(string(b))
		defer C.free(unsafe.Pointer(cFieldsJSON))
	}

	resultPtr := C.aegis_engine_evaluate(e.ptr, cEventType, cFieldsJSON)
	if resultPtr == nil {
		return nil, fmt.Errorf("automaguard: evaluate failed: %s", lastError())
	}
	defer C.aegis_result_free(resultPtr)

	result, err := parseResult(C.GoString(resultPtr))
	if err != nil {
		return nil, fmt.Errorf("automaguard: failed to parse result JSON: %w", err)
	}
	return result, nil
}

// EvaluateOrErr is a convenience wrapper around Evaluate that additionally
// returns an *EnforcementError when the verdict is Deny.
func (e *Engine) EvaluateOrErr(eventType string, fields map[string]any) (*PolicyResult, error) {
	result, err := e.Evaluate(eventType, fields)
	if err != nil {
		return nil, err
	}
	if result.IsDenied() {
		return result, &EnforcementError{Result: result}
	}
	return result, nil
}

// Close releases the native engine handle.  The Engine must not be used after
// Close returns.  Calling Close more than once is safe.
func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.ptr != nil {
		C.aegis_engine_free(e.ptr)
		e.ptr = nil
	}
}

// lastError reads the thread-local error string set by the native library.
// The returned string is only valid until the next CGO call on this goroutine.
func lastError() string {
	ptr := C.aegis_last_error()
	if ptr == nil {
		return "unknown error"
	}
	return C.GoString(ptr)
}
