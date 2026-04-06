import { AutomaGuardCallbackHandler } from '../js/langchain';
import { __setNativeBinding, EnforcementError, type PolicyResult } from '../js/index';

// ── Mock native binding ───────────────────────────────────────────────────────

const allowResult: PolicyResult = {
  verdict: 'allow',
  reason: null,
  triggered_rules: [],
  violations: [],
  constraint_violations: [],
  actions: [],
  latency_us: 2,
};

const denyResult: PolicyResult = {
  verdict: 'deny',
  reason: 'Tool "exec" is not allowed',
  triggered_rules: [1],
  violations: [],
  constraint_violations: [],
  actions: [],
  latency_us: 3,
};

const auditResult: PolicyResult = {
  verdict: 'audit',
  reason: 'PII record accessed',
  triggered_rules: [0],
  violations: [],
  constraint_violations: [],
  actions: [],
  latency_us: 2,
};

let mockEvaluate: jest.Mock;

beforeEach(() => {
  mockEvaluate = jest.fn().mockReturnValue(allowResult);

  __setNativeBinding({
    PolicyEngine: {
      fromFile: jest.fn().mockReturnValue({
        evaluate: mockEvaluate,
        setContext: jest.fn(),
        setConfig: jest.fn(),
        reset: jest.fn(),
        status: jest.fn(),
        policyName: 'TestPolicy',
        eventCount: 0,
      }),
      fromBytes: jest.fn(),
    },
  } as any);
});

// ── Constructor ───────────────────────────────────────────────────────────────

describe('AutomaGuardCallbackHandler constructor', () => {
  it('loads the policy engine from the given path', () => {
    const handler = new AutomaGuardCallbackHandler({ policy: 'guard.aegisc' });
    expect(handler.policyEngine).toBeDefined();
  });

  it('has the expected name', () => {
    const handler = new AutomaGuardCallbackHandler({ policy: 'guard.aegisc' });
    expect(handler.name).toBe('AutomaGuardCallbackHandler');
  });
});

// ── handleToolStart ───────────────────────────────────────────────────────────

describe('handleToolStart', () => {
  it('evaluates the tool call as a tool_call event', () => {
    const handler = new AutomaGuardCallbackHandler({ policy: 'guard.aegisc' });
    handler.handleToolStart({ name: 'search' }, '{"query":"test"}', 'run-1');

    expect(mockEvaluate).toHaveBeenCalledWith('tool_call', {
      tool_name: 'search',
      arguments: { query: 'test' },
    });
  });

  it('uses "unknown" as tool_name when tool has no name', () => {
    const handler = new AutomaGuardCallbackHandler({ policy: 'guard.aegisc' });
    handler.handleToolStart({}, '{}', 'run-1');

    expect(mockEvaluate).toHaveBeenCalledWith('tool_call', {
      tool_name: 'unknown',
      arguments: {},
    });
  });

  it('keeps input as string when it is not valid JSON', () => {
    const handler = new AutomaGuardCallbackHandler({ policy: 'guard.aegisc' });
    handler.handleToolStart({ name: 'cmd' }, 'plain text input', 'run-1');

    expect(mockEvaluate).toHaveBeenCalledWith('tool_call', {
      tool_name: 'cmd',
      arguments: 'plain text input',
    });
  });

  it('throws EnforcementError on deny by default', () => {
    mockEvaluate.mockReturnValue(denyResult);
    const handler = new AutomaGuardCallbackHandler({ policy: 'guard.aegisc' });

    expect(() => {
      handler.handleToolStart({ name: 'exec' }, '{}', 'run-1');
    }).toThrow(EnforcementError);
  });

  it('calls onDeny callback instead of throwing when provided', () => {
    mockEvaluate.mockReturnValue(denyResult);
    const onDeny = jest.fn();
    const handler = new AutomaGuardCallbackHandler({
      policy: 'guard.aegisc',
      onDeny,
    });

    handler.handleToolStart({ name: 'exec' }, '{}', 'run-1');
    expect(onDeny).toHaveBeenCalledWith(denyResult, 'exec');
  });

  it('calls onAudit callback on audit verdict', () => {
    mockEvaluate.mockReturnValue(auditResult);
    const onAudit = jest.fn();
    const handler = new AutomaGuardCallbackHandler({
      policy: 'guard.aegisc',
      onAudit,
    });

    handler.handleToolStart({ name: 'get_profile' }, '{}', 'run-1');
    expect(onAudit).toHaveBeenCalledWith(auditResult, 'get_profile');
  });

  it('does nothing on allow verdict', () => {
    const onDeny = jest.fn();
    const onAudit = jest.fn();
    const handler = new AutomaGuardCallbackHandler({
      policy: 'guard.aegisc',
      onDeny,
      onAudit,
    });

    handler.handleToolStart({ name: 'search' }, '{}', 'run-1');
    expect(onDeny).not.toHaveBeenCalled();
    expect(onAudit).not.toHaveBeenCalled();
  });
});

// ── handleToolEnd ─────────────────────────────────────────────────────────────

describe('handleToolEnd', () => {
  it('evaluates the output as a tool_result event', () => {
    const handler = new AutomaGuardCallbackHandler({ policy: 'guard.aegisc' });
    handler.handleToolEnd('{"status":"ok"}', 'run-1');

    expect(mockEvaluate).toHaveBeenCalledWith('tool_result', {
      output: { status: 'ok' },
    });
  });

  it('keeps output as string when it is not valid JSON', () => {
    const handler = new AutomaGuardCallbackHandler({ policy: 'guard.aegisc' });
    handler.handleToolEnd('plain output', 'run-1');

    expect(mockEvaluate).toHaveBeenCalledWith('tool_result', {
      output: 'plain output',
    });
  });

  it('throws EnforcementError when tool result is denied', () => {
    mockEvaluate.mockReturnValue(denyResult);
    const handler = new AutomaGuardCallbackHandler({ policy: 'guard.aegisc' });

    expect(() => {
      handler.handleToolEnd('{}', 'run-1');
    }).toThrow(EnforcementError);
  });
});

// ── handleToolError ───────────────────────────────────────────────────────────

describe('handleToolError', () => {
  it('fires a tool_error event', () => {
    const handler = new AutomaGuardCallbackHandler({ policy: 'guard.aegisc' });
    handler.handleToolError(new Error('boom'), 'run-1');

    expect(mockEvaluate).toHaveBeenCalledWith('tool_error', {});
  });
});
