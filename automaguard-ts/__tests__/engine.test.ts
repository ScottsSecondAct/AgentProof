import {
  PolicyEngine,
  EnforcementError,
  __setNativeBinding,
  type PolicyResult,
  type EngineStatus,
} from '../js/index';

// ── Mock native binding ───────────────────────────────────────────────────────

const allowResult: PolicyResult = {
  verdict: 'allow',
  reason: null,
  triggered_rules: [],
  violations: [],
  constraint_violations: [],
  actions: [],
  latency_us: 3,
};

const denyResult: PolicyResult = {
  verdict: 'deny',
  reason: 'Tool "exec" is not allowed',
  triggered_rules: [0],
  violations: [],
  constraint_violations: [],
  actions: [],
  latency_us: 4,
};

const mockStatus: EngineStatus = {
  policy_name: 'TestPolicy',
  severity: 'High',
  total_rules: 2,
  total_state_machines: 1,
  active_state_machines: 1,
  violated_state_machines: 0,
  satisfied_state_machines: 0,
  total_constraints: 0,
  events_processed: 0,
};

function makeMockNativeEngine(overrides: Partial<{
  evaluate: jest.Mock;
  setContext: jest.Mock;
  setConfig: jest.Mock;
  reset: jest.Mock;
  status: jest.Mock;
  policyName: string;
  eventCount: number;
}> = {}) {
  return {
    evaluate: overrides.evaluate ?? jest.fn().mockReturnValue(allowResult),
    setContext: overrides.setContext ?? jest.fn(),
    setConfig: overrides.setConfig ?? jest.fn(),
    reset: overrides.reset ?? jest.fn(),
    status: overrides.status ?? jest.fn().mockReturnValue(mockStatus),
    policyName: overrides.policyName ?? 'TestPolicy',
    eventCount: overrides.eventCount ?? 0,
  };
}

beforeEach(() => {
  const mockNativeEngine = makeMockNativeEngine();
  __setNativeBinding({
    PolicyEngine: {
      fromFile: jest.fn().mockReturnValue(mockNativeEngine),
      fromBytes: jest.fn().mockReturnValue(mockNativeEngine),
    },
  } as any);
});

// ── EnforcementError ──────────────────────────────────────────────────────────

describe('EnforcementError', () => {
  it('carries the full policy result', () => {
    const err = new EnforcementError(denyResult);
    expect(err.result).toBe(denyResult);
  });

  it('uses the denial reason as the error message', () => {
    const err = new EnforcementError(denyResult);
    expect(err.message).toBe('Tool "exec" is not allowed');
  });

  it('falls back to a generic message when reason is null', () => {
    const result: PolicyResult = { ...denyResult, reason: null };
    const err = new EnforcementError(result);
    expect(err.message).toBe('Policy denied: deny');
  });

  it('is an instance of Error', () => {
    const err = new EnforcementError(denyResult);
    expect(err).toBeInstanceOf(Error);
  });

  it('sets the name to EnforcementError', () => {
    const err = new EnforcementError(denyResult);
    expect(err.name).toBe('EnforcementError');
  });

  it('can be caught as an Error', () => {
    expect(() => {
      throw new EnforcementError(denyResult);
    }).toThrow(Error);
  });
});

// ── PolicyEngine.fromFile ─────────────────────────────────────────────────────

describe('PolicyEngine.fromFile', () => {
  it('constructs an engine from a file path', () => {
    const engine = PolicyEngine.fromFile('test.aegisc');
    expect(engine).toBeInstanceOf(PolicyEngine);
  });

  it('delegates to the native fromFile factory', () => {
    const native = (require('../js/index') as any);
    // Reset with a spy
    const spy = jest.fn().mockReturnValue(makeMockNativeEngine());
    __setNativeBinding({
      PolicyEngine: { fromFile: spy, fromBytes: jest.fn() },
    } as any);
    PolicyEngine.fromFile('guard.aegisc');
    expect(spy).toHaveBeenCalledWith('guard.aegisc');
  });
});

// ── PolicyEngine.fromBytes ────────────────────────────────────────────────────

describe('PolicyEngine.fromBytes', () => {
  it('constructs an engine from a buffer', () => {
    const engine = PolicyEngine.fromBytes(Buffer.from([0xae, 0x61]));
    expect(engine).toBeInstanceOf(PolicyEngine);
  });
});

// ── PolicyEngine.evaluate ─────────────────────────────────────────────────────

describe('PolicyEngine.evaluate', () => {
  it('returns the result from the native binding', () => {
    const nativeEngine = makeMockNativeEngine({
      evaluate: jest.fn().mockReturnValue(denyResult),
    });
    __setNativeBinding({
      PolicyEngine: {
        fromFile: jest.fn().mockReturnValue(nativeEngine),
        fromBytes: jest.fn(),
      },
    } as any);

    const engine = PolicyEngine.fromFile('test.aegisc');
    const result = engine.evaluate('tool_call', { tool_name: 'exec' });

    expect(result.verdict).toBe('deny');
    expect(result.reason).toBe('Tool "exec" is not allowed');
    expect(nativeEngine.evaluate).toHaveBeenCalledWith('tool_call', { tool_name: 'exec' });
  });

  it('forwards event type and fields to the native engine', () => {
    const nativeEngine = makeMockNativeEngine();
    __setNativeBinding({
      PolicyEngine: {
        fromFile: jest.fn().mockReturnValue(nativeEngine),
        fromBytes: jest.fn(),
      },
    } as any);

    const engine = PolicyEngine.fromFile('test.aegisc');
    engine.evaluate('data_access', { classification: 'PII', record_id: '42' });

    expect(nativeEngine.evaluate).toHaveBeenCalledWith('data_access', {
      classification: 'PII',
      record_id: '42',
    });
  });

  it('can be called with no fields', () => {
    const nativeEngine = makeMockNativeEngine();
    __setNativeBinding({
      PolicyEngine: {
        fromFile: jest.fn().mockReturnValue(nativeEngine),
        fromBytes: jest.fn(),
      },
    } as any);

    const engine = PolicyEngine.fromFile('test.aegisc');
    engine.evaluate('heartbeat');

    expect(nativeEngine.evaluate).toHaveBeenCalledWith('heartbeat', undefined);
  });
});

// ── PolicyEngine.policyName / eventCount ──────────────────────────────────────

describe('PolicyEngine getters', () => {
  it('returns the policy name', () => {
    const nativeEngine = makeMockNativeEngine({ policyName: 'MyGuard' });
    __setNativeBinding({
      PolicyEngine: {
        fromFile: jest.fn().mockReturnValue(nativeEngine),
        fromBytes: jest.fn(),
      },
    } as any);
    const engine = PolicyEngine.fromFile('test.aegisc');
    expect(engine.policyName).toBe('MyGuard');
  });

  it('returns the event count', () => {
    const nativeEngine = makeMockNativeEngine({ eventCount: 7 });
    __setNativeBinding({
      PolicyEngine: {
        fromFile: jest.fn().mockReturnValue(nativeEngine),
        fromBytes: jest.fn(),
      },
    } as any);
    const engine = PolicyEngine.fromFile('test.aegisc');
    expect(engine.eventCount).toBe(7);
  });
});

// ── PolicyEngine.reset ────────────────────────────────────────────────────────

describe('PolicyEngine.reset', () => {
  it('delegates to the native reset method', () => {
    const nativeEngine = makeMockNativeEngine();
    __setNativeBinding({
      PolicyEngine: {
        fromFile: jest.fn().mockReturnValue(nativeEngine),
        fromBytes: jest.fn(),
      },
    } as any);
    const engine = PolicyEngine.fromFile('test.aegisc');
    engine.reset();
    expect(nativeEngine.reset).toHaveBeenCalledTimes(1);
  });
});

// ── PolicyEngine.status ───────────────────────────────────────────────────────

describe('PolicyEngine.status', () => {
  it('returns the engine status snapshot', () => {
    const nativeEngine = makeMockNativeEngine({
      status: jest.fn().mockReturnValue(mockStatus),
    });
    __setNativeBinding({
      PolicyEngine: {
        fromFile: jest.fn().mockReturnValue(nativeEngine),
        fromBytes: jest.fn(),
      },
    } as any);
    const engine = PolicyEngine.fromFile('test.aegisc');
    const status = engine.status();
    expect(status.policy_name).toBe('TestPolicy');
    expect(status.total_rules).toBe(2);
  });
});

// ── PolicyEngine.setContext / setConfig ───────────────────────────────────────

describe('PolicyEngine context and config', () => {
  it('delegates setContext to native', () => {
    const nativeEngine = makeMockNativeEngine();
    __setNativeBinding({
      PolicyEngine: {
        fromFile: jest.fn().mockReturnValue(nativeEngine),
        fromBytes: jest.fn(),
      },
    } as any);
    const engine = PolicyEngine.fromFile('test.aegisc');
    engine.setContext('user_role', 'admin');
    expect(nativeEngine.setContext).toHaveBeenCalledWith('user_role', 'admin');
  });

  it('delegates setConfig to native', () => {
    const nativeEngine = makeMockNativeEngine();
    __setNativeBinding({
      PolicyEngine: {
        fromFile: jest.fn().mockReturnValue(nativeEngine),
        fromBytes: jest.fn(),
      },
    } as any);
    const engine = PolicyEngine.fromFile('test.aegisc');
    engine.setConfig('max_retries', 3);
    expect(nativeEngine.setConfig).toHaveBeenCalledWith('max_retries', 3);
  });
});
