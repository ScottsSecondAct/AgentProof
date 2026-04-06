import { withGuard } from '../js/vercel-ai';
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
  reason: 'Tool "send_pii" is not allowed',
  triggered_rules: [0],
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

// ── Helpers ───────────────────────────────────────────────────────────────────

function makeToolCall(toolName: string, args: Record<string, unknown> = {}, toolCallId = 'tc-1') {
  return { type: 'tool-call' as const, toolCallId, toolName, args };
}

function makeModel(overrides: {
  doGenerate?: jest.Mock;
  doStream?: jest.Mock;
} = {}) {
  return {
    doGenerate: overrides.doGenerate ?? jest.fn().mockResolvedValue({ toolCalls: [] }),
    doStream: overrides.doStream ?? jest.fn().mockResolvedValue({
      stream: (async function* () {})(),
    }),
  };
}

async function collectStream(stream: AsyncIterable<unknown>): Promise<unknown[]> {
  const chunks: unknown[] = [];
  for await (const chunk of stream) {
    chunks.push(chunk);
  }
  return chunks;
}

// ── withGuard() returns proxy ─────────────────────────────────────────────────

describe('withGuard()', () => {
  it('returns an object with the same interface as the model', () => {
    const model = makeModel();
    const guarded = withGuard(model, { policy: 'guard.aegisc' });
    expect(typeof guarded.doGenerate).toBe('function');
    expect(typeof guarded.doStream).toBe('function');
  });

  it('passes through non-intercepted properties transparently', () => {
    const model = { ...makeModel(), specificationVersion: 'v1', modelId: 'gpt-4o' };
    const guarded = withGuard(model, { policy: 'guard.aegisc' });
    expect((guarded as any).specificationVersion).toBe('v1');
    expect((guarded as any).modelId).toBe('gpt-4o');
  });
});

// ── doGenerate: allow ─────────────────────────────────────────────────────────

describe('withGuard() doGenerate', () => {
  it('returns the response unchanged when there are no tool calls', async () => {
    const response = { content: 'hello', toolCalls: [] };
    const model = makeModel({ doGenerate: jest.fn().mockResolvedValue(response) });
    const guarded = withGuard(model, { policy: 'guard.aegisc' });

    const result = await guarded.doGenerate({});
    expect(result).toEqual(response);
    expect(mockEvaluate).not.toHaveBeenCalled();
  });

  it('evaluates each tool call when the response contains them', async () => {
    const tc1 = makeToolCall('search', { query: 'test' }, 'tc-1');
    const tc2 = makeToolCall('summarise', {}, 'tc-2');
    const model = makeModel({
      doGenerate: jest.fn().mockResolvedValue({ toolCalls: [tc1, tc2] }),
    });
    const guarded = withGuard(model, { policy: 'guard.aegisc' });

    await guarded.doGenerate({});

    expect(mockEvaluate).toHaveBeenCalledTimes(2);
    expect(mockEvaluate).toHaveBeenCalledWith('tool_call', {
      tool_name: 'search',
      tool_call_id: 'tc-1',
      arguments: { query: 'test' },
    });
    expect(mockEvaluate).toHaveBeenCalledWith('tool_call', {
      tool_name: 'summarise',
      tool_call_id: 'tc-2',
      arguments: {},
    });
  });

  it('throws EnforcementError by default when a tool call is denied', async () => {
    mockEvaluate.mockReturnValue(denyResult);
    const model = makeModel({
      doGenerate: jest.fn().mockResolvedValue({
        toolCalls: [makeToolCall('send_pii')],
      }),
    });
    const guarded = withGuard(model, { policy: 'guard.aegisc' });

    await expect(guarded.doGenerate({})).rejects.toThrow(EnforcementError);
  });

  it('calls onDeny callback instead of throwing when provided', async () => {
    mockEvaluate.mockReturnValue(denyResult);
    const onDeny = jest.fn();
    const model = makeModel({
      doGenerate: jest.fn().mockResolvedValue({
        toolCalls: [makeToolCall('send_pii')],
      }),
    });
    const guarded = withGuard(model, { policy: 'guard.aegisc', onDeny });

    await guarded.doGenerate({});
    expect(onDeny).toHaveBeenCalledWith(denyResult, 'send_pii');
  });

  it('calls onAudit callback on audit verdict', async () => {
    mockEvaluate.mockReturnValue(auditResult);
    const onAudit = jest.fn();
    const model = makeModel({
      doGenerate: jest.fn().mockResolvedValue({
        toolCalls: [makeToolCall('get_profile')],
      }),
    });
    const guarded = withGuard(model, { policy: 'guard.aegisc', onAudit });

    await guarded.doGenerate({});
    expect(onAudit).toHaveBeenCalledWith(auditResult, 'get_profile');
  });

  it('forwards the original options to the underlying model', async () => {
    const doGenerate = jest.fn().mockResolvedValue({ toolCalls: [] });
    const model = makeModel({ doGenerate });
    const guarded = withGuard(model, { policy: 'guard.aegisc' });

    const opts = { prompt: 'hello', maxTokens: 100 };
    await guarded.doGenerate(opts);

    expect(doGenerate).toHaveBeenCalledWith(opts);
  });
});

// ── doStream: allow ───────────────────────────────────────────────────────────

describe('withGuard() doStream', () => {
  it('passes non-tool-call chunks through unchanged', async () => {
    const chunks = [
      { type: 'text-delta', textDelta: 'hello' },
      { type: 'text-delta', textDelta: ' world' },
      { type: 'finish', finishReason: 'stop' },
    ];
    async function* chunkStream() { for (const c of chunks) yield c; }

    const model = makeModel({
      doStream: jest.fn().mockResolvedValue({ stream: chunkStream() }),
    });
    const guarded = withGuard(model, { policy: 'guard.aegisc' });

    const { stream } = await guarded.doStream({});
    const collected = await collectStream(stream);

    expect(collected).toEqual(chunks);
    expect(mockEvaluate).not.toHaveBeenCalled();
  });

  it('evaluates tool-call chunks as they arrive', async () => {
    const tc = { type: 'tool-call', toolCallId: 'tc-1', toolName: 'search', args: {} };
    async function* chunkStream() { yield tc; }

    const model = makeModel({
      doStream: jest.fn().mockResolvedValue({ stream: chunkStream() }),
    });
    const guarded = withGuard(model, { policy: 'guard.aegisc' });

    const { stream } = await guarded.doStream({});
    await collectStream(stream);

    expect(mockEvaluate).toHaveBeenCalledWith('tool_call', {
      tool_name: 'search',
      tool_call_id: 'tc-1',
      arguments: {},
    });
  });

  it('throws EnforcementError mid-stream when a tool call is denied', async () => {
    mockEvaluate.mockReturnValue(denyResult);
    const tc = { type: 'tool-call', toolCallId: 'tc-1', toolName: 'send_pii', args: {} };
    async function* chunkStream() { yield tc; }

    const model = makeModel({
      doStream: jest.fn().mockResolvedValue({ stream: chunkStream() }),
    });
    const guarded = withGuard(model, { policy: 'guard.aegisc' });

    const { stream } = await guarded.doStream({});
    await expect(collectStream(stream)).rejects.toThrow(EnforcementError);
  });

  it('calls onDeny callback instead of throwing mid-stream', async () => {
    mockEvaluate.mockReturnValue(denyResult);
    const onDeny = jest.fn();
    const tc = { type: 'tool-call', toolCallId: 'tc-1', toolName: 'send_pii', args: {} };
    async function* chunkStream() { yield tc; }

    const model = makeModel({
      doStream: jest.fn().mockResolvedValue({ stream: chunkStream() }),
    });
    const guarded = withGuard(model, { policy: 'guard.aegisc', onDeny });

    const { stream } = await guarded.doStream({});
    await collectStream(stream);

    expect(onDeny).toHaveBeenCalledWith(denyResult, 'send_pii');
  });

  it('calls onAudit for audited tool-call chunks', async () => {
    mockEvaluate.mockReturnValue(auditResult);
    const onAudit = jest.fn();
    const tc = { type: 'tool-call', toolCallId: 'tc-1', toolName: 'get_profile', args: {} };
    async function* chunkStream() { yield tc; }

    const model = makeModel({
      doStream: jest.fn().mockResolvedValue({ stream: chunkStream() }),
    });
    const guarded = withGuard(model, { policy: 'guard.aegisc', onAudit });

    const { stream } = await guarded.doStream({});
    await collectStream(stream);

    expect(onAudit).toHaveBeenCalledWith(auditResult, 'get_profile');
  });

  it('preserves non-stream properties of the stream result', async () => {
    async function* chunkStream() {}
    const model = makeModel({
      doStream: jest.fn().mockResolvedValue({
        stream: chunkStream(),
        rawResponse: { headers: {} },
      }),
    });
    const guarded = withGuard(model, { policy: 'guard.aegisc' });

    const result = await guarded.doStream({});
    expect((result as any).rawResponse).toEqual({ headers: {} });
  });

  it('forwards the original options to the underlying model', async () => {
    const doStream = jest.fn().mockResolvedValue({ stream: (async function* () {})() });
    const model = makeModel({ doStream });
    const guarded = withGuard(model, { policy: 'guard.aegisc' });

    const opts = { prompt: 'hello' };
    await guarded.doStream(opts);

    expect(doStream).toHaveBeenCalledWith(opts);
  });
});
