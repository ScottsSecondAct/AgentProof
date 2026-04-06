import { enforce } from '../js/openai';
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
  reason: 'PII access audited',
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

function makeCompletion(toolCalls?: Array<{
  id?: string;
  function?: { name: string; arguments: string };
}>) {
  return {
    id: 'chatcmpl-test',
    choices: [
      {
        message: {
          role: 'assistant',
          content: null,
          tool_calls: toolCalls?.map((tc) => ({
            id: tc.id ?? 'call-1',
            type: 'function',
            function: tc.function,
          })),
        },
        finish_reason: toolCalls ? 'tool_calls' : 'stop',
      },
    ],
  };
}

function makeOpenAIClient(createReturn: unknown) {
  return {
    chat: {
      completions: {
        create: jest.fn().mockResolvedValue(createReturn),
      },
    },
  };
}

// ── enforce() ─────────────────────────────────────────────────────────────────

describe('enforce()', () => {
  it('returns a proxy with the same interface', () => {
    const client = makeOpenAIClient(makeCompletion());
    const guarded = enforce(client, { policy: 'guard.aegisc' });
    expect(guarded).toBeDefined();
    expect(guarded.chat).toBeDefined();
    expect(guarded.chat.completions).toBeDefined();
    expect(typeof guarded.chat.completions.create).toBe('function');
  });

  it('passes through completions with no tool calls without calling evaluate', async () => {
    const completion = makeCompletion(); // no tool_calls
    const client = makeOpenAIClient(completion);
    const guarded = enforce(client, { policy: 'guard.aegisc' });

    const result = await guarded.chat.completions.create({});
    expect(result).toEqual(completion);
    expect(mockEvaluate).not.toHaveBeenCalled();
  });

  it('evaluates tool calls in assistant messages', async () => {
    const completion = makeCompletion([
      {
        id: 'call-1',
        function: {
          name: 'send_email',
          arguments: JSON.stringify({ to: 'user@example.com', subject: 'Hi' }),
        },
      },
    ]);
    const client = makeOpenAIClient(completion);
    const guarded = enforce(client, { policy: 'guard.aegisc' });

    await guarded.chat.completions.create({});

    expect(mockEvaluate).toHaveBeenCalledWith('tool_call', {
      tool_name: 'send_email',
      tool_call_id: 'call-1',
      arguments: { to: 'user@example.com', subject: 'Hi' },
    });
  });

  it('evaluates all tool calls when multiple are present', async () => {
    const completion = makeCompletion([
      { id: 'c1', function: { name: 'search', arguments: '{}' } },
      { id: 'c2', function: { name: 'summarise', arguments: '{}' } },
    ]);
    const client = makeOpenAIClient(completion);
    const guarded = enforce(client, { policy: 'guard.aegisc' });

    await guarded.chat.completions.create({});

    expect(mockEvaluate).toHaveBeenCalledTimes(2);
  });

  it('throws EnforcementError by default when a tool call is denied', async () => {
    mockEvaluate.mockReturnValue(denyResult);

    const completion = makeCompletion([
      { id: 'c1', function: { name: 'send_pii', arguments: '{}' } },
    ]);
    const client = makeOpenAIClient(completion);
    const guarded = enforce(client, { policy: 'guard.aegisc' });

    await expect(guarded.chat.completions.create({})).rejects.toThrow(
      EnforcementError
    );
  });

  it('calls onDeny callback instead of throwing when provided', async () => {
    mockEvaluate.mockReturnValue(denyResult);
    const onDeny = jest.fn();

    const completion = makeCompletion([
      { id: 'c1', function: { name: 'send_pii', arguments: '{}' } },
    ]);
    const client = makeOpenAIClient(completion);
    const guarded = enforce(client, { policy: 'guard.aegisc', onDeny });

    await guarded.chat.completions.create({});
    expect(onDeny).toHaveBeenCalledTimes(1);
  });

  it('calls onAudit callback on audit verdict', async () => {
    mockEvaluate.mockReturnValue(auditResult);
    const onAudit = jest.fn();

    const completion = makeCompletion([
      { id: 'c1', function: { name: 'get_profile', arguments: '{}' } },
    ]);
    const client = makeOpenAIClient(completion);
    const guarded = enforce(client, { policy: 'guard.aegisc', onAudit });

    await guarded.chat.completions.create({});
    expect(onAudit).toHaveBeenCalledTimes(1);
  });

  it('handles tool function arguments that are not valid JSON', async () => {
    const completion = makeCompletion([
      { id: 'c1', function: { name: 'cmd', arguments: 'not json' } },
    ]);
    const client = makeOpenAIClient(completion);
    const guarded = enforce(client, { policy: 'guard.aegisc' });

    await guarded.chat.completions.create({});
    expect(mockEvaluate).toHaveBeenCalledWith('tool_call', {
      tool_name: 'cmd',
      tool_call_id: 'c1',
      arguments: 'not json',
    });
  });

  it('proxies non-chat properties transparently', () => {
    const client = { ...makeOpenAIClient({}), models: { list: jest.fn() } };
    const guarded = enforce(client, { policy: 'guard.aegisc' });
    expect(guarded.models).toBe(client.models);
  });

  it('forwards the original create arguments to the underlying client', async () => {
    const completion = makeCompletion();
    const createSpy = jest.fn().mockResolvedValue(completion);
    const client = { chat: { completions: { create: createSpy } } };
    const guarded = enforce(client, { policy: 'guard.aegisc' });

    const args = { model: 'gpt-4o', messages: [{ role: 'user', content: 'hi' }] };
    await guarded.chat.completions.create(args);

    expect(createSpy).toHaveBeenCalledWith(args);
  });
});
