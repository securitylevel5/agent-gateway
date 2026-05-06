const assert = require('node:assert');
const { test } = require('node:test');
const {
  translateOtlpLogs,
  translateJaegerTraces,
  translateOtlpTraces,
} = require('./translate');

test('translates a single OTLP log record to one event', () => {
  const payload = {
    resourceLogs: [{
      resource: {
        attributes: [{ key: 'service.name', value: { stringValue: 'agent-gateway' } }],
      },
      scopeLogs: [{
        logRecords: [{
          timeUnixNano: '1713816000000000000',
          eventName: 'request.denied',
          attributes: [
            { key: 'agent.id',       value: { stringValue: 'agent-abc' } },
            { key: 'http.host',      value: { stringValue: 'docstore.example.com' } },
            { key: 'denial.reason',  value: { stringValue: 'permission denied' } },
          ],
        }],
      }],
    }],
  };

  const events = translateOtlpLogs(payload);
  assert.strictEqual(events.length, 1);
  assert.deepStrictEqual(events[0], {
    source: 'agent-gateway',
    event_type: 'request.denied',
    timestamp: '2024-04-22T20:00:00.000Z',
    attributes: {
      'agent.id': 'agent-abc',
      'http.host': 'docstore.example.com',
      'denial.reason': 'permission denied',
    },
  });
});

test('returns empty array for empty payload', () => {
  assert.deepStrictEqual(translateOtlpLogs({}), []);
  assert.deepStrictEqual(translateOtlpLogs({ resourceLogs: [] }), []);
});

test('handles multiple resources and multiple records', () => {
  const payload = {
    resourceLogs: [
      {
        resource: { attributes: [{ key: 'service.name', value: { stringValue: 'svc-a' } }] },
        scopeLogs: [{
          logRecords: [
            { timeUnixNano: '1000000000', eventName: 'a.one', attributes: [] },
            { timeUnixNano: '2000000000', eventName: 'a.two', attributes: [] },
          ],
        }],
      },
      {
        resource: { attributes: [{ key: 'service.name', value: { stringValue: 'svc-b' } }] },
        scopeLogs: [{
          logRecords: [
            { timeUnixNano: '3000000000', eventName: 'b.one', attributes: [] },
          ],
        }],
      },
    ],
  };
  const events = translateOtlpLogs(payload);
  assert.strictEqual(events.length, 3);
  assert.strictEqual(events[0].source, 'svc-a');
  assert.strictEqual(events[2].source, 'svc-b');
});

test('flattens int and bool attribute values', () => {
  const payload = {
    resourceLogs: [{
      resource: { attributes: [{ key: 'service.name', value: { stringValue: 'svc' } }] },
      scopeLogs: [{ logRecords: [{
        timeUnixNano: '1000000000',
        eventName: 'permission.checked',
        attributes: [
          { key: 'permission.allowed', value: { boolValue: true } },
          { key: 'count',              value: { intValue: '42' } },
        ],
      }] }],
    }],
  };
  const [ev] = translateOtlpLogs(payload);
  assert.strictEqual(ev.attributes['permission.allowed'], true);
  assert.strictEqual(ev.attributes['count'], 42);
});

test('skips records with no eventName (ambient startup logs)', () => {
  const payload = {
    resourceLogs: [{
      resource: { attributes: [{ key: 'service.name', value: { stringValue: 'svc' } }] },
      scopeLogs: [{
        logRecords: [
          { timeUnixNano: '1000000000', body: { stringValue: 'User device listening on 0.0.0.0:8081' }, attributes: [] },
          { timeUnixNano: '2000000000', eventName: 'demo.reset', attributes: [] },
          { timeUnixNano: '3000000000', eventName: 'not_dotted', attributes: [] },
        ],
      }],
    }],
  };
  const events = translateOtlpLogs(payload);
  assert.strictEqual(events.length, 1);
  assert.strictEqual(events[0].event_type, 'demo.reset');
});

test('skips appender-synthesized event names (e.g. "event crates/.../main.rs:450")', () => {
  const payload = {
    resourceLogs: [{
      resource: { attributes: [{ key: 'service.name', value: { stringValue: 'agent-gateway' } }] },
      scopeLogs: [{
        logRecords: [
          { timeUnixNano: '1000000000', eventName: 'event crates/agent-gateway/src/main.rs:450', attributes: [] },
          { timeUnixNano: '2000000000', eventName: 'demo.reset', attributes: [] },
          { timeUnixNano: '3000000000', eventName: 'Foo.Bar', attributes: [] },
          { timeUnixNano: '4000000000', eventName: 'hello world', attributes: [] },
        ],
      }],
    }],
  };
  const events = translateOtlpLogs(payload);
  assert.strictEqual(events.length, 1);
  assert.strictEqual(events[0].event_type, 'demo.reset');
});

test('falls back to observedTimeUnixNano when timeUnixNano is missing or zero', () => {
  const payload = {
    resourceLogs: [{
      resource: { attributes: [{ key: 'service.name', value: { stringValue: 'svc' } }] },
      scopeLogs: [{
        logRecords: [
          { timeUnixNano: '0', observedTimeUnixNano: '1713816000000000000', eventName: 'demo.reset', attributes: [] },
          { observedTimeUnixNano: '1713816000000000000', eventName: 'demo.again', attributes: [] },
        ],
      }],
    }],
  };
  const events = translateOtlpLogs(payload);
  assert.strictEqual(events.length, 2);
  assert.strictEqual(events[0].timestamp, '2024-04-22T20:00:00.000Z');
  assert.strictEqual(events[1].timestamp, '2024-04-22T20:00:00.000Z');
});

// ─── translateJaegerTraces ────────────────────────────────────────────────

function jaegerTrace(spans, processes) {
  return { data: [{ traceID: 't1', spans, processes }] };
}

test('translateJaegerTraces: 2-span trace becomes a request.allowed event', () => {
  const sidecar = {
    spanID: 'sc1',
    operationName: 'sidecar CONNECT',
    references: [],
    processID: 'p1',
    startTime: 1713816000_000_000,
    tags: [
      { key: 'source_identity', value: 'agent-alpha' },
      { key: 'dest_authority',  value: 'api.anthropic.com:443' },
    ],
  };
  const gateway = {
    spanID: 'gw1',
    operationName: 'gateway CONNECT',
    references: [{ refType: 'CHILD_OF', spanID: 'sc1' }],
    processID: 'p2',
    startTime: 1713816000_000_500,
    tags: [
      { key: 'dest_authority',   value: 'api.anthropic.com:443' },
      { key: 'otel.status_code', value: 'OK' },
    ],
  };
  const payload = jaegerTrace([sidecar, gateway], {
    p1: { serviceName: 'agent_gateway_sidecar' },
    p2: { serviceName: 'agent_gateway' },
  });

  const events = translateJaegerTraces(payload);
  assert.strictEqual(events.length, 1);
  assert.deepStrictEqual(events[0], {
    source: 'agent-gateway',
    event_type: 'request.allowed',
    timestamp: '2024-04-22T20:00:00.001Z',
    attributes: {
      'agent.id': 'agent-alpha',
      'http.host': 'api.anthropic.com:443',
    },
  });
});

test('translateJaegerTraces: error tag produces request.denied with denial.reason', () => {
  const sidecar = {
    spanID: 'sc1',
    operationName: 'sidecar CONNECT',
    references: [],
    processID: 'p1',
    startTime: 1713816000_000_000,
    tags: [{ key: 'source_identity', value: 'agent-alpha' }],
  };
  const gateway = {
    spanID: 'gw1',
    operationName: 'gateway CONNECT',
    references: [{ spanID: 'sc1' }],
    processID: 'p2',
    startTime: 1713816000_000_500,
    tags: [
      { key: 'dest_authority',   value: 'evil.example.com:443' },
      { key: 'error',            value: true },
      { key: 'otel.status_code', value: 'ERROR' },
    ],
  };
  const payload = jaegerTrace([sidecar, gateway], {
    p1: { serviceName: 'agent_gateway_sidecar' },
    p2: { serviceName: 'agent_gateway' },
  });

  const [ev] = translateJaegerTraces(payload);
  assert.strictEqual(ev.event_type, 'request.denied');
  assert.strictEqual(ev.attributes['agent.id'], 'agent-alpha');
  assert.strictEqual(ev.attributes['http.host'], 'evil.example.com:443');
  assert.strictEqual(ev.attributes['denial.reason'], 'ERROR');
});

test('translateJaegerTraces: sidecar-only trace yields no events', () => {
  const sidecar = {
    spanID: 'sc1',
    operationName: 'sidecar CONNECT',
    references: [],
    processID: 'p1',
    startTime: 1713816000_000_000,
    tags: [{ key: 'source_identity', value: 'agent-alpha' }],
  };
  const payload = jaegerTrace([sidecar], { p1: { serviceName: 'agent_gateway_sidecar' } });
  assert.deepStrictEqual(translateJaegerTraces(payload), []);
});

test('translateJaegerTraces: empty payloads', () => {
  assert.deepStrictEqual(translateJaegerTraces({}), []);
  assert.deepStrictEqual(translateJaegerTraces({ data: [] }), []);
});

test('translateJaegerTraces: parses real fixture', () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const fixture = path.join(__dirname, 'traces-1777683017707.json');
  if (!fs.existsSync(fixture)) return; // skip when sample dump isn't present
  const payload = JSON.parse(fs.readFileSync(fixture, 'utf8'));
  const events = translateJaegerTraces(payload);
  // Every gateway CONNECT span becomes one event; the dump has 17 of them.
  assert.strictEqual(events.length, 17);
  // Every event has a destination host. agent.id is best-effort: it comes
  // from the parent sidecar span, which is sometimes absent (the dump has
  // a couple of traces with only a gateway span). Those events get an
  // empty agent.id, which is fine for the dashboard's purposes.
  for (const ev of events) {
    assert.match(ev.event_type, /^request\.(allowed|denied)$/);
    assert.ok(ev.attributes['http.host']);
  }
  const withAgent = events.filter(e => e.attributes['agent.id']);
  assert.ok(withAgent.length > 0, 'at least some events should have agent.id');
});

// ─── translateOtlpTraces ────────────────────────────────────────────────

function otlpAttrs(o) {
  return Object.entries(o).map(([key, v]) => {
    if (typeof v === 'string') return { key, value: { stringValue: v } };
    if (typeof v === 'boolean') return { key, value: { boolValue: v } };
    if (typeof v === 'number') return { key, value: { intValue: String(v) } };
    return { key, value: { stringValue: String(v) } };
  });
}

test('translateOtlpTraces: sidecar parent + gateway child becomes one allowed event', () => {
  const payload = {
    resourceSpans: [
      {
        resource: { attributes: otlpAttrs({ 'service.name': 'agent_gateway_sidecar' }) },
        scopeSpans: [{
          spans: [{
            traceId: 'abc', spanId: 'sc1', name: 'sidecar CONNECT',
            startTimeUnixNano: '1713816000000000000',
            attributes: otlpAttrs({
              source_identity: 'agent-alpha',
              dest_authority: 'api.anthropic.com:443',
            }),
          }],
        }],
      },
      {
        resource: { attributes: otlpAttrs({ 'service.name': 'agent_gateway' }) },
        scopeSpans: [{
          spans: [{
            traceId: 'abc', spanId: 'gw1', parentSpanId: 'sc1', name: 'gateway CONNECT',
            startTimeUnixNano: '1713816000500000000',
            attributes: otlpAttrs({ dest_authority: 'api.anthropic.com:443' }),
            status: { code: 1 },
          }],
        }],
      },
    ],
  };
  const events = translateOtlpTraces(payload);
  assert.strictEqual(events.length, 1);
  assert.deepStrictEqual(events[0], {
    source: 'agent-gateway',
    event_type: 'request.allowed',
    timestamp: '2024-04-22T20:00:00.500Z',
    attributes: {
      'agent.id': 'agent-alpha',
      'http.host': 'api.anthropic.com:443',
    },
  });
});

test('translateOtlpTraces: status.code === 2 yields request.denied', () => {
  const payload = {
    resourceSpans: [{
      resource: { attributes: otlpAttrs({ 'service.name': 'agent_gateway' }) },
      scopeSpans: [{
        spans: [{
          spanId: 'gw1', name: 'gateway CONNECT',
          startTimeUnixNano: '1000000000',
          attributes: otlpAttrs({ dest_authority: 'evil.example.com:443' }),
          status: { code: 2, message: 'permission denied' },
        }],
      }],
    }],
  };
  const [ev] = translateOtlpTraces(payload);
  assert.strictEqual(ev.event_type, 'request.denied');
  assert.strictEqual(ev.attributes['http.host'], 'evil.example.com:443');
  assert.strictEqual(ev.attributes['denial.reason'], 'permission denied');
});

test('translateOtlpTraces: accepts proto-name STATUS_CODE_ERROR string', () => {
  const payload = {
    resourceSpans: [{
      resource: { attributes: otlpAttrs({ 'service.name': 'agent_gateway' }) },
      scopeSpans: [{
        spans: [{
          spanId: 'gw1', name: 'gateway CONNECT',
          startTimeUnixNano: '1000000000',
          attributes: otlpAttrs({ dest_authority: 'foo:443' }),
          status: { code: 'STATUS_CODE_ERROR' },
        }],
      }],
    }],
  };
  const [ev] = translateOtlpTraces(payload);
  assert.strictEqual(ev.event_type, 'request.denied');
});

test('translateOtlpTraces: only emits gateway CONNECT spans', () => {
  const payload = {
    resourceSpans: [{
      resource: { attributes: otlpAttrs({ 'service.name': 'agent_gateway_sidecar' }) },
      scopeSpans: [{
        spans: [
          { spanId: 'sc1', name: 'sidecar CONNECT', startTimeUnixNano: '1', attributes: [] },
          { spanId: 'sc2', name: 'something else',  startTimeUnixNano: '2', attributes: [] },
        ],
      }],
    }],
  };
  assert.deepStrictEqual(translateOtlpTraces(payload), []);
});

test('translateOtlpTraces: empty payload', () => {
  assert.deepStrictEqual(translateOtlpTraces({}), []);
  assert.deepStrictEqual(translateOtlpTraces({ resourceSpans: [] }), []);
});

test('translateOtlpTraces: CONNECT allowed span event yields request.allowed with source_identity', () => {
  const payload = {
    resourceSpans: [{
      resource: { attributes: otlpAttrs({ 'service.name': 'agent_gateway' }) },
      scopeSpans: [{
        spans: [{
          spanId: 'gw1', name: 'gateway CONNECT',
          startTimeUnixNano: '1713816000000000000',
          attributes: otlpAttrs({ dest_authority: 'api.anthropic.com:443' }),
          events: [{
            name: 'CONNECT allowed',
            timeUnixNano: '1713816000100000000',
            attributes: otlpAttrs({ source_identity: 'agent-alpha', policy_decision: 'allow' }),
          }],
        }],
      }],
    }],
  };
  const events = translateOtlpTraces(payload);
  assert.strictEqual(events.length, 1);
  assert.deepStrictEqual(events[0], {
    source: 'agent-gateway',
    event_type: 'request.allowed',
    timestamp: '2024-04-22T20:00:00.000Z',
    attributes: { 'agent.id': 'agent-alpha', 'http.host': 'api.anthropic.com:443' },
  });
});

test('translateOtlpTraces: CONNECT denied span event yields request.denied with deny_reason', () => {
  const payload = {
    resourceSpans: [{
      resource: { attributes: otlpAttrs({ 'service.name': 'agent_gateway' }) },
      scopeSpans: [{
        spans: [{
          spanId: 'gw1', name: 'gateway CONNECT',
          startTimeUnixNano: '1000000000',
          attributes: otlpAttrs({ dest_authority: 'evil.example.com:443' }),
          events: [{
            name: 'CONNECT denied',
            timeUnixNano: '1000100000',
            attributes: otlpAttrs({
              source_identity: 'agent-alpha',
              deny_reason: 'no active permission found',
              policy_decision: 'deny',
            }),
          }],
        }],
      }],
    }],
  };
  const [ev] = translateOtlpTraces(payload);
  assert.strictEqual(ev.event_type, 'request.denied');
  assert.strictEqual(ev.attributes['agent.id'], 'agent-alpha');
  assert.strictEqual(ev.attributes['http.host'], 'evil.example.com:443');
  assert.strictEqual(ev.attributes['denial.reason'], 'no active permission found');
});

test('translateOtlpTraces: CONNECT denied without source_identity leaves agent.id empty', () => {
  const payload = {
    resourceSpans: [{
      resource: { attributes: otlpAttrs({ 'service.name': 'agent_gateway' }) },
      scopeSpans: [{
        spans: [{
          spanId: 'gw1', name: 'gateway CONNECT',
          startTimeUnixNano: '1000000000',
          attributes: otlpAttrs({ dest_authority: 'evil.example.com:443' }),
          events: [{
            name: 'CONNECT denied',
            timeUnixNano: '1000100000',
            attributes: otlpAttrs({ deny_reason: 'missing required extension', policy_decision: 'deny' }),
          }],
        }],
      }],
    }],
  };
  const [ev] = translateOtlpTraces(payload);
  assert.strictEqual(ev.event_type, 'request.denied');
  assert.strictEqual(ev.attributes['agent.id'], '');
  assert.strictEqual(ev.attributes['denial.reason'], 'missing required extension');
});
