'use strict';

const DOTTED_EVENT_NAME = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$/;

function attrValue(v) {
  if (!v) return undefined;
  if (v.stringValue !== undefined) return v.stringValue;
  if (v.boolValue   !== undefined) return v.boolValue;
  if (v.intValue    !== undefined) return parseInt(v.intValue, 10);
  if (v.doubleValue !== undefined) return v.doubleValue;
  if (v.arrayValue  !== undefined) return v.arrayValue;
  if (v.kvlistValue !== undefined) return v.kvlistValue;
  return undefined;
}

function attrMap(attrs) {
  const out = {};
  if (!Array.isArray(attrs)) return out;
  for (const { key, value } of attrs) {
    if (typeof key === 'string') out[key] = attrValue(value);
  }
  return out;
}

function nanosToIso(ns) {
  if (!ns) return new Date(0).toISOString();
  const ms = Number(BigInt(ns) / 1_000_000n);
  return new Date(ms).toISOString();
}

function pickTimestamp(rec) {
  const t = rec.timeUnixNano;
  if (t && t !== '0' && t !== 0) return t;
  return rec.observedTimeUnixNano;
}

function translateOtlpLogs(otlp) {
  const out = [];
  for (const rl of otlp.resourceLogs || []) {
    const source = attrMap(rl.resource?.attributes)['service.name'] || 'unknown';
    for (const sl of rl.scopeLogs || []) {
      for (const rec of sl.logRecords || []) {
        const event_type = rec.eventName;
        // Only surface explicitly-named events. Skips ambient tracing::info!("message")
        // startup logs that have no eventName.
        if (!event_type || !DOTTED_EVENT_NAME.test(event_type)) continue;
        out.push({
          source,
          event_type,
          timestamp: nanosToIso(pickTimestamp(rec)),
          attributes: attrMap(rec.attributes),
        });
      }
    }
  }
  return out;
}

// ─── Jaeger trace export → flat events ─────────────────────────────────────

function tagMap(tags) {
  const out = {};
  if (!Array.isArray(tags)) return out;
  for (const t of tags) {
    if (t && typeof t.key === 'string') out[t.key] = t.value;
  }
  return out;
}

function microsToIso(us) {
  if (!us) return new Date(0).toISOString();
  return new Date(Math.round(Number(us) / 1000)).toISOString();
}

function translateJaegerTraces(payload) {
  const out = [];
  for (const trace of (payload && payload.data) || []) {
    const spans = trace.spans || [];
    const processes = trace.processes || {};
    const spanById = new Map();
    for (const s of spans) spanById.set(s.spanID, s);

    for (const span of spans) {
      // Only the gateway CONNECT span carries the allow/deny decision.
      // The sidecar CONNECT is its parent and holds the agent identity.
      if (span.operationName !== 'gateway CONNECT') continue;

      const tags = tagMap(span.tags);
      const parentRef = (span.references || []).find(r => r && r.spanID);
      const parent = parentRef ? spanById.get(parentRef.spanID) : null;
      const parentTags = parent ? tagMap(parent.tags) : {};

      const denied = tags.error === true || tags['otel.status_code'] === 'ERROR';
      const event_type = denied ? 'request.denied' : 'request.allowed';

      const serviceName = (processes[span.processID] || {}).serviceName || 'unknown';
      const source = serviceName.replace(/_/g, '-');

      const attributes = {
        'agent.id': parentTags.source_identity || tags.source_identity || '',
        'http.host': tags.dest_authority || '',
      };
      if (denied) {
        attributes['denial.reason'] = tags['otel.status_code'] || 'error';
      }

      out.push({
        source,
        event_type,
        timestamp: microsToIso(span.startTime),
        attributes,
      });
    }
  }
  return out;
}

// ─── OTLP HTTP/JSON traces → flat events ──────────────────────────────────
//
// OTLP wire format (the live shape sent by an opentelemetry-collector via the
// `otlphttp` exporter to /v1/traces). Distinct from Jaeger export. Each span
// is one entry in `resourceSpans[].scopeSpans[].spans[]`, with attributes,
// startTimeUnixNano, status, and parentSpanId for cross-resource lookup.

function statusCode(s) {
  if (!s) return undefined;
  // OTLP status code: 0 = UNSET, 1 = OK, 2 = ERROR. Accept the numeric form
  // as well as the proto-name form ("STATUS_CODE_ERROR") for robustness.
  if (typeof s.code === 'number') return s.code;
  if (typeof s.code === 'string') {
    const c = s.code.toUpperCase();
    if (c === 'STATUS_CODE_ERROR' || c === 'ERROR') return 2;
    if (c === 'STATUS_CODE_OK'    || c === 'OK')    return 1;
    return 0;
  }
  return undefined;
}

function translateOtlpTraces(payload) {
  const out = [];
  const resourceSpans = (payload && payload.resourceSpans) || [];

  // Build a global span lookup so we can find the sidecar parent of a
  // gateway span even when they arrive under different resourceSpans
  // entries (different services).
  const spanById = new Map();
  for (const rs of resourceSpans) {
    const serviceName = attrMap(rs.resource && rs.resource.attributes)['service.name'] || 'unknown';
    for (const ss of rs.scopeSpans || []) {
      for (const span of ss.spans || []) {
        spanById.set(span.spanId, { span, serviceName });
      }
    }
  }

  for (const rs of resourceSpans) {
    const serviceName = attrMap(rs.resource && rs.resource.attributes)['service.name'] || 'unknown';
    const source = serviceName.replace(/_/g, '-');
    for (const ss of rs.scopeSpans || []) {
      for (const span of ss.spans || []) {
        if (span.name !== 'gateway CONNECT') continue;

        const attrs = attrMap(span.attributes);
        const parentEntry = span.parentSpanId ? spanById.get(span.parentSpanId) : null;
        const parentAttrs = parentEntry ? attrMap(parentEntry.span.attributes) : {};

        // The gateway emits "CONNECT allowed" or "CONNECT denied" as tracing
        // events inside the span, carrying source_identity and deny_reason.
        // Check these first; fall back to span status for spans that set it
        // explicitly (e.g. a future sidecar path).
        let connectEvent = null;
        for (const ev of (span.events || [])) {
          if (ev.name === 'CONNECT allowed' || ev.name === 'CONNECT denied') {
            connectEvent = ev;
            break;
          }
        }
        const eventAttrs = connectEvent ? attrMap(connectEvent.attributes) : {};

        const code = statusCode(span.status);
        const denied = connectEvent ? connectEvent.name === 'CONNECT denied' : code === 2;
        const event_type = denied ? 'request.denied' : 'request.allowed';

        const attributes = {
          'agent.id': eventAttrs.source_identity || parentAttrs.source_identity || attrs.source_identity || '',
          'http.host': attrs.dest_authority || '',
        };
        if (denied) {
          attributes['denial.reason'] = eventAttrs.deny_reason || (span.status && span.status.message) || 'ERROR';
        }

        out.push({
          source,
          event_type,
          timestamp: nanosToIso(span.startTimeUnixNano),
          attributes,
        });
      }
    }
  }
  return out;
}

module.exports = { translateOtlpLogs, translateJaegerTraces, translateOtlpTraces };
