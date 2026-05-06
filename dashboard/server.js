const http = require('http');
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { WebSocketServer } = require('ws');
const { Pool } = require('pg');
const { translateOtlpLogs, translateOtlpTraces } = require('./translate');


const dbPool = new Pool({
  connectionString: process.env.AGENT_GATEWAY_DATABASE_URL ||
    'postgres://agent_gateway_admin:agent_gateway_dev@localhost:5432/agent_gateway',
});

const PORT = 3000;
const MAX_EVENTS = 1000;

// In-memory event store (bounded)
let events = [];
const wsClients = new Set();

async function parseBody(req) {
  const buf = await parseBodyBuffer(req);
  return buf.length ? JSON.parse(buf.toString('utf8')) : {};
}

function parseBodyBuffer(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => { chunks.push(chunk); });
    req.on('end', () => {
      const buf = Buffer.concat(chunks);
      const enc = req.headers['content-encoding'] || '';
      if (enc.includes('gzip')) {
        zlib.gunzip(buf, (err, result) => err ? reject(err) : resolve(result));
      } else {
        resolve(buf);
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res, statusCode, data) {
  const json = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(json),
  });
  res.end(json);
}

function broadcastEvent(event) {
  const msg = JSON.stringify(event);
  for (const client of wsClients) {
    if (client.readyState === 1) { // OPEN
      client.send(msg);
    }
  }
}

// Serve static files from /app/public (+ shared theme.css)
function serveStatic(req, res) {
  const publicDir = path.join(__dirname, 'public');
  let filePath;
  if (req.url === '/theme.css') {
    filePath = path.join(__dirname, 'theme.css');
  } else if (req.url === '/registry-panel.js') {
    filePath = path.join(__dirname, 'registry-panel.js');
  } else {
    filePath = path.join(publicDir, req.url === '/' ? 'index.html' : req.url);
    // Prevent directory traversal (only for public dir paths)
    if (!filePath.startsWith(publicDir)) {
      res.writeHead(403);
      return res.end('Forbidden');
    }
  }

  const ext = path.extname(filePath);
  const contentTypes = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.svg': 'image/svg+xml',
  };

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404);
      return res.end('Not found');
    }
    res.writeHead(200, { 'Content-Type': contentTypes[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);
  const pathName = url.pathname;
  const method = req.method;

  try {
    // Health check
    if (pathName === '/health' && method === 'GET') {
      return sendJson(res, 200, { status: 'ok' });
    }

    // GET /events - retrieve event history
    if (pathName === '/events' && method === 'GET') {
      return sendJson(res, 200, events);
    }

    // POST /v1/logs - OTLP HTTP/JSON logs ingestion
    if (pathName === '/v1/logs' && method === 'POST') {
      const body = await parseBody(req);
      for (const ev of translateOtlpLogs(body)) {
        ev.received_at = new Date().toISOString();
        if (ev.event_type === 'demo.reset') {
          events = [];
        } else {
          events.push(ev);
          if (events.length > MAX_EVENTS) events = events.slice(-MAX_EVENTS);
        }
        broadcastEvent(ev);
      }
      return sendJson(res, 200, { partialSuccess: {} });
    }

    // POST /v1/traces - OTLP HTTP/JSON traces ingestion (optionally gzip-encoded).
    if (pathName === '/v1/traces' && method === 'POST') {
      const body = await parseBody(req);
      for (const ev of translateOtlpTraces(body)) {
        ev.received_at = new Date().toISOString();
        events.push(ev);
        if (events.length > MAX_EVENTS) events = events.slice(-MAX_EVENTS);
        broadcastEvent(ev);
      }
      return sendJson(res, 200, { partialSuccess: {} });
    }

    // GET /api/users - list of active principal signing keys as user nodes
    if (pathName === '/api/users' && method === 'GET') {
      try {
        const result = await dbPool.query(
          `SELECT key_id AS id FROM principal_signing_keys
           WHERE revoked_at IS NULL AND not_before <= now() AND not_after > now()
           ORDER BY key_id`
        );
        return sendJson(res, 200, result.rows);
      } catch (_err) {
        return sendJson(res, 200, []);
      }
    }

    // GET /api/registry - snapshot of principals and agent permissions from Postgres
    if (pathName === '/api/registry' && method === 'GET') {
      try {
        const [keysResult, delegationsResult, permsResult] = await Promise.all([
          dbPool.query(
            `SELECT key_id FROM principal_signing_keys
             WHERE revoked_at IS NULL AND not_before <= now() AND not_after > now()
             ORDER BY key_id`
          ),
          dbPool.query(
            `SELECT signing_key_id, destination
             FROM principal_key_permissions
             WHERE revoked_at IS NULL AND not_before <= now() AND not_after > now()
             ORDER BY signing_key_id, destination`
          ),
          dbPool.query(
            `SELECT DISTINCT signing_key_id, subject_identity, destination
             FROM permission_registry
             WHERE revoked_at IS NULL AND not_before <= now() AND not_after > now()
             ORDER BY subject_identity, destination`
          ),
        ]);

        const humanMap = new Map();
        for (const row of keysResult.rows) {
          humanMap.set(row.key_id, { id: row.key_id, permissions: [] });
        }
        for (const row of delegationsResult.rows) {
          const h = humanMap.get(row.signing_key_id);
          if (h) h.permissions.push(row.destination);
        }

        const agentMap = new Map();
        for (const row of permsResult.rows) {
          if (!agentMap.has(row.subject_identity)) {
            agentMap.set(row.subject_identity, {
              id: row.subject_identity,
              created_by: row.signing_key_id,
              permissions: [],
            });
          }
          agentMap.get(row.subject_identity).permissions.push(row.destination);
        }

        return sendJson(res, 200, {
          humans: Array.from(humanMap.values()),
          agents: Array.from(agentMap.values()),
        });
      } catch (_err) {
        return sendJson(res, 502, { error: 'registry unavailable' });
      }
    }

    // POST /api/reset - proxy to demo-admin reset endpoint
    if (pathName === '/api/reset' && method === 'POST') {
      const adminHost = process.env.ADMIN_HOST || 'demo-admin';
      const adminPort = process.env.ADMIN_PORT || '8080';
      return new Promise((resolve) => {
        let responded = false;
        const proxyReq = http.request({
          hostname: adminHost,
          port: parseInt(adminPort),
          path: '/api/reset',
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          timeout: 30000,
        }, (proxyRes) => {
          let body = '';
          proxyRes.on('data', chunk => { body += chunk; });
          proxyRes.on('end', () => {
            if (responded) return;
            responded = true;
            events = [];
            res.writeHead(proxyRes.statusCode, { 'Content-Type': 'application/json' });
            res.end(body);
            resolve();
          });
        });
        proxyReq.on('error', (err) => {
          if (responded) return;
          responded = true;
          sendJson(res, 502, { error: 'Failed to reach demo-admin: ' + err.message });
          resolve();
        });
        proxyReq.on('timeout', () => {
          proxyReq.destroy();
          if (responded) return;
          responded = true;
          sendJson(res, 504, { error: 'demo-admin request timed out' });
          resolve();
        });
        proxyReq.end();
      });
    }

    // Serve static files for everything else
    serveStatic(req, res);
  } catch (e) {
    sendJson(res, 400, { error: e.message });
  }
});

// WebSocket server on /ws path
const wss = new WebSocketServer({ server, path: '/ws' });

wss.on('connection', (ws) => {
  wsClients.add(ws);

  // Send event history on connect
  ws.send(JSON.stringify({ type: 'history', events }));

  ws.on('close', () => {
    wsClients.delete(ws);
  });

  ws.on('error', () => {
    wsClients.delete(ws);
  });
});

server.listen(PORT, () => {
  console.log(`Dashboard listening on port ${PORT}`);
});
