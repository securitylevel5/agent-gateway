# Agent Gateway Dashboard

A standalone web server that visualizes an agent gateway deployment in real time. It ingests OpenTelemetry log records from the gateway and surrounding services, and queries the authority registry directly for snapshots of registered humans, devices, and agents.

The dashboard is owned by this repo. The backend it visualizes (gateway, platform, registry, agents) lives elsewhere and is the contract surface described below.

## What it does

- Serves the dashboard UI (`public/index.html`, `public/topology.js`, `registry-panel.js`).
- Accepts OTLP/HTTP+JSON log records on `POST /v1/logs` and pushes them to connected browsers over a WebSocket. Recent events are kept in an in-memory ring buffer (`MAX_EVENTS = 1000`).
- Proxies `GET /api/registry` and `GET /api/devices` to an upstream authority registry (`REGISTRY_URL`). The browser uses these for the registry panel and the topology's user-device discovery.

## Backend contract

The dashboard expects the backend to provide:

| Surface | What the dashboard does with it |
|---------|---------------------------------|
| OTLP push to `POST /v1/logs` | Live event feed: gateway decisions (`request.allowed` / `request.denied` / `auth.allowed` / `tunnel.error`), platform lifecycle (`agent.created` / `agent.terminated`), user-device actions (`agent.requested` / `prompt.sent` / `permission.change_requested` / `termination.requested`). |
| `GET /snapshot` on the registry (proxied as `/api/registry`) | Topology + registry panel: humans, agents, permission grants. |
| `GET /users` on the registry (proxied as `/api/users`) | User nodes in the topology. |

The OTLP shape is plain HTTP/JSON (no gRPC). `translate.js` parses the standard OTLP `resourceLogs` envelope and lifts each `LogRecord`'s attributes into a flat event the browser consumes.

## Configuration

| Env var | Default | Purpose |
|---------|---------|---------|
| `REGISTRY_URL` | `http://authority-registry:8080` | Upstream registry. The two `/api/...` endpoints proxy to this host. |

The server binds `0.0.0.0:3000`.

## Running

```bash
npm install
npm start            # node server.js
npm test             # node --test
```

Open `http://localhost:3000`. With no events flowing in and no upstream registry reachable, the topology will show only the static infrastructure nodes and the registry panel will display an error.

## Layout

```
.
├── server.js                # HTTP + WebSocket server, OTLP ingest, registry proxy
├── translate.js             # OTLP -> flat-event translation
├── translate.test.js
├── registry-panel.js        # Browser-side renderer for the registry panel
├── registry-panel.test.js
├── theme.css                # Shared color tokens
├── public/
│   ├── index.html           # Dashboard shell
│   └── topology.js          # Topology canvas, edge highlighting, node placement
└── package.json
```
