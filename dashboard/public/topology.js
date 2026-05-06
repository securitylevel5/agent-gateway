// ============================================================
// Topology module — extracted from index.html
// Exposes window.Topology with all topology state and functions.
// ============================================================
(function() {
  'use strict';

  // ============================================================
  // SVG icon paths
  // ============================================================
  const ICONS = {
    shield:   '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    containers: { viewBox: '-1 -1 26 27', path: '<path d="M10.07,1.27 L13.93,1.27 L13.87,3.36 L15.08,4.06 L16.86,2.96 L18.79,6.31 L16.95,7.3 L16.95,8.7 L18.79,9.69 L16.86,13.04 L15.08,11.94 L13.87,12.64 L13.93,14.73 L10.07,14.73 L10.13,12.64 L8.92,11.94 L7.14,13.04 L5.21,9.69 L7.05,8.7 L7.05,7.3 L5.21,6.31 L7.14,2.96 L8.92,4.06 L10.13,3.36 Z"/><circle cx="12" cy="8" r="2.8"/><rect x="3" y="16" width="18" height="3.5" rx="1"/><rect x="3" y="20.5" width="18" height="3.5" rx="1"/><circle cx="6.5" cy="17.75" r=".8"/><circle cx="6.5" cy="22.25" r=".8"/>' },
    robot:    '<rect x="3" y="11" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><line x1="12" y1="7" x2="12" y2="11"/><line x1="8" y1="16" x2="8" y2="16"/><line x1="16" y1="16" x2="16" y2="16"/>',
    question: '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>',
    monitor:  '<rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>',
    user:     '<circle cx="12" cy="8" r="4"/><path d="M4 21v-1a8 8 0 0 1 16 0v1"/>',
    book:     '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
    chat:     '<path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    lock:     '<rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>',
    document: '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>',
    gear:     { viewBox: '2 -1.5 20 19', path: '<path d="M10.07,1.27 L13.93,1.27 L13.87,3.36 L15.08,4.06 L16.86,2.96 L18.79,6.31 L16.95,7.3 L16.95,8.7 L18.79,9.69 L16.86,13.04 L15.08,11.94 L13.87,12.64 L13.93,14.73 L10.07,14.73 L10.13,12.64 L8.92,11.94 L7.14,13.04 L5.21,9.69 L7.05,8.7 L7.05,7.3 L5.21,6.31 L7.14,2.96 L8.92,4.06 L10.13,3.36 Z"/><circle cx="12" cy="8" r="2.8"/>' },
  };

  function iconSvg(name, size) {
    const icon = ICONS[name];
    const isObj = typeof icon === 'object';
    const vb = isObj ? icon.viewBox : '0 0 24 24';
    const path = isObj ? icon.path : icon;
    return '<svg width="' + size + '" height="' + size + '" viewBox="' + vb + '" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + path + '</svg>';
  }

  // ============================================================
  // HTML escaping
  // ============================================================
  const _escapeEl = document.createElement('span');
  function escapeHtml(str) {
    _escapeEl.textContent = str;
    return _escapeEl.innerHTML;
  }
  function esc(str) {
    return escapeHtml(String(str));
  }

  // ============================================================
  // Static node definitions (non-agent-runtime nodes are always present)
  // ============================================================
  const STATIC_NODE_DEFS = [
    { id: 'node-docstore',           icon: 'book',     label: 'docstore',           classes: 'org-node example-service' },
    { id: 'node-messaging',          icon: 'chat',     label: 'messaging',          classes: 'org-node example-service' },
    { id: 'node-agent-gateway',      icon: 'shield',   label: 'agent-gateway',      classes: 'gateway' },
    { id: 'node-agent-platform',       icon: 'gear',       label: 'agent-platform',    classes: 'agent' },
    { id: 'node-authority-registry', icon: 'lock',     label: 'authority-registry', classes: 'infrastructure-node infra-item' },
  ];

  // Dynamic user device nodes - tracked by device_id
  // Map: device_id -> { id: dom_id, label: device_id }
  const users = new Map();
  let userNodeCounter = 0;

  // Dynamic agent runtime nodes - tracked by agent_id
  // Map: agent_id -> { id: dom_id, label: agent_id }
  const agentRuntimes = new Map();
  let agentNodeCounter = 0;

  // State: recently active edges (for highlighting)
  const activeEdges = new Set();
  const deniedEdges = new Set();

  // ============================================================
  // Layout — named grid system
  // ============================================================

  // Canvas dimensions
  const CANVAS = { width: 828, height: 520 };

  // Zone rectangles
  const ZONES = {
    agentCluster: { left: 30, top: 15, width: 288, height: 390 },
    orgNetwork:   { left: 358, top: 15, width: 440, height: 390 },
    infra:        { left: 30, top: 420, width: 288, height: 90 },
    notes:        { left: 358, top: 420, width: 440, height: 90 },
  };

  // Named columns (x positions for node icon centers)
  const COL = {
    agentRuntime:    102,  // left side of agent cluster
    agentCluster:    222,  // agent-platform
    gateway:         338,  // gap between zones
    orgCore:         554,  // user devices
    exampleServices: 726,  // docstore, messaging
  };

  // Named rows (y positions for node icon centers)
  const ROW = {
    center:          210,  // gateway (org zone vertical center)
    agentPlatform:   308,  // agent-platform (halfway between center and zone bottom)
    users:     325,  // users row
    exServiceTop:    105,  // example services distribute range top
    exServiceBottom: 325,  // example services distribute range bottom
  };

  // Icon, font, and spacing sizes
  const SIZES = {
    icon: 56,            iconRadius: 14,       svgIcon: 22,
    gatewayIcon: 80,     gatewayRadius: 20,    gatewaySvg: 34,
    infraIcon: 44,       infraRadius: 11,      infraSvg: 18,

    labelFont: 12,
    agentLabelFont: 10,
    infraLabelFont: 10,
    zoneLabelFont: 11,
    subZoneLabelFont: 10,
    externalEdgeLabelFont: 10,

    nodeGap: 8,
    verticalSpacing: 140,
    subZonePad: 16,
    subZoneLabelGap: 16,
    runtimeSubzonePad: 12,
    runtimeNodeInset: 10,
    userZoneWidth: 176,         // round(440 * 2/5)
    userVerticalOffset: 6,
    externalEdgeTopOffset: 5,
  };

  // ============================================================
  // DOM creation for nodes
  // ============================================================
  function createNodeElement(def) {
    const icon = ICONS[def.icon];
    const isObj = typeof icon === 'object';
    const vb = isObj ? icon.viewBox : '0 0 24 24';
    const path = isObj ? icon.path : icon;
    const baseAttrs = 'fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"';
    const div = document.createElement('div');
    div.className = 'node ' + def.classes;
    div.id = def.id;
    div.innerHTML =
      '<div class="node-icon"><svg viewBox="' + vb + '" ' + baseAttrs + '>' + path + '</svg></div>' +
      '<div class="node-label">' + escapeHtml(def.label) + '</div>';
    return div;
  }

  function createStaticNodes() {
    const container = document.getElementById('nodes-container');
    for (let i = 0; i < STATIC_NODE_DEFS.length; i++) {
      container.appendChild(createNodeElement(STATIC_NODE_DEFS[i]));
    }
    document.getElementById('ap-header-icon').innerHTML = iconSvg('containers', 14);
  }

  function addAgentRuntimeNode(agentId) {
    if (agentRuntimes.has(agentId)) return;

    agentNodeCounter++;
    const domId = 'node-agent-' + agentNodeCounter;
    const shortId = agentId.length > 16 ? agentId.slice(0, 16) : agentId;

    agentRuntimes.set(agentId, { id: domId, label: shortId });

    const container = document.getElementById('nodes-container');
    const def = { id: domId, icon: 'robot', label: shortId, classes: 'agent agent-runtime' };
    const el = createNodeElement(def);
    container.appendChild(el);

    // Apply size to the new node
    applyNodeSize(el);

    // Recompute layout and redraw
    reLayout();
  }

  function removeAgentRuntimeNode(agentId) {
    const info = agentRuntimes.get(agentId);
    if (!info) return;

    const el = document.getElementById(info.id);
    if (el) el.remove();
    agentRuntimes.delete(agentId);

    reLayout();
  }

  function addUserNode(userId) {
    if (users.has(userId)) return;

    userNodeCounter++;
    const domId = 'node-' + userId;

    users.set(userId, { id: domId, label: userId });

    const container = document.getElementById('nodes-container');
    const def = { id: domId, icon: 'user', label: userId, classes: 'org-node user-node' };
    const el = createNodeElement(def);
    container.appendChild(el);

    applyNodeSize(el);
    reLayout();
  }

  function removeUserNode(userId) {
    const info = users.get(userId);
    if (!info) return;

    const el = document.getElementById(info.id);
    if (el) el.remove();
    users.delete(userId);

    reLayout();
  }

  // ============================================================
  // Sizing
  // ============================================================
  function applyNodeSize(node) {
    node.style.gap = SIZES.nodeGap + 'px';
    const icon = node.querySelector('.node-icon');
    const label = node.querySelector('.node-label');
    const svgEl = icon.querySelector('svg');

    if (node.classList.contains('gateway')) {
      setIconSize(icon, svgEl, SIZES.gatewayIcon, SIZES.gatewayRadius, SIZES.gatewaySvg);
      label.style.fontSize = SIZES.labelFont + 'px';
    } else if (node.classList.contains('infra-item')) {
      setIconSize(icon, svgEl, SIZES.infraIcon, SIZES.infraRadius, SIZES.infraSvg);
      label.style.fontSize = SIZES.infraLabelFont + 'px';
    } else {
      setIconSize(icon, svgEl, SIZES.icon, SIZES.iconRadius, SIZES.svgIcon);
      label.style.fontSize = node.classList.contains('agent')
        ? SIZES.agentLabelFont + 'px'
        : SIZES.labelFont + 'px';
    }
  }

  function applySizes() {
    const canvas = document.getElementById('canvas');
    canvas.style.width = CANVAS.width + 'px';
    canvas.style.height = CANVAS.height + 'px';

    const svg = document.getElementById('edges');
    svg.style.width = CANVAS.width + 'px';
    svg.style.height = CANVAS.height + 'px';

    setRect('zone-org', ZONES.orgNetwork);
    setRect('zone-ap', ZONES.agentCluster);
    setRect('zone-infra', ZONES.infra);
    setRect('zone-notes', ZONES.notes);

    document.querySelectorAll('.zone-label').forEach(function(el) {
      el.style.fontSize = SIZES.zoneLabelFont + 'px';
    });

    document.querySelectorAll('.node').forEach(applyNodeSize);
  }

  function setIconSize(icon, svgEl, size, radius, svgSize) {
    icon.style.width = size + 'px';
    icon.style.height = size + 'px';
    icon.style.borderRadius = radius + 'px';
    svgEl.setAttribute('width', svgSize);
    svgEl.setAttribute('height', svgSize);
  }

  function setRect(id, r) {
    const el = document.getElementById(id);
    el.style.left = r.left + 'px';
    el.style.top = r.top + 'px';
    el.style.width = r.width + 'px';
    el.style.height = r.height + 'px';
  }

  // ============================================================
  // Layout computation
  // ============================================================
  function computeLayout() {
    const ap = ZONES.agentCluster;
    const infra = ZONES.infra;

    // Static node positions from the named grid
    placeNodeCenter('node-agent-gateway',    COL.gateway,      ROW.center);
    placeNodeCenter('node-agent-platform',   COL.agentCluster, ROW.agentPlatform);

    // User devices subzone
    const udNodes = Array.from(document.querySelectorAll('.user-node'));
    const sampleUd = udNodes[0];
    const udNodeW = sampleUd ? sampleUd.offsetWidth : SIZES.icon;
    const udNodeH = sampleUd ? sampleUd.offsetHeight : SIZES.icon + SIZES.nodeGap + SIZES.labelFont;
    const udIconH = sampleUd ? sampleUd.querySelector('.node-icon').offsetHeight : SIZES.icon;
    const udZoneW = SIZES.userZoneWidth;
    const udZonePad = SIZES.subZonePad;
    const udZoneH = udNodeH + udZonePad;
    const udZoneLeft = COL.orgCore - udZoneW / 2;
    const udZoneTop = ROW.users - udIconH / 2 - udZonePad + SIZES.userVerticalOffset;
    const udSz = document.getElementById('subzone-users');
    udSz.style.left = Math.round(udZoneLeft) + 'px';
    udSz.style.top = Math.round(udZoneTop) + 'px';
    udSz.style.width = udZoneW + 'px';
    udSz.style.height = udZoneH + 'px';

    const udNodeInset = SIZES.runtimeNodeInset;
    const udLeftInset = udNodeW / 2 + udNodeInset;
    const udRightInset = udNodeW / 2 + udNodeInset;
    distributeHorizontally(udNodes, ROW.users,
      Math.round(udZoneLeft) + udLeftInset,
      Math.round(udZoneLeft) + udZoneW - udRightInset);

    const udLabel = document.getElementById('label-users');
    udLabel.style.fontSize = SIZES.subZoneLabelFont + 'px';
    udLabel.style.left = Math.round(udZoneLeft + udZoneW / 2) + 'px';
    udLabel.style.transform = 'translateX(-50%)';
    udLabel.style.top = Math.round(udZoneTop - SIZES.subZoneLabelGap) + 'px';

    // Example services (distributed vertically)
    const exampleServiceNodes = Array.from(document.querySelectorAll('.example-service'));
    distributeVertically(exampleServiceNodes, COL.exampleServices, ROW.center,
      ROW.exServiceTop, ROW.exServiceBottom);
    positionSubZone(exampleServiceNodes, 'subzone-example-services', 'label-example-services');

    // Agent runtime subzone
    const runtimeNodes = Array.from(document.querySelectorAll('.agent-runtime'));
    const sampleRuntime = runtimeNodes[0];
    const runtimeW = sampleRuntime ? sampleRuntime.offsetWidth : 60;
    const apHeader = document.querySelector('#zone-ap .zone-header');
    const headerH = apHeader ? apHeader.offsetHeight : 0;
    const rzPadding = SIZES.runtimeSubzonePad;
    const rzTop = ap.top + headerH + rzPadding;
    const rzHeight = ap.height - headerH - rzPadding * 2;
    const sz = document.getElementById('subzone-agent-runtimes');

    const szLeft = COL.agentRuntime - runtimeW / 2 - SIZES.subZonePad;
    sz.style.display = '';
    sz.style.left = szLeft + 'px';
    sz.style.top = rzTop + 'px';
    sz.style.width = (runtimeW + SIZES.subZonePad * 2) + 'px';
    sz.style.height = rzHeight + 'px';

    if (runtimeNodes.length > 0) {
      const sampleIconH = sampleRuntime.querySelector('.node-icon').offsetHeight;
      const sampleNodeH = sampleRuntime.offsetHeight;
      const nodeInsetPad = SIZES.runtimeNodeInset;
      const topInset = sampleIconH / 2 + nodeInsetPad;
      const bottomInset = sampleNodeH - sampleIconH / 2 + nodeInsetPad;
      distributeVertically(runtimeNodes, COL.agentRuntime, ROW.center,
        rzTop + topInset, rzTop + rzHeight - bottomInset);
    }

    // Infrastructure nodes
    const infraNodes = Array.from(document.querySelectorAll('.infra-item'));
    const infraColumnXs = [COL.agentCluster, COL.gateway];
    const sampleInfra = infraNodes[0];
    if (sampleInfra) {
      const infraNodeH = sampleInfra.offsetHeight;
      const infraIconH = sampleInfra.querySelector('.node-icon').offsetHeight;
      const infraCY = infra.top + (infra.height - infraNodeH) / 2 + infraIconH / 2;
      infraNodes.forEach(function(node, i) {
        placeNodeCenter(node.id, infraColumnXs[i % infraColumnXs.length], infraCY);
      });
    }
  }

  function placeNodeCenter(id, cx, cy) {
    const el = document.getElementById(id);
    if (!el) return;
    const iconH = el.querySelector('.node-icon').offsetHeight;
    const nodeW = el.offsetWidth;
    el.style.left = Math.round(cx - nodeW / 2) + 'px';
    el.style.top = Math.round(cy - iconH / 2) + 'px';
  }

  function distributeVertically(nodes, centerX, midY, minY, maxY) {
    const n = nodes.length;
    if (n === 0) return;
    if (n === 1) { placeNodeCenter(nodes[0].id, centerX, midY); return; }
    const span = Math.min(maxY - minY, (n - 1) * SIZES.verticalSpacing);
    const startY = midY - span / 2;
    const step = span / (n - 1);
    for (let i = 0; i < n; i++) {
      placeNodeCenter(nodes[i].id, centerX, startY + i * step);
    }
  }

  /**
   * Distribute nodes horizontally, centered on midX at a fixed centerY.
   * minX/maxX define the allowed range for node icon centers.
   */
  function distributeHorizontally(nodes, centerY, minX, maxX) {
    const n = nodes.length;
    if (n === 0) return;
    const midX = (minX + maxX) / 2;
    if (n === 1) { placeNodeCenter(nodes[0].id, midX, centerY); return; }
    const span = maxX - minX;
    const step = span / (n - 1);
    for (let i = 0; i < n; i++) {
      placeNodeCenter(nodes[i].id, minX + i * step, centerY);
    }
  }

  function positionSubZone(nodes, subZoneId, labelId) {
    if (nodes.length === 0) return;
    const pad = SIZES.subZonePad;
    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    nodes.forEach(function(n) {
      const l = parseInt(n.style.left, 10);
      const t = parseInt(n.style.top, 10);
      minX = Math.min(minX, l);
      maxX = Math.max(maxX, l + n.offsetWidth);
      minY = Math.min(minY, t);
      maxY = Math.max(maxY, t + n.offsetHeight);
    });
    const szEl = document.getElementById(subZoneId);
    const zoneLeft = minX - pad;
    const zoneWidth = maxX - minX + pad * 2;
    szEl.style.left = zoneLeft + 'px';
    szEl.style.top = (minY - pad) + 'px';
    szEl.style.width = zoneWidth + 'px';
    szEl.style.height = (maxY - minY + pad * 2) + 'px';

    const labelEl = document.getElementById(labelId);
    labelEl.style.fontSize = SIZES.subZoneLabelFont + 'px';
    labelEl.style.left = (zoneLeft + zoneWidth / 2) + 'px';
    labelEl.style.transform = 'translateX(-50%)';
    labelEl.style.top = (minY - pad - SIZES.subZoneLabelGap) + 'px';
  }

  // ============================================================
  // Edge drawing
  // ============================================================
  function nodeIconRect(id) {
    const el = document.getElementById(id);
    if (!el) return null;
    const icon = el.querySelector('.node-icon');
    return {
      cx: el.offsetLeft + icon.offsetLeft + icon.offsetWidth / 2,
      cy: el.offsetTop + icon.offsetTop + icon.offsetHeight / 2,
      halfW: icon.offsetWidth / 2,
      halfH: icon.offsetHeight / 2
    };
  }

  function rectBorderPoint(cx, cy, halfW, halfH, tx, ty) {
    const dx = tx - cx, dy = ty - cy;
    if (dx === 0 && dy === 0) return { x: cx, y: cy };
    const t = Math.min(
      dx !== 0 ? halfW / Math.abs(dx) : Infinity,
      dy !== 0 ? halfH / Math.abs(dy) : Infinity
    );
    return { x: cx + dx * t, y: cy + dy * t };
  }

  function drawEdge(fromId, toId, style) {
    const from = nodeIconRect(fromId);
    const to = nodeIconRect(toId);
    if (!from || !to) return;
    const p1 = rectBorderPoint(from.cx, from.cy, from.halfW, from.halfH, to.cx, to.cy);
    const p2 = rectBorderPoint(to.cx, to.cy, to.halfW, to.halfH, from.cx, from.cy);

    const prefix = (style === 'active' || style === 'denied') ? style : 'default';
    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', p1.x);
    line.setAttribute('y1', p1.y);
    line.setAttribute('x2', p2.x);
    line.setAttribute('y2', p2.y);
    line.setAttribute('class', style === 'default' ? 'edge' : 'edge ' + style);
    line.setAttribute('marker-start', 'url(#arrow-' + prefix + '-start)');
    line.setAttribute('marker-end', 'url(#arrow-' + prefix + '-end)');
    document.getElementById('edges').appendChild(line);
  }

  function drawExternalEdge(nodeId, label, key) {
    const from = nodeIconRect(nodeId);
    if (!from) return;
    const startY = from.cy - from.halfH;
    const endY = ZONES.orgNetwork.top + SIZES.externalEdgeTopOffset;

    const svg = document.getElementById('edges');
    const style = edgeStyle(key);
    const prefix = (style === 'active' || style === 'denied') ? style : 'default';

    const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    line.setAttribute('x1', from.cx);
    line.setAttribute('y1', startY);
    line.setAttribute('x2', from.cx);
    line.setAttribute('y2', endY);
    line.setAttribute('class', style === 'default' ? 'edge' : 'edge ' + style);
    line.setAttribute('marker-start', 'url(#arrow-' + prefix + '-start)');
    line.setAttribute('marker-end', 'url(#arrow-' + prefix + '-end)');
    svg.appendChild(line);

    // Place the label to the left of the arrow (which, after the -90° rotation,
    // reads as "above" the arrow's direction of travel).
    const labelX = from.cx - 10;
    const labelY = (startY + endY) / 2;
    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', labelX);
    text.setAttribute('y', labelY);
    text.setAttribute('text-anchor', 'middle');
    text.setAttribute('dominant-baseline', 'central');
    text.setAttribute('transform', 'rotate(-90 ' + labelX + ' ' + labelY + ')');
    text.setAttribute('fill', 'currentColor');
    text.setAttribute('font-size', SIZES.labelFont + 'px');
    text.setAttribute('font-family', getComputedStyle(document.body).fontFamily);
    text.setAttribute('font-weight', '500');
    text.textContent = label;
    svg.appendChild(text);
  }

  function edgeStyle(key) {
    if (deniedEdges.has(key)) return 'denied';
    if (activeEdges.has(key)) return 'active';
    return 'default';
  }

  function buildEdgeList() {
    const edges = [];

    // Devices connect directly to agent-platform over mTLS. The gateway only
    // mediates outbound traffic from agents.
    document.querySelectorAll('.user-node').forEach(function(ud) {
      const name = ud.id.replace('node-', '');
      edges.push([ud.id, 'node-agent-platform', edgeStyle(name)]);
    });
    for (let entry of agentRuntimes) {
      const agentId = entry[0], info = entry[1];
      // Outbound: agent-proxy talks to the gateway (mTLS CONNECT).
      edges.push([info.id, 'node-agent-gateway', edgeStyle(agentId)]);
      // Control: platform spawns and drives the agent via the agent-host
      // supervisor. We collapse the supervisor hop visually.
      edges.push(['node-agent-platform', info.id, edgeStyle('platform-' + agentId)]);
    }

    document.querySelectorAll('.example-service').forEach(function(svc) {
      const svcName = svc.id.replace('node-', '');
      edges.push(['node-agent-gateway', svc.id, edgeStyle(svcName)]);
    });

    document.querySelectorAll('.infra-item').forEach(function(infra) {
      const infraName = infra.id.replace('node-', '');
      edges.push(['node-agent-gateway', infra.id, edgeStyle('gateway-' + infraName)]);
      edges.push(['node-agent-platform', infra.id, edgeStyle('platform-' + infraName)]);
    });

    return edges;
  }

  function drawAllEdges() {
    const svg = document.getElementById('edges');
    svg.querySelectorAll('line, text').forEach(function(el) { el.remove(); });

    const edgeList = buildEdgeList();
    for (let i = 0; i < edgeList.length; i++) {
      drawEdge(edgeList[i][0], edgeList[i][1], edgeList[i][2]);
    }
    drawExternalEdge('node-agent-gateway', 'To Anthropic API', 'anthropic');
  }

  // ============================================================
  // Fit topology canvas
  // ============================================================
  function fitTopologyToPanel() {
    const panel = document.getElementById('panel-topology');
    const canvas = document.getElementById('canvas');
    const scaleX = panel.clientWidth / CANVAS.width;
    const scaleY = panel.clientHeight / CANVAS.height;
    const fit = Math.min(scaleX, scaleY);
    const scaledW = CANVAS.width * fit;
    const scaledH = CANVAS.height * fit;
    canvas.style.position = 'absolute';
    canvas.style.left = ((panel.clientWidth - scaledW) / 2) + 'px';
    canvas.style.top = ((panel.clientHeight - scaledH) / 2) + 'px';
    canvas.style.transformOrigin = 'top left';
    canvas.style.transform = 'scale(' + fit + ')';
  }

  /** Full re-layout after topology changes (agent add/remove) */
  function reLayout() {
    computeLayout();
    drawAllEdges();
    fitTopologyToPanel();
  }

  // ============================================================
  // Edge highlighting
  // ============================================================
  const EDGE_HIGHLIGHT_MS = 1500;

  function highlightEdge(key, durationMs) {
    activeEdges.add(key);
    drawAllEdges();
    setTimeout(function() {
      activeEdges.delete(key);
      drawAllEdges();
    }, durationMs || 1500);
  }

  function highlightEdgeDenied(key, durationMs) {
    deniedEdges.add(key);
    drawAllEdges();
    setTimeout(function() {
      deniedEdges.delete(key);
      drawAllEdges();
    }, durationMs || 1500);
  }

  // ============================================================
  // Public API
  // ============================================================
  window.Topology = {
    // Functions
    esc: esc,
    createStaticNodes: createStaticNodes,
    applySizes: applySizes,
    computeLayout: computeLayout,
    drawAllEdges: drawAllEdges,
    fitTopologyToPanel: fitTopologyToPanel,
    reLayout: reLayout,
    addAgentRuntimeNode: addAgentRuntimeNode,
    removeAgentRuntimeNode: removeAgentRuntimeNode,
    addUserNode: addUserNode,
    removeUserNode: removeUserNode,
    highlightEdge: highlightEdge,
    highlightEdgeDenied: highlightEdgeDenied,

    // State (exposed as properties for dashboard read/write access)
    get agentRuntimes() { return agentRuntimes; },
    get agentNodeCounter() { return agentNodeCounter; },
    set agentNodeCounter(v) { agentNodeCounter = v; },
    get activeEdges() { return activeEdges; },
    get deniedEdges() { return deniedEdges; },
    get EDGE_HIGHLIGHT_MS() { return EDGE_HIGHLIGHT_MS; },
  };
})();
