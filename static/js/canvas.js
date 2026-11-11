/* canvas.js — the interactive architecture canvas.
 *
 * A small hand-rolled editor (no frameworks):
 *   - component nodes are absolutely-positioned divs,
 *   - connections are SVG lines between node centers,
 *   - a floating tool row switches select / link / delete,
 *   - the palette on the left places new components.
 *
 * Placing components supports BOTH gestures:
 *   - drag from the palette and release over the canvas (drop),
 *   - click a palette item to arm it, then click the canvas to place.
 *
 * Endpoint telemetry (EDR / Sysmon) is not a separate component: every host
 * carries its own toggles, edited in the inspector.
 *
 * Public API used by app.js:
 *   Canvas.load(json) / Canvas.toJSON() / Canvas.clear()
 *   Canvas.onChange(cb)        — called after every design mutation
 *   Canvas.setRunning(bool)    — lock editing during a simulation run
 *   Canvas.showPath(ids) / Canvas.clearFx() / Canvas.pulse(id) / Canvas.flashBlock(id)
 */
(function () {
  'use strict';

  const wrap = document.getElementById('canvas-wrap');
  const scroller = document.getElementById('canvas-scroll');
  const stage = document.getElementById('zoom-stage');
  const viewEl = document.getElementById('view');
  const svg = document.getElementById('edge-svg');
  const layer = document.getElementById('node-layer');
  const ghost = document.getElementById('place-ghost');
  const paletteEl = document.getElementById('palette');
  const inspector = document.getElementById('inspector');
  const inspBody = document.getElementById('insp-body');   // re-rendered by renderInspector

  // ------------------------------------------------------------------
  // Component catalog: tag shown in the node box, display name, color
  // family, one-line description for the inspector.
  // (edr / sysmon stay here so older saved designs still render; the
  //  palette no longer offers them — hosts carry toggles instead.)
  // ------------------------------------------------------------------
  const TYPES = {
    internet:     { tag: 'INET',  name: 'Internet',            cls: 'net',       desc: 'Entry point of every scenario. Path-based controls (WAF, mail gateway, egress rules) are only evaluated if a path from here to the target exists.' },
    subnet:       { tag: 'SEG',   name: 'Subnet',              cls: 'subnet',    desc: 'Groups the hosts wired to it. Zeek and NetFlow placed on a segment see that segment\u2019s network traffic.' },
    firewall:     { tag: 'FW',    name: 'Firewall',            cls: 'appliance', desc: 'Logs connection 5-tuples on its path. With "default-deny egress" it drops C2/exfil; with segmentation it blocks east-west lateral movement.' },
    waf:          { tag: 'WAF',   name: 'Web app firewall',    cls: 'appliance', desc: 'Sees HTTP payload content on its path and blocks web exploitation of public-facing apps behind it.' },
    mail_gateway: { tag: 'MGW',   name: 'Mail gateway',        cls: 'appliance', desc: 'Sees every email delivered anywhere in the design and can quarantine malicious attachments.' },
    workstation:  { tag: 'WS',    name: 'Workstation',         cls: 'host',      desc: 'A user endpoint. Phishing scenarios land here first.', host: true },
    server_win:   { tag: 'SRV-W', name: 'Windows server',      cls: 'host',      desc: 'Internal Windows server — a classic lateral-movement target (SMB, admin shares).', host: true },
    server_linux: { tag: 'SRV-L', name: 'Linux server',        cls: 'host',      desc: 'Internal Linux server. Note: Sysmon is Windows-only — a deliberate blind spot.', host: true, linux: true },
    web_server:   { tag: 'APP',   name: 'Web server',          cls: 'host',      desc: 'Public-facing application. FIN7-style scenarios land here.', host: true },
    edr:          { tag: 'EDR',   name: 'EDR agent',           cls: 'sensor',    desc: '(legacy component — hosts now carry an EDR toggle in the inspector) Full process tree, command lines, file writes, network with process attribution.' },
    sysmon:       { tag: 'SYS',   name: 'Sysmon / Win event log', cls: 'sensor', desc: '(legacy component — hosts now carry a Sysmon toggle in the inspector) Process creation, script blocks, logons. Windows hosts only.' },
    zeek:         { tag: 'ZK',    name: 'Zeek (SPAN port)',    cls: 'sensor',    desc: 'Network metadata (connections, SNI, HTTP) for the segment it monitors — but zero process context.' },
    ids:          { tag: 'IDS',   name: 'IDS / NDR (SPAN)',    cls: 'sensor',    desc: 'Signature-based network detection (Suricata-style). Monitors the segment it SPANs: exploit/C2/scanning signatures on the payload itself — no process context, so it detects but rarely explains.' },
    netflow:      { tag: 'NF',    name: 'NetFlow collector',   cls: 'sensor',    desc: 'Raw 5-tuples. Link to a segment or to the backbone firewall (then it sees everything transiting).' },
    siem:         { tag: 'SIEM',  name: 'SIEM',                cls: 'sensor',    desc: 'Only shows what other sensors ship to it. Wire hosts, network sensors or cloud services to it. Cloud audit rows reach your console ONLY through a SIEM link.' },
    idp:          { tag: 'IdP',   name: 'IdP / SSO',           cls: 'cloud',     desc: 'Cloud identity. With MFA on, phished credentials alone cannot sign in. Exploiting an exposed IdP appliance is nearly invisible (appliance = black box).' },
    iam:          { tag: 'IAM',   name: 'IAM / control plane', cls: 'cloud',     desc: 'Cloud API activity lives in its own audit log — invisible until shipped to a SIEM.' },
    s3:           { tag: 'S3',    name: 'S3 bucket',           cls: 'cloud',     desc: 'Cloud storage. "Block public / least-privilege" denies bulk reads; access rows are only visible via a SIEM.' },
  };

  const PALETTE_GROUPS = [
    { group: 'Network', items: ['internet', 'subnet', 'firewall', 'waf', 'mail_gateway'] },
    { group: 'Compute', items: ['workstation', 'server_win', 'server_linux', 'web_server'] },
    { group: 'Detection', items: ['zeek', 'ids', 'netflow', 'siem'] },   // EDR/Sysmon moved onto hosts
    { group: 'Identity & Cloud', items: ['idp', 'iam', 's3'] },
  ];

  // ------------------------------------------------------------------
  // Editor state
  // ------------------------------------------------------------------
  let G = { nodes: [], edges: [], seq: 1 };
  let tool = 'select';          // select | link | delete | place:<type>
  let sel = null;               // {kind:'node'|'edge', id}
  let linkFrom = null;          // node id waiting for the link's second click
  let armed = null;             // palette type waiting to be placed
  let running = false;
  let changeCb = null;
  let drag = null;              // active node drag info
  let palDrag = null;           // active palette drag info {type, moved}

  // -- zoom / multi-select / per-asset line hiding -------------------------
  let zoom = 1;                 // current canvas scale (1 = 100%)
  let prevZoom = 1;             // zoom to restore after a run's auto-fit
  let marquee = null;           // active rubber-band {x0,y0,x1,y1,moved}
  let suppressClick = false;    // swallow the click that ends a marquee drag
  const selection = new Set();   // multi-selected node ids (marquee / shift-click)
  const hiddenNodes = new Set(); // assets whose connection lines are hidden
  const marqueeEl = document.createElement('div');
  marqueeEl.id = 'marquee';
  viewEl.appendChild(marqueeEl);

  // ---------------------------- helpers ------------------------------
  const node = (id) => G.nodes.find((n) => n.id === id);
  const el = (id) => layer.querySelector(`[data-id="${id}"]`);
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  function emitChange() { if (changeCb) changeCb(toJSON()); }

  function uniqueLabel(type) {
    const base = TYPES[type].name.replace(/ \(.*\)/, '');
    const used = new Set(G.nodes.map((n) => n.label));
    let label = base, i = 2;
    while (used.has(label)) label = `${base} ${i++}`;
    return label;
  }

  function setGhostPos(clientX, clientY) {
    const rect = wrap.getBoundingClientRect();
    ghost.style.left = (clientX - rect.left) + 'px';
    ghost.style.top = (clientY - rect.top) + 'px';
  }

  // ---------------- zoom & coordinate mapping ---------------------------
  function toCanvas(clientX, clientY) {
    // screen position -> logical canvas position (scroll + zoom aware)
    const r = scroller.getBoundingClientRect();
    return { x: (clientX - r.left + scroller.scrollLeft) / zoom,
             y: (clientY - r.top + scroller.scrollTop) / zoom };
  }

  // The canvas is an expanding world: it always covers the viewport, the
  // zoomed-out field of view and every node (plus a margin), so dragging an
  // asset toward any edge simply grows the canvas — there is no hard wall.
  let worldW = 0, worldH = 0;   // logical (unzoomed) canvas size
  const WORLD_PAD = 140;        // margin kept beyond the rightmost node
  const WORLD_CAP = 40000;      // sanity ceiling

  function computeWorld() {
    let maxX = 0, maxY = 0;
    for (const n of G.nodes) {
      if (n.x > maxX) maxX = n.x;
      if (n.y > maxY) maxY = n.y;
    }
    // when zoomed out, the visible logical span is viewport / zoom — the
    // world must cover it, otherwise the old edge shows as an invisible wall
    const visW = zoom < 1 ? wrap.clientWidth / zoom : 0;
    const visH = zoom < 1 ? wrap.clientHeight / zoom : 0;
    worldW = Math.min(WORLD_CAP,
      Math.max(wrap.clientWidth, visW, maxX + WORLD_PAD));
    worldH = Math.min(WORLD_CAP,
      Math.max(wrap.clientHeight, visH, maxY + WORLD_PAD));
  }

  function applyView() {
    // stage carries the layout size (world*zoom) so the scrollbars track
    // the scaled content; #view stays world-sized and gets transform-scaled
    computeWorld();
    stage.style.width = (worldW * zoom) + 'px';
    stage.style.height = (worldH * zoom) + 'px';
    viewEl.style.width = worldW + 'px';
    viewEl.style.height = worldH + 'px';
    viewEl.style.transform = `scale(${zoom})`;
    // the SVG must stay 1:1 with #view: a stale viewBox letterboxes the
    // edges away from the nodes after any world/zoom change (the bug where
    // lines only re-aligned after clicking the canvas)
    svg.setAttribute('viewBox', `0 0 ${worldW} ${worldH}`);
    const zl = document.getElementById('zoom-label');
    if (zl) zl.textContent = Math.round(zoom * 100) + '%';
  }

  function setZoomAt(nz, clientX, clientY) {
    // change zoom while keeping the canvas point under the cursor fixed
    const r = scroller.getBoundingClientRect();
    const cx = clientX - r.left, cy = clientY - r.top;
    const lx = (cx + scroller.scrollLeft) / zoom;
    const ly = (cy + scroller.scrollTop) / zoom;
    zoom = Math.min(3, Math.max(0.25, nz));
    applyView();
    scroller.scrollLeft = lx * zoom - cx;
    scroller.scrollTop = ly * zoom - cy;
  }

  scroller.addEventListener('wheel', (ev) => {
    ev.preventDefault();
    setZoomAt(zoom * (ev.deltaY < 0 ? 1.15 : 1 / 1.15), ev.clientX, ev.clientY);
  }, { passive: false });

  function arm(type) {          // arm a palette type (show ghost, switch tool)
    armed = type;
    tool = type ? `place:${type}` : 'select';
    ghost.classList.toggle('hidden', !type);
    if (type) ghost.innerHTML = `<div class="node" data-cls="${TYPES[type].cls}">
        <div class="tag">${TYPES[type].tag}</div></div>`;
    syncPalette(); syncToolbar();
  }

  // ---------------------------- palette ------------------------------
  function buildPalette() {
    paletteEl.innerHTML = '';
    for (const g of PALETTE_GROUPS) {
      const h = document.createElement('div');
      h.className = 'pal-group'; h.textContent = g.group;
      paletteEl.appendChild(h);
      for (const t of g.items) paletteEl.appendChild(makePaletteItem(t));
    }
  }

  function makePaletteItem(t) {
    const item = document.createElement('div');
    item.className = 'pal-item'; item.dataset.type = t;
    item.innerHTML = `<span class="pal-tag" data-cls="${TYPES[t].cls}">${TYPES[t].tag}</span>
                      <span>${esc(TYPES[t].name)}</span>`;

    // press on the item: start a potential drag AND arm the ghost, so the
    // component follows the pointer immediately (fixes "can't put it down":
    // releasing over the canvas now DROPS it; releasing elsewhere cancels).
    item.addEventListener('pointerdown', (ev) => {
      if (running || ev.button !== 0) return;
      ev.preventDefault();
      palDrag = { type: t, moved: false };
      try { item.setPointerCapture(ev.pointerId); } catch { /* ok */ }
      arm(t);
      setGhostPos(ev.clientX, ev.clientY);
    });
    item.addEventListener('pointermove', (ev) => {
      if (!palDrag || palDrag.type !== t) return;
      palDrag.moved = true;
      setGhostPos(ev.clientX, ev.clientY);      // capture keeps events flowing
    });
    item.addEventListener('pointerup', (ev) => {
      if (!palDrag || palDrag.type !== t) return;
      palDrag = null;
      const hit = document.elementFromPoint(ev.clientX, ev.clientY);
      if (hit && hit.closest('#canvas-wrap')) {
        // drop: place the component where the pointer is
        const p = toCanvas(ev.clientX, ev.clientY);
        place(armed, p.x, p.y);
        if (isNarrow()) closePaletteDrawer();  // phone drawer gets out of the way
        arm(null);
      } else if (hit && hit.closest('.pal-item') === item) {
        // plain click on the item: stay armed, user will click the canvas
      } else {
        arm(null);                               // released nowhere useful
      }
    });
    item.addEventListener('pointercancel', () => { palDrag = null; arm(null); });
    return item;
  }

  function syncPalette() {
    paletteEl.querySelectorAll('.pal-item').forEach((p) =>
      p.classList.toggle('armed', p.dataset.type === armed));
  }

  // ---------------------------- toolbar ------------------------------
  let toolbar;
  function buildToolbar() {
    toolbar = document.createElement('div');
    toolbar.style.cssText = 'position:absolute;top:8px;right:10px;z-index:40;';
    toolbar.id = 'canvas-toolbar';
    toolbar.innerHTML = `
      <button class="btn" data-t="select" data-full="Select" data-short="Sel">Select</button>
      <button class="btn" data-t="lasso" data-full="Box" data-short="Box"
        title="Drag a box on the canvas to multi-select — the touch-friendly rubber band">Box</button>
      <button class="btn" data-t="link" data-full="Link / unlink" data-short="Link"
        title="Click node A then node B — toggles the connection">Link / unlink</button>
      <button class="btn" data-t="delete" data-full="Delete" data-short="Del">Delete</button>`;
    toolbar.querySelectorAll('button').forEach((b) =>
      b.addEventListener('click', () => { if (!running) setTool(b.dataset.t); }));
    wrap.appendChild(toolbar);
    buildZoombar();
    applyToolbarLabels();
  }

  // phones get short labels: four full-width buttons cannot fit a 390px row
  function applyToolbarLabels() {
    const narrow = window.matchMedia('(max-width: 640px)').matches;
    const coarse = window.matchMedia('(pointer: coarse)').matches;
    toolbar.querySelectorAll('button').forEach((b) => {
      if (!b.dataset.short) return;
      b.textContent = narrow ? b.dataset.short : b.dataset.full;
    });
    // desktop select already rubber-bands with the mouse: the Box tool only
    // earns its space where a finger cannot shift-drag
    const box = toolbar.querySelector('[data-t=lasso]');
    if (box) box.style.display = (narrow || coarse) ? '' : 'none';
  }

  // zoom + line-visibility controls (fixed to the wrap, outside the scroller)
  function buildZoombar() {
    const zb = document.createElement('div');
    zb.id = 'zoombar';
    zb.innerHTML = `
      <button class="btn" id="z-out" title="zoom out (the mouse wheel zooms too)">&minus;</button>
      <button class="btn" id="z-reset" title="reset zoom to 100%"><span id="zoom-label">100%</span></button>
      <button class="btn" id="z-in" title="zoom in (the mouse wheel zooms too)">+</button>
      <button class="btn" id="z-unhide" title="show every hidden connection line again">unhide lines</button>`;
    const center = () => {
      const r = scroller.getBoundingClientRect();
      return [r.left + r.width / 2, r.top + r.height / 2];
    };
    zb.querySelector('#z-in').addEventListener('click', () => { const [x, y] = center(); setZoomAt(zoom * 1.2, x, y); });
    zb.querySelector('#z-out').addEventListener('click', () => { const [x, y] = center(); setZoomAt(zoom / 1.2, x, y); });
    zb.querySelector('#z-reset').addEventListener('click', () => { const [x, y] = center(); setZoomAt(1, x, y); });
    zb.querySelector('#z-unhide').addEventListener('click', () => {
      if (!hiddenNodes.size) return;
      hiddenNodes.clear(); renderEdges(); renderNodes();
    });
    wrap.appendChild(zb);
  }

  function setTool(t) {
    tool = t; armed = null; linkFrom = null;
    ghost.classList.add('hidden');
    if (t !== 'select') select(null);
    syncPalette(); syncToolbar();
  }

  function syncToolbar() {
    toolbar.querySelectorAll('button').forEach((b) => {
      b.style.borderColor = (tool === b.dataset.t) ? 'var(--teal)' : '';
      b.style.color = (tool === b.dataset.t) ? 'var(--teal)' : '';
    });
  }

  // ---------------------------- rendering ------------------------------
  function fitView() {
    // Auto-fit during a run so the whole design stays visible in the
    // smaller (split-screen) canvas area. Design mode keeps the user zoom.
    if (!running || !G.nodes.length) { applyView(); return; }
    fitContent();
  }

  function fitContent() {
    if (!G.nodes.length) return;
    const xs = G.nodes.map((n) => n.x), ys = G.nodes.map((n) => n.y);
    const minX = Math.min(...xs) - 90, maxX = Math.max(...xs) + 90;
    const minY = Math.min(...ys) - 70, maxY = Math.max(...ys) + 70;
    zoom = Math.max(0.2, Math.min(1.25,
      wrap.clientWidth / (maxX - minX), wrap.clientHeight / (maxY - minY)));
    applyView();
    // scroll the fitted content into view from the top-left corner
    scroller.scrollLeft = Math.max(0, (minX * zoom) - 20);
    scroller.scrollTop = Math.max(0, (minY * zoom) - 20);
  }

  function renderAll() {
    applyView();      // the world may need to grow/shrink to fit the nodes
    renderEdges();
    renderNodes();
    renderInspector();
  }

  // Small chips under the node label showing active controls/agents.
  function badgesOf(n) {
    const out = [];
    if (n.props && n.props.edr) out.push('EDR');
    if (n.props && n.props.sysmon) out.push('SYS');
    if (n.type === 'firewall') {
      if (n.props.egress === 'default-deny') out.push('DENY');
      if (n.props.segmentation) out.push('SEG');
    }
    if (n.type === 'idp' && n.props.mfa) out.push('MFA');
    if (n.type === 's3' && n.props.block_public) out.push('LOCK');
    return out;
  }

  function renderNodes() {
    layer.innerHTML = '';
    for (const n of G.nodes) {
      const d = document.createElement('div');
      d.className = 'node'; d.dataset.id = n.id; d.dataset.cls = TYPES[n.type] ? TYPES[n.type].cls : 'net';
      d.style.left = n.x + 'px'; d.style.top = n.y + 'px';
      const badges = badgesOf(n);
      const hidden = hiddenNodes.has(n.id);
      d.innerHTML = `<div class="tag">${(TYPES[n.type] || { tag: n.type }).tag}</div>
                     <div class="lbl">${esc(n.label)}</div>` +
        (badges.length ? `<div class="badges">${badges.map((b) => `<i>${b}</i>`).join('')}</div>` : '') +
        `<button class="eye-btn${hidden ? ' off' : ''}" title="${hidden ? 'show' : 'hide'} this asset's connection lines">${hidden ? '\u25CC' : '\u25C9'}</button>`;
      if (sel && sel.kind === 'node' && sel.id === n.id) d.classList.add('sel');
      if (selection.has(n.id)) d.classList.add('multi-sel');
      if (linkFrom === n.id) d.classList.add('link-from');
      attachNodeEvents(d, n, hidden);
      layer.appendChild(d);
    }
  }

  function renderEdges() {
    // viewBox is owned by applyView() so edges can never drift out of sync
    let out = `<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5"
      markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#2b3b4d"/></marker></defs>`;
    for (const e of G.edges) {
      const a = node(e.src), b = node(e.dst);
      if (!a || !b) continue;
      // per-asset line hiding: either endpoint can hide the edge
      if (hiddenNodes.has(a.id) || hiddenNodes.has(b.id)) continue;
      const selected = sel && sel.kind === 'edge' && sel.id === e.id;
      // fat invisible "hit" line first: makes thin edges clickable/unlinkable
      out += `<line class="edge-hit" data-id="${e.id}"
          x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>`;
      out += `<line class="edge${selected ? ' sel' : ''}" data-id="${e.id}"
          x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"
          ${selected ? '' : 'marker-end="url(#arr)"'}/>`;
    }
    svg.innerHTML = out;
    // interactions live on the fat hit lines
    svg.querySelectorAll('.edge-hit').forEach((line) =>
      line.addEventListener('click', (ev) => {
        if (running || armed) return;
        ev.stopPropagation();
        if (tool === 'delete') { removeEdge(line.dataset.id); return; }
        select({ kind: 'edge', id: line.dataset.id });
      }));
  }

  // ---------------------------- interactions ------------------------------
  function attachNodeEvents(d, n, hidden) {
    // the ◉ toggle is its own control — never start a node drag from it
    const eye = d.querySelector('.eye-btn');
    eye.addEventListener('pointerdown', (ev) => ev.stopPropagation());
    eye.addEventListener('click', (ev) => {
      ev.stopPropagation();
      if (running) return;                    // visuals locked during playback
      if (hiddenNodes.has(n.id)) hiddenNodes.delete(n.id); else hiddenNodes.add(n.id);
      renderEdges(); renderNodes();
    });

    d.addEventListener('pointerdown', (ev) => {
      if (ev.target.closest('.eye-btn')) return;
      if (running) { select({ kind: 'node', id: n.id }); return; }
      if (armed) return;                       // placing a new component wins
      if (ev.shiftKey && tool === 'select') {  // additive multi-select
        if (selection.has(n.id)) selection.delete(n.id); else selection.add(n.id);
        renderNodes(); renderInspector();
        return;
      }
      if (tool === 'delete') { removeNode(n.id); return; }
      if (tool === 'link') {
        if (!linkFrom) { linkFrom = n.id; renderNodes(); }
        else if (linkFrom !== n.id) { toggleEdge(linkFrom, n.id); linkFrom = null; renderAll(); emitChange(); }
        return;
      }
      if (!selection.has(n.id)) selection.clear();   // clicking outside resets it
      // drag: remember each node's origin so a multi-selection moves as one
      const ids = (selection.has(n.id) && selection.size > 1) ? [...selection] : [n.id];
      const origins = new Map();
      for (const id of ids) { const m = node(id); if (m) origins.set(id, { x: m.x, y: m.y }); }
      ev.preventDefault();
      const p0 = toCanvas(ev.clientX, ev.clientY);
      drag = { id: n.id, px: p0.x, py: p0.y, origins, moved: false };
      try { d.setPointerCapture(ev.pointerId); } catch { /* ok */ }
    });
    d.addEventListener('pointermove', (ev) => {
      if (!drag || drag.id !== n.id) return;
      const p = toCanvas(ev.clientX, ev.clientY);
      const dx = p.x - drag.px, dy = p.y - drag.py;
      if (Math.abs(dx) + Math.abs(dy) > 2) drag.moved = true;
      for (const [id, o] of drag.origins) {
        const m = node(id); if (!m) continue;
        // no upper clamp: the world below grows to fit the drag, so an
        // asset can be carried anywhere (only a sanity ceiling remains)
        m.x = Math.max(24, Math.min(WORLD_CAP - 24, o.x + dx));
        m.y = Math.max(24, Math.min(WORLD_CAP - 24, o.y + dy));
        const eln = el(id);
        if (eln) { eln.style.left = m.x + 'px'; eln.style.top = m.y + 'px'; }
      }
      // grow the canvas under the cursor — the group's extreme node drives it
      let extX = 0, extY = 0;
      for (const [id] of drag.origins) {
        const m = node(id); if (!m) continue;
        if (m.x > extX) extX = m.x;
        if (m.y > extY) extY = m.y;
      }
      if (extX > worldW - WORLD_PAD || extY > worldH - WORLD_PAD) applyView();
      renderEdges();
    });
    const endDrag = (ev) => {
      if (!drag || drag.id !== n.id) return;
      if (drag.moved) { emitChange(); }
      else { select({ kind: 'node', id: n.id }); }
      try { d.releasePointerCapture(ev.pointerId); } catch { /* already up */ }
      drag = null;
    };
    d.addEventListener('pointerup', endDrag);
    d.addEventListener('pointercancel', endDrag);   // e.g. touch scroll steals the pointer
    // block HTML5 drag ghosting
    d.addEventListener('dragstart', (e) => e.preventDefault());
  }

  wrap.addEventListener('mousemove', (ev) => {
    if (!armed) return;
    setGhostPos(ev.clientX, ev.clientY);
  });

  // ------------------ rubber-band multi-select -----------------------------
  function drawMarquee() {
    if (!marquee) return;
    marqueeEl.style.display = 'block';
    marqueeEl.style.left = Math.min(marquee.x0, marquee.x1) + 'px';
    marqueeEl.style.top = Math.min(marquee.y0, marquee.y1) + 'px';
    marqueeEl.style.width = Math.abs(marquee.x1 - marquee.x0) + 'px';
    marqueeEl.style.height = Math.abs(marquee.y1 - marquee.y0) + 'px';
  }

  scroller.addEventListener('pointerdown', (ev) => {
    if (running || ev.button !== 0 || armed) return;
    if (ev.pointerType === 'touch' && tool !== 'lasso') return;   // a finger pans instead
    if (!ev.isPrimary) return;                                    // pinch's second finger
    if (ev.target.closest('.node') || ev.target.closest('button') ||
        ev.target.closest('.edge-hit')) return;
    const p = toCanvas(ev.clientX, ev.clientY);
    marquee = { x0: p.x, y0: p.y, x1: p.x, y1: p.y, moved: false };
    try { scroller.setPointerCapture(ev.pointerId); } catch { /* ok */ }
    drawMarquee();
  });
  scroller.addEventListener('pointermove', (ev) => {
    if (!marquee) return;
    const p = toCanvas(ev.clientX, ev.clientY);
    marquee.x1 = p.x; marquee.y1 = p.y;
    if (Math.abs(marquee.x1 - marquee.x0) + Math.abs(marquee.y1 - marquee.y0) > 4) {
      marquee.moved = true;
    }
    drawMarquee();
  });
  scroller.addEventListener('pointerup', () => {
    if (!marquee) return;
    const m = marquee; marquee = null; marqueeEl.style.display = 'none';
    if (!m.moved) return;                     // plain click: the click handler decides
    const x0 = Math.min(m.x0, m.x1), x1 = Math.max(m.x0, m.x1);
    const y0 = Math.min(m.y0, m.y1), y1 = Math.max(m.y0, m.y1);
    selection.clear();
    sel = null;
    for (const n of G.nodes) {
      // nodes are center-positioned; pad by their half-size (~54x32)
      if (n.x >= x0 - 54 && n.x <= x1 + 54 && n.y >= y0 - 32 && n.y <= y1 + 32) {
        selection.add(n.id);
      }
    }
    renderNodes(); renderInspector();
    if (selection.size) { inspPinned = true; syncInsp(); }   // phones: open the sheet
    suppressClick = true;                     // don't let the click clear it again
  });
  scroller.addEventListener('pointercancel', () => {
    // native scroll (or the OS) stole the pointer — never leave a stale rect
    if (!marquee) return;
    marquee = null; marqueeEl.style.display = 'none';
  });

  wrap.addEventListener('click', (ev) => {
    if (suppressClick) { suppressClick = false; return; }
    if (running || ev.target.closest('.node') || ev.target.closest('.edge-hit') || ev.target.closest('button')) return;
    if (armed) {
      const p = toCanvas(ev.clientX, ev.clientY);
      place(armed, p.x, p.y);
      if (isNarrow()) closePaletteDrawer();    // placed from the drawer: put it away
      if (!ev.shiftKey) arm(null);
    } else {
      if (selection.size) { selection.clear(); renderNodes(); }
      select(null);
    }
  });

  // ------------------ spacebar canvas panning ------------------------------
  // Hold space and drag anywhere to pan — the same gesture design tools use.
  let spaceDown = false;
  let pan = null;               // {sx, sy, sl, st} pointer + scroll start

  function setSpace(v) {
    if (spaceDown === v) return;
    spaceDown = v;
    wrap.classList.toggle('space-pan', v);
    if (!v && pan) { pan = null; wrap.classList.remove('panning'); }
  }

  // capture phase: beats the node-drag / marquee / edge handlers, so the
  // first press-drag while space is held pans instead of moving an asset
  scroller.addEventListener('pointerdown', (ev) => {
    if (!spaceDown || ev.button !== 0) return;
    ev.preventDefault();
    ev.stopPropagation();
    suppressClick = true;       // a pan is not a click: keep the selection
    pan = { sx: ev.clientX, sy: ev.clientY,
            sl: scroller.scrollLeft, st: scroller.scrollTop };
    wrap.classList.add('panning');
    try { scroller.setPointerCapture(ev.pointerId); } catch { /* ok */ }
  }, true);
  scroller.addEventListener('pointermove', (ev) => {
    if (!pan) return;
    scroller.scrollLeft = pan.sl - (ev.clientX - pan.sx);
    scroller.scrollTop = pan.st - (ev.clientY - pan.sy);
  }, true);
  scroller.addEventListener('pointerup', () => {
    if (!pan) return;
    pan = null; wrap.classList.remove('panning');
  }, true);
  scroller.addEventListener('pointercancel', () => {
    if (!pan) return;
    pan = null; wrap.classList.remove('panning');
  }, true);

  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') { setTool('select'); select(null); if (selection.size) { selection.clear(); renderNodes(); } }
    const tag = (document.activeElement || {}).tagName;
    // space = pan modifier (keep it out of text inputs; a focused button is
    // blurred instead — space after clicking a button must pan, not re-click)
    if (ev.key === ' ') {
      if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return;
      ev.preventDefault();                    // don't scroll the page instead
      if (tag === 'BUTTON' && document.activeElement.blur) {
        document.activeElement.blur();
      }
      if (!ev.repeat) setSpace(true);
      return;
    }
    if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return;
    if ((ev.key === 'Delete' || ev.key === 'Backspace') && !running) {
      if (selection.size) {
        for (const id of [...selection]) removeNode(id);
        selection.clear();
      } else if (sel) {
        if (sel.kind === 'node') removeNode(sel.id); else removeEdge(sel.id);
      }
    }
  });
  document.addEventListener('keyup', (ev) => {
    if (ev.key === ' ') setSpace(false);
  });
  window.addEventListener('blur', () => setSpace(false));   // alt-tab safety

  // ---------------- touch: one-finger pan + two-finger pinch -----------------
  // Touch has no spacebar and no wheel. One finger on empty canvas pans the
  // viewport (design-tool style), two fingers pinch-zoom around the midpoint.
  // The rubber-band stays reachable through the Box (lasso) tool.
  const touches = new Map();      // pointerId -> latest {x, y}
  let pinch = null;               // {d0, z0, cx, cy}
  let touchPan = null;            // {sx, sy, sl, st, moved}

  const isNarrow = () => window.matchMedia('(max-width: 899px)').matches;
  let inspPinned = true;         // false after the user closed the sheet manually
  function inspSheet(open) { document.body.classList.toggle('insp-open', !!open); }
  function syncInsp() {
    if (!isNarrow()) return;
    const has = !!(sel || selection.size);
    if (!has) { inspPinned = true; inspSheet(false); }
    else if (inspPinned) inspSheet(true);
  }
  function closePaletteDrawer() { document.body.classList.remove('palette-open'); }

  scroller.addEventListener('pointerdown', (ev) => {
    if (ev.pointerType !== 'touch') return;
    touches.set(ev.pointerId, { x: ev.clientX, y: ev.clientY });
    if (touches.size >= 2 && !drag) {
      // pinch wins over any single-finger gesture in progress
      stopTouchPan();
      if (marquee) { marquee = null; marqueeEl.style.display = 'none'; }
      const pts = [...touches.values()];
      const d = Math.hypot(pts[0].x - pts[1].x, pts[0].y - pts[1].y);
      if (d > 0) {
        pinch = { d0: d, z0: zoom,
                  cx: (pts[0].x + pts[1].x) / 2, cy: (pts[0].y + pts[1].y) / 2 };
        ev.preventDefault();
      }
      return;
    }
    if (touches.size === 1 && !drag && !armed &&
        (running || tool === 'select') &&
        !ev.target.closest('.node') && !ev.target.closest('button') &&
        !ev.target.closest('.edge-hit')) {
      // one finger on empty canvas pans the canvas (works during runs too)
      touchPan = { sx: ev.clientX, sy: ev.clientY,
                   sl: scroller.scrollLeft, st: scroller.scrollTop, moved: false };
      wrap.classList.add('panning');
      try { scroller.setPointerCapture(ev.pointerId); } catch { /* ok */ }
    }
  }, true);

  scroller.addEventListener('pointermove', (ev) => {
    if (ev.pointerType !== 'touch') return;
    const t = touches.get(ev.pointerId);
    if (t) { t.x = ev.clientX; t.y = ev.clientY; }
    if (pinch && touches.size >= 2) {
      const pts = [...touches.values()];
      const d = Math.hypot(pts[0].x - pts[1].x, pts[0].y - pts[1].y);
      if (d > 0) setZoomAt(pinch.z0 * (d / pinch.d0), pinch.cx, pinch.cy);
      return;
    }
    if (touchPan) {
      const dx = ev.clientX - touchPan.sx, dy = ev.clientY - touchPan.sy;
      if (Math.abs(dx) + Math.abs(dy) > 3) touchPan.moved = true;
      scroller.scrollLeft = touchPan.sl - dx;
      scroller.scrollTop = touchPan.st - dy;
    }
  }, true);

  function stopTouchPan() {
    if (touchPan && touchPan.moved) {
      suppressClick = true;                    // a pan is not a click
      setTimeout(() => { suppressClick = false; }, 0);   // residue guard
    }
    touchPan = null;
    wrap.classList.remove('panning');
  }
  function touchEnd(ev) {
    touches.delete(ev.pointerId);
    if (pinch && touches.size < 2) {
      pinch = null;
      suppressClick = true;
      setTimeout(() => { suppressClick = false; }, 0);   // click, if any, goes first
    }
    if (touchPan && !touches.size) stopTouchPan();
  }
  scroller.addEventListener('pointerup', touchEnd, true);
  scroller.addEventListener('pointercancel', touchEnd, true);

  // mobile chrome: hamburger-close, palette drawer toggle, inspector sheet close
  document.getElementById('btn-menu').addEventListener('click', () => {
    document.body.classList.toggle('menu-open');
  });
  document.getElementById('pal-toggle').addEventListener('click', () => {
    document.body.classList.toggle('palette-open');
  });
  document.getElementById('insp-close').addEventListener('click', () => {
    inspPinned = false; inspSheet(false);
  });
  window.addEventListener('resize', applyToolbarLabels);

  // ---------------------------- mutations ------------------------------
  function place(type, x, y) {
    if (!type) return;
    const n = { id: 'n' + (G.seq++), type, label: uniqueLabel(type), x, y, props: {} };
    if (type === 'firewall') n.props = { egress: 'default-allow', segmentation: false };
    if (type === 'idp') n.props = { mfa: false };
    if (type === 's3') n.props = { block_public: false };
    G.nodes.push(n);
    renderAll(); emitChange();
    select({ kind: 'node', id: n.id });
  }

  // kept for compatibility with older call sites/tests
  function addNode(type, x, y) { place(type, x, y); }

  function toggleEdge(src, dst) {
    // the Link tool is a toggle: same gesture links and unlinks
    const existing = G.edges.find((e) =>
      (e.src === src && e.dst === dst) || (e.src === dst && e.dst === src));
    if (existing) { removeEdge(existing.id); return false; }
    G.edges.push({ id: 'e' + (G.seq++), src, dst });
    return true;
  }

  function addEdge(src, dst) {
    const dup = G.edges.some((e) =>
      (e.src === src && e.dst === dst) || (e.src === dst && e.dst === src));
    if (!dup) G.edges.push({ id: 'e' + (G.seq++), src, dst });
  }

  function removeNode(id) {
    G.nodes = G.nodes.filter((n) => n.id !== id);
    G.edges = G.edges.filter((e) => e.src !== id && e.dst !== id);
    if (sel && sel.id === id) sel = null;
    renderAll(); emitChange();
    syncInsp();
  }

  function removeEdge(id) {
    G.edges = G.edges.filter((e) => e.id !== id);
    if (sel && sel.id === id) sel = null;
    renderAll(); emitChange();
  }

  // ---------------------------- inspector ------------------------------
  function renderInspector() {
    if (!sel) {
      if (selection.size) {          // rubber-band selection, nothing single
        inspBody.innerHTML = `<div class="insp"><h3>${selection.size} assets selected</h3>
          <div class="meta">Drag any of them to move the whole group.
          Del / Backspace removes all of them. Click empty canvas to clear.</div>
          <button class="btn danger" id="insp-del-multi">Delete selected</button></div>`;
        inspBody.querySelector('#insp-del-multi').onclick = () => {
          for (const id of [...selection]) removeNode(id);
          selection.clear();
        };
        return;
      }
      inspBody.innerHTML = `<div class="insp-empty">Select a component to inspect it.<br><br>
        Drag components from the palette (or click, then click the canvas).
        Hosts carry their own <b>EDR / Sysmon</b> toggles here. The link tool
        toggles connections; select any wire to unlink it. Drag on empty
        canvas to multi-select; the &#9679; on a node hides its lines.</div>`;
      return;
    }
    if (sel.kind === 'edge') {
      const e = G.edges.find((x) => x.id === sel.id); if (!e) { sel = null; return renderInspector(); }
      const a = node(e.src), b = node(e.dst);
      inspBody.innerHTML = `<div class="insp"><h3>Connection</h3>
        <div class="meta">${esc(a ? a.label : '?')} &harr; ${esc(b ? b.label : '?')}</div>
        <button class="btn danger" id="insp-del">Unlink</button></div>`;
      inspBody.querySelector('#insp-del').onclick = () => removeEdge(e.id);
      return;
    }
    const n = node(sel.id); if (!n) { sel = null; return renderInspector(); }
    const t = TYPES[n.type] || {};
    let propsHtml = '';
    // hosts carry their endpoint telemetry as toggles on the asset itself
    if (t.host) {
      propsHtml = `<div class="insp-sec">Endpoint telemetry</div>
        <label class="chk"><input type="checkbox" id="p-edr"${n.props.edr ? ' checked' : ''}>
          EDR agent <span class="chk-sub">full process tree, cmdline, network w/ attribution; can block some techniques</span></label>
        <label class="chk${t.linux ? ' off' : ''}"><input type="checkbox" id="p-sysmon"${n.props.sysmon ? ' checked' : ''}${t.linux ? ' disabled' : ''}>
          Sysmon / Windows event log <span class="chk-sub">${t.linux ? 'Windows only — a deliberate blind spot on Linux' : 'process creation, logons (4624), no network attribution'}</span></label>`;
    } else if (n.type === 'firewall') {
      propsHtml = `<div class="row"><label>Egress policy</label>
        <select id="p-egress">
          <option value="default-allow"${n.props.egress !== 'default-deny' ? ' selected' : ''}>default-allow</option>
          <option value="default-deny"${n.props.egress === 'default-deny' ? ' selected' : ''}>default-deny</option>
        </select></div>
        <label class="chk"><input type="checkbox" id="p-seg"${n.props.segmentation ? ' checked' : ''}>
          east-west segmentation (blocks SMB/RDP between segments)</label>`;
    } else if (n.type === 'idp') {
      propsHtml = `<label class="chk"><input type="checkbox" id="p-mfa"${n.props.mfa ? ' checked' : ''}>
        require MFA (phished passwords alone fail)</label>`;
    } else if (n.type === 's3') {
      propsHtml = `<label class="chk"><input type="checkbox" id="p-bp"${n.props.block_public ? ' checked' : ''}>
        block public / least-privilege IAM (denies bulk GetObject)</label>`;
    }
    // every connection of this node, each with its own unlink button
    const links = G.edges.filter((e) => e.src === n.id || e.dst === n.id);
    const linksHtml = links.length
      ? links.map((e) => {
          const other = node(e.src === n.id ? e.dst : e.src);
          return `<div class="lnk"><span>${esc(other ? other.label : '?')}</span>
                  <button class="mini" data-edge="${e.id}" title="Unlink">unlink</button></div>`;
        }).join('')
      : '<div class="meta">not linked to anything yet</div>';

    inspBody.innerHTML = `<div class="insp"><h3>${esc(t.name || n.type)}</h3>
      <div class="row"><label>Label</label>
        <input type="text" id="p-label" value="${esc(n.label)}"></div>
      ${propsHtml}
      <div class="insp-sec">Connections (${links.length})</div>
      ${linksHtml}
      <div class="meta" style="margin-top:10px">${esc(t.desc || '')}</div>
      <button class="btn danger" id="insp-del">Delete component</button></div>`;

    inspBody.querySelector('#p-label').addEventListener('input', (ev) => {
      n.label = ev.target.value || n.label;
      const lbl = el(n.id) && el(n.id).querySelector('.lbl');
      if (lbl) lbl.textContent = n.label;
      emitChange();
    });
    const bind = (id, prop, isSel) => {
      const input = inspBody.querySelector(id); if (!input) return;
      input.addEventListener('change', () => {
        if (isSel) n.props[prop] = input.value; else n.props[prop] = input.checked;
        renderNodes();     // badges on the node reflect the toggle instantly
        emitChange();
      });
    };
    bind('#p-egress', 'egress', true);
    bind('#p-seg', 'segmentation');
    bind('#p-edr', 'edr');
    bind('#p-sysmon', 'sysmon');
    bind('#p-mfa', 'mfa');
    bind('#p-bp', 'block_public');
    inspBody.querySelectorAll('.lnk .mini').forEach((btn) =>
      btn.onclick = () => removeEdge(btn.dataset.edge));
    inspBody.querySelector('#insp-del').onclick = () => removeNode(n.id);
  }

  function select(s) {
    sel = s; renderNodes(); renderEdges(); renderInspector();
    if (!running) {
      if (sel || selection.size) inspPinned = true;
      syncInsp();                              // phones: bottom sheet follows selection
    } else inspSheet(false);                   // never during playback
  }

  // ---------------------------- run-mode FX ------------------------------
  function setRunning(v) {
    running = v;
    document.body.classList.toggle('running', v);
    if (v) { prevZoom = zoom; armed = null; ghost.classList.add('hidden');
             if (selection.size) { selection.clear(); renderNodes(); }   // no edit chrome in playback
             select(null); syncPalette(); closePaletteDrawer(); inspSheet(false); }
    else { zoom = prevZoom || 1; }          // leave the run's auto-fit
    fitView();
  }

  function clearFx() {
    layer.querySelectorAll('.on-path,.pulse,.flash-block,.link-from').forEach((d) =>
      d.classList.remove('on-path', 'pulse', 'flash-block', 'link-from'));
    svg.querySelectorAll('.edge.on-path').forEach((l) => l.classList.remove('on-path'));
    linkFrom = null;
  }

  function showPath(ids) {
    if (!ids || ids.length < 2) return;
    for (const id of ids) {
      const d = el(id); if (d) d.classList.add('on-path');
    }
    for (let i = 0; i + 1 < ids.length; i++) {
      const a = ids[i], b = ids[i + 1];
      svg.querySelectorAll('.edge').forEach((l) => {
        const e = G.edges.find((x) => x.id === l.dataset.id);
        if (e && ((e.src === a && e.dst === b) || (e.src === b && e.dst === a))) l.classList.add('on-path');
      });
    }
  }

  function pulse(id) { const d = el(id); if (!d) return; d.classList.add('pulse'); setTimeout(() => d.classList.remove('pulse'), 2400); }
  function flashBlock(id) { const d = el(id); if (!d) return; d.classList.add('flash-block'); setTimeout(() => d.classList.remove('flash-block'), 2000); }

  // ---------------------------- persistence ------------------------------
  function toJSON() {
    return { nodes: G.nodes, edges: G.edges, seq: G.seq,
             view: { hidden: [...hiddenNodes] } };
  }

  function load(json) {
    G = { nodes: (json.nodes || []).map((n) => ({ props: {}, ...n })),
          edges: (json.edges || []).map((e) => ({ ...e })),
          seq: json.seq || (json.nodes || []).length + 1 };
    sel = null; linkFrom = null;
    hiddenNodes.clear();
    for (const id of (json.view && json.view.hidden) || []) hiddenNodes.add(id);
    renderAll();
    // narrow viewports start with the whole design in view (the example and
    // most saved designs are drawn wider than a phone); desktop keeps 100%
    if (G.nodes.length && (isNarrow() || wrap.clientWidth < 760)) fitContent();
  }

  function clear() { load({ nodes: [], edges: [] }); emitChange(); }

  buildPalette();
  buildToolbar();
  syncToolbar();
  applyView();               // size the zoom stage at startup (otherwise the
                             // canvas has no scrollable area until first zoom)
  window.addEventListener('resize', () => { renderEdges(); fitView(); });

  window.Canvas = {
    load, toJSON, clear, addNode,
    onChange(cb) { changeCb = cb; },
    setRunning, clearFx, showPath, pulse, flashBlock,
    selectNode(id) { select({ kind: 'node', id }); },
  };
})();
