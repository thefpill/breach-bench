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
  const svg = document.getElementById('edge-svg');
  const layer = document.getElementById('node-layer');
  const ghost = document.getElementById('place-ghost');
  const paletteEl = document.getElementById('palette');
  const inspector = document.getElementById('inspector');

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
    netflow:      { tag: 'NF',    name: 'NetFlow collector',   cls: 'sensor',    desc: 'Raw 5-tuples. Link to a segment or to the backbone firewall (then it sees everything transiting).' },
    siem:         { tag: 'SIEM',  name: 'SIEM',                cls: 'sensor',    desc: 'Only shows what other sensors ship to it. Wire hosts, network sensors or cloud services to it. Cloud audit rows reach your console ONLY through a SIEM link.' },
    idp:          { tag: 'IdP',   name: 'IdP / SSO',           cls: 'cloud',     desc: 'Cloud identity. With MFA on, phished credentials alone cannot sign in. Exploiting an exposed IdP appliance is nearly invisible (appliance = black box).' },
    iam:          { tag: 'IAM',   name: 'IAM / control plane', cls: 'cloud',     desc: 'Cloud API activity lives in its own audit log — invisible until shipped to a SIEM.' },
    s3:           { tag: 'S3',    name: 'S3 bucket',           cls: 'cloud',     desc: 'Cloud storage. "Block public / least-privilege" denies bulk reads; access rows are only visible via a SIEM.' },
  };

  const PALETTE_GROUPS = [
    { group: 'Network', items: ['internet', 'subnet', 'firewall', 'waf', 'mail_gateway'] },
    { group: 'Compute', items: ['workstation', 'server_win', 'server_linux', 'web_server'] },
    { group: 'Detection', items: ['zeek', 'netflow', 'siem'] },   // EDR/Sysmon moved onto hosts
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
        const rect = wrap.getBoundingClientRect();
        place(armed, ev.clientX - rect.left, ev.clientY - rect.top);
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
    toolbar.style.cssText = 'position:absolute;top:8px;right:10px;z-index:40;display:flex;gap:6px;';
    toolbar.innerHTML = `
      <button class="btn" data-t="select">Select</button>
      <button class="btn" data-t="link" title="Click node A then node B — toggles the connection">Link / unlink</button>
      <button class="btn" data-t="delete">Delete</button>`;
    toolbar.querySelectorAll('button').forEach((b) =>
      b.addEventListener('click', () => { if (!running) setTool(b.dataset.t); }));
    wrap.appendChild(toolbar);
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
    // smaller (split-screen) canvas area. Design mode resets to 1:1.
    const view = document.getElementById('view');
    if (!running || !G.nodes.length) { view.style.transform = ''; return; }
    const xs = G.nodes.map((n) => n.x), ys = G.nodes.map((n) => n.y);
    const minX = Math.min(...xs) - 90, maxX = Math.max(...xs) + 90;
    const minY = Math.min(...ys) - 70, maxY = Math.max(...ys) + 70;
    const s = Math.min(1, wrap.clientWidth / (maxX - minX), wrap.clientHeight / (maxY - minY));
    view.style.transform = `scale(${s})`;
  }

  function renderAll() {
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
      d.innerHTML = `<div class="tag">${(TYPES[n.type] || { tag: n.type }).tag}</div>
                     <div class="lbl">${esc(n.label)}</div>` +
        (badges.length ? `<div class="badges">${badges.map((b) => `<i>${b}</i>`).join('')}</div>` : '');
      if (sel && sel.kind === 'node' && sel.id === n.id) d.classList.add('sel');
      if (linkFrom === n.id) d.classList.add('link-from');
      attachNodeEvents(d, n);
      layer.appendChild(d);
    }
  }

  function renderEdges() {
    const W = wrap.clientWidth || 1200, H = wrap.clientHeight || 700;
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    let out = `<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5"
      markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="#2b3b4d"/></marker></defs>`;
    for (const e of G.edges) {
      const a = node(e.src), b = node(e.dst);
      if (!a || !b) continue;
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
  function attachNodeEvents(d, n) {
    d.addEventListener('pointerdown', (ev) => {
      if (running) { select({ kind: 'node', id: n.id }); return; }
      if (armed) return;                       // placing a new component wins
      if (tool === 'delete') { removeNode(n.id); return; }
      if (tool === 'link') {
        if (!linkFrom) { linkFrom = n.id; renderNodes(); }
        else if (linkFrom !== n.id) { toggleEdge(linkFrom, n.id); linkFrom = null; renderAll(); emitChange(); }
        return;
      }
      // select + drag: record anchor points, move deltas relative to the start
      ev.preventDefault();
      const rect = wrap.getBoundingClientRect();
      drag = { id: n.id, px: ev.clientX - rect.left, py: ev.clientY - rect.top,
               x0: n.x, y0: n.y, moved: false };
      try { d.setPointerCapture(ev.pointerId); } catch { /* ok */ }
    });
    d.addEventListener('pointermove', (ev) => {
      if (!drag || drag.id !== n.id) return;
      const rect = wrap.getBoundingClientRect();
      const dx = (ev.clientX - rect.left) - drag.px;
      const dy = (ev.clientY - rect.top) - drag.py;
      if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
      n.x = Math.max(24, Math.min(wrap.clientWidth - 24, drag.x0 + dx));
      n.y = Math.max(24, Math.min(wrap.clientHeight - 24, drag.y0 + dy));
      const eln = el(n.id); eln.style.left = n.x + 'px'; eln.style.top = n.y + 'px';
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

  wrap.addEventListener('click', (ev) => {
    if (running || ev.target.closest('.node') || ev.target.closest('.edge-hit') || ev.target.closest('button')) return;
    if (armed) {
      const rect = wrap.getBoundingClientRect();
      place(armed, ev.clientX - rect.left, ev.clientY - rect.top);
      if (!ev.shiftKey) arm(null);
    } else { select(null); }
  });

  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Escape') { setTool('select'); select(null); }
    const tag = (document.activeElement || {}).tagName;
    if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA') return;
    if ((ev.key === 'Delete' || ev.key === 'Backspace') && sel && !running) {
      if (sel.kind === 'node') removeNode(sel.id); else removeEdge(sel.id);
    }
  });

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
  }

  function removeEdge(id) {
    G.edges = G.edges.filter((e) => e.id !== id);
    if (sel && sel.id === id) sel = null;
    renderAll(); emitChange();
  }

  // ---------------------------- inspector ------------------------------
  function renderInspector() {
    if (!sel) {
      inspector.innerHTML = `<div class="insp-empty">Select a component to inspect it.<br><br>
        Drag components from the palette (or click, then click the canvas).
        Hosts carry their own <b>EDR / Sysmon</b> toggles here. The link tool
        toggles connections; select any wire to unlink it.</div>`;
      return;
    }
    if (sel.kind === 'edge') {
      const e = G.edges.find((x) => x.id === sel.id); if (!e) { sel = null; return renderInspector(); }
      const a = node(e.src), b = node(e.dst);
      inspector.innerHTML = `<div class="insp"><h3>Connection</h3>
        <div class="meta">${esc(a ? a.label : '?')} &harr; ${esc(b ? b.label : '?')}</div>
        <button class="btn danger" id="insp-del">Unlink</button></div>`;
      inspector.querySelector('#insp-del').onclick = () => removeEdge(e.id);
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

    inspector.innerHTML = `<div class="insp"><h3>${esc(t.name || n.type)}</h3>
      <div class="row"><label>Label</label>
        <input type="text" id="p-label" value="${esc(n.label)}"></div>
      ${propsHtml}
      <div class="insp-sec">Connections (${links.length})</div>
      ${linksHtml}
      <div class="meta" style="margin-top:10px">${esc(t.desc || '')}</div>
      <button class="btn danger" id="insp-del">Delete component</button></div>`;

    inspector.querySelector('#p-label').addEventListener('input', (ev) => {
      n.label = ev.target.value || n.label;
      const lbl = el(n.id) && el(n.id).querySelector('.lbl');
      if (lbl) lbl.textContent = n.label;
      emitChange();
    });
    const bind = (id, prop, isSel) => {
      const input = inspector.querySelector(id); if (!input) return;
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
    inspector.querySelectorAll('.lnk .mini').forEach((btn) =>
      btn.onclick = () => removeEdge(btn.dataset.edge));
    inspector.querySelector('#insp-del').onclick = () => removeNode(n.id);
  }

  function select(s) {
    sel = s; renderNodes(); renderEdges(); renderInspector();
  }

  // ---------------------------- run-mode FX ------------------------------
  function setRunning(v) {
    running = v;
    document.body.classList.toggle('running', v);
    if (v) { armed = null; ghost.classList.add('hidden'); select(null); syncPalette(); }
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
  function toJSON() { return { nodes: G.nodes, edges: G.edges, seq: G.seq }; }

  function load(json) {
    G = { nodes: (json.nodes || []).map((n) => ({ props: {}, ...n })),
          edges: (json.edges || []).map((e) => ({ ...e })),
          seq: json.seq || (json.nodes || []).length + 1 };
    sel = null; linkFrom = null;
    renderAll();
  }

  function clear() { load({ nodes: [], edges: [] }); emitChange(); }

  buildPalette();
  buildToolbar();
  syncToolbar();
  window.addEventListener('resize', () => { renderEdges(); fitView(); });

  window.Canvas = {
    load, toJSON, clear, addNode,
    onChange(cb) { changeCb = cb; },
    setRunning, clearFx, showPath, pulse, flashBlock,
    selectNode(id) { select({ kind: 'node', id }); },
  };
})();
