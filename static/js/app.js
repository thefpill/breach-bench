/* app.js — glue: API calls, run flow, panels (console / adversary / matrix /
 * summary) and design persistence. Canvas + Player live in their own files. */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  const APIQ = window.XTPQ && window.XTPQ !== '__XTPQ__' ? window.XTPQ : '';
  const api = (path) => path + APIQ;

  let player = null;
  let alerts = 0;
  let hiddenRows = 0;

  // ------------------------------------------------------------------
  // boot
  // ------------------------------------------------------------------
  async function boot() {
    await loadScenarios();

    // design: restore autosave, else bundled example
    const saved = localStorage.getItem('secarch.graph');
    if (saved) {
      try { Canvas.load(JSON.parse(saved)); } catch { await loadExample(); }
    } else {
      await loadExample();
    }
    Canvas.onChange((json) => localStorage.setItem('secarch.graph', JSON.stringify(json)));

    wireControls();
  }

  // (re)build the scenario picker; keeps the current selection when possible
  async function loadScenarios() {
    const scs = await fetch(api('/api/scenarios')).then((r) => r.json());
    const sel = $('scenario-select');
    const prev = sel.value;
    sel.innerHTML = '';
    for (const s of scs) {
      const o = document.createElement('option');
      o.value = s.id; o.textContent = `${s.group} — ${s.name.replace(/^[^—]+— /, '')}`;
      sel.appendChild(o);
    }
    if ([...sel.options].some((o) => o.value === prev)) sel.value = prev;
  }

  async function loadExample() {
    const g = await fetch(api('/api/example')).then((r) => r.json());
    Canvas.load(g);
    localStorage.setItem('secarch.graph', JSON.stringify(Canvas.toJSON()));
  }

  // ------------------------------------------------------------------
  // controls
  // ------------------------------------------------------------------
  function wireControls() {
    $('btn-scenarios').onclick = () => window.ScenarioEditor.open();
    if (window.ScenarioEditor) {
      window.ScenarioEditor.onSaved(() => loadScenarios());   // editor changes refresh the picker
    }
    $('btn-example').onclick = loadExample;
    $('btn-clear').onclick = () => Canvas.clear();
    $('btn-export').onclick = () => {
      const blob = new Blob([JSON.stringify(Canvas.toJSON(), null, 2)], { type: 'application/json' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'secarch-design.json';
      a.click();
      URL.revokeObjectURL(a.href);
    };
    $('file-import').onchange = (ev) => {
      const f = ev.target.files[0]; if (!f) return;
      f.text().then((txt) => {
        try { Canvas.load(JSON.parse(txt)); localStorage.setItem('secarch.graph', JSON.stringify(Canvas.toJSON())); }
        catch { alert('Not a valid design JSON.'); }
      });
      ev.target.value = '';
    };
    $('noise-rate').oninput = (ev) => { $('noise-val').textContent = ev.target.value; };
    $('btn-run').onclick = runSimulation;
    $('btn-back').onclick = backToDesign;
    $('btn-play').onclick = () => {
      if (!player) return;
      if (player.playing) { player.pause(); $('btn-play').textContent = 'Play'; }
      else { player.resume(); $('btn-play').textContent = 'Pause'; }
    };
    $('btn-next-step').onclick = () => player && player.nextStep();
    $('speed').onchange = (ev) => player && player.setSpeed(parseFloat(ev.target.value));
    $('progress').onclick = (ev) => {
      if (!player) return;
      const r = ev.currentTarget.getBoundingClientRect();
      player.seekFrac((ev.clientX - r.left) / r.width);
      $('btn-play').textContent = player.playing ? 'Pause' : 'Play';
    };
    $('show-gt').onchange = (ev) => player && player.setShowGT(ev.target.checked);

    // tabs
    document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach((x) => x.classList.toggle('active', x === t));
      document.querySelectorAll('.tab-page').forEach((p) =>
        p.classList.toggle('active', p.id === 'tab-' + t.dataset.tab));
    }));
  }

  // ------------------------------------------------------------------
  // run flow
  // ------------------------------------------------------------------
  async function runSimulation() {
    const graph = Canvas.toJSON();
    if (!graph.nodes.length) { alert('Draw a design first — or click "Load example".'); return; }
    const btn = $('btn-run');
    btn.disabled = true; btn.textContent = 'Simulating…';
    try {
      const res = await fetch(api('/api/simulate'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ graph, scenario_id: $('scenario-select').value,
                               noise_rate: parseInt($('noise-rate').value, 10) }),
      });
      const rec = await res.json();
      if (rec.error) { alert(rec.error); return; }
      startRun(rec);
    } catch (e) {
      alert('Simulation request failed: ' + e);
    } finally {
      btn.disabled = false; btn.textContent = 'Run \u25B6';
    }
  }

  function startRun(rec) {
    Canvas.setRunning(true);
    $('run-config').classList.add('hidden');
    $('playback-controls').classList.remove('hidden');
    $('run-panel').classList.remove('hidden');
    $('mode-hint').textContent = 'run mode — the adversary acts on YOUR design; watch the canvas, then read the consoles';

    alerts = 0; hiddenRows = 0;
    $('alert-tally').textContent = '';
    $('console').innerHTML = '';
    renderAdversary(rec);
    renderMatrix(rec);
    renderSummary(rec);
    switchTab('console');

    player = new Player(rec, {
      onRow: appendRow,
      onStep: onStep,
      onProgress: (f) => { $('progress-fill').style.width = (f * 100).toFixed(1) + '%'; },
      onSeek: () => {
        $('console').innerHTML = '';
        alerts = 0; hiddenRows = 0;
        $('alert-tally').textContent = '';
        document.querySelectorAll('.step-card').forEach((c) => resetCard(c));
      },
      onDone: () => { $('btn-play').textContent = 'Replay'; },
      onReset: () => {
        $('console').innerHTML = '';
        alerts = 0; hiddenRows = 0;
        $('alert-tally').textContent = '';
        document.querySelectorAll('.step-card').forEach((c) => resetCard(c));
      },
    });
    player.setShowGT($('show-gt').checked);
    player.start();
    $('btn-play').textContent = 'Pause';
  }

  function backToDesign() {
    if (player) { player.destroy(); player = null; }
    Canvas.setRunning(false);
    Canvas.clearFx();
    $('run-panel').classList.add('hidden');
    $('playback-controls').classList.add('hidden');
    $('run-config').classList.remove('hidden');
    $('mode-hint').textContent = 'drag from the palette \u00B7 link tool toggles a connection \u00B7 hosts carry EDR / Sysmon toggles in the inspector';
  }

  function switchTab(name) {
    document.querySelectorAll('.tab').forEach((x) =>
      x.classList.toggle('active', x.dataset.tab === name));
    document.querySelectorAll('.tab-page').forEach((p) =>
      p.classList.toggle('active', p.id === 'tab-' + name));
  }

  // ------------------------------------------------------------------
  // defender console
  // ------------------------------------------------------------------
  const fmtT = (ts) => {
    const m = Math.floor(ts / 60), s = Math.floor(ts % 60);
    return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  };

  const DET_KEYS = ['event', 'logon_type', 'user', 'result', 'src', 'dst', 'sni',
    'bytes_out', 'proto', 'method', 'path', 'status', 'payload', 'api', 'bucket',
    'key', 'principal', 'src_ip', 'geo', 'device', 'mfa', 'count', 'action',
    'rule', 'subject', 'attachment', 'from', 'verdict', 'duration', 'interval',
    'granted', 'auth', 'src_ws', 'note', 'host_role'];

  function rowMsg(r) {
    const bits = [];
    if (r.process) bits.push(r.process);
    if (r.cmd) bits.push(r.cmd);
    const d = r.details || {};
    const kv = DET_KEYS.filter((k) => d[k] !== undefined && d[k] !== '')
      .map((k) => `${k}=${d[k]}`);
    if (kv.length) bits.push(kv.join(' '));
    return bits.join('  \u00B7  ');
  }

  function rowTitle(r) {
    const d = r.details ? JSON.stringify(r.details) : '';
    return `${r.sensor} \u00B7 ${r.ds}${d ? '\n' + d : ''}` +
           (r.alert_reason ? `\nALERT: ${r.alert_reason}` : '');
  }

  function appendRow(r) {
    const c = $('console');
    const div = document.createElement('div');
    div.className = 'crow' + (r.alert ? ' alert' : '') +
      (r.unseen ? ' unseen' : '') + (!r.malicious && !r.alert ? ' noise' : '');
    const chipKind = r.unseen ? 'unseen' : r.kind;
    div.innerHTML =
      `<span class="t">${fmtT(r.ts)}</span>` +
      `<span class="chip k-${esc(chipKind)}">${r.unseen ? 'GHOST' : esc((r.kind || '').toUpperCase())}</span>` +
      `<span class="sensor">${esc(r.sensor)}</span>` +
      `<span class="host">${esc(r.host)}</span>` +
      `<span class="ds">${esc(r.ds)}</span>` +
      `<span class="msg" title="${esc(rowTitle(r))}">${esc(rowMsg(r))}</span>` +
      (r.alert ? `<span class="alert-chip">ALERT</span>` : '') +
      (r.unseen ? `<span class="unseen-chip">UNSEEN</span>` : '');
    div.title = rowTitle(r);

    // keep the console light: drop oldest rows beyond 700
    const nearBottom = c.scrollHeight - c.scrollTop - c.clientHeight < 60;
    c.appendChild(div);
    if (c.children.length > 700) { c.removeChild(c.firstChild); hiddenRows++; }
    if (r.alert) { alerts++; $('alert-tally').textContent = `ALERTS: ${alerts}`; }
    $('row-count').textContent = hiddenRows ? `(+${hiddenRows} earlier rows scrolled off)` : '';
    if (nearBottom) c.scrollTop = c.scrollHeight;
  }

  // ------------------------------------------------------------------
  // adversary view (ground truth)
  // ------------------------------------------------------------------
  function renderAdversary(rec) {
    const box = $('tab-adversary');
    box.innerHTML = `<div class="scenario-blurb"><b>${esc(rec.scenario.group)}</b> — ${esc(rec.scenario.blurb)}</div>`;
    for (const s of rec.steps) {
      const card = document.createElement('div');
      card.className = `step-card v-${s.verdict} reveal-hidden`;
      card.id = `step-${s.n}`;
      card.innerHTML =
        `<div class="step-head">
           <span class="step-n">#${s.n}</span>
           <span class="tech">${esc(s.technique)}</span>
           <span class="sname">${esc(s.name)}</span>
           <span class="tac">${esc(s.tactic)}</span>
           <span class="gbadge">${esc(s.group)}</span>
           <span class="verdict pending">pending</span>
         </div>
         <p class="proc">${esc(s.procedure)}</p>
         <pre class="cmd">${esc(s.command)}</pre>
         <div class="cmd-src">tradecraft source: ${esc(s.cmd_source)} \u00B7 target: ${esc(s.target || '\u2014')}</div>
         <div class="why">${esc(s.why)}</div>
         <div class="seen">${seenHtml(s)}</div>`;
      box.appendChild(card);
    }
  }

  function seenHtml(s) {
    if (!s.seen_by.length) return 'Seen by: nothing. This step left no row anywhere in your design.';
    return 'Seen by: ' + s.seen_by.map((x) => `${esc(x.sensor)} (${esc(x.detail)})`).join('; ');
  }

  function onStep(s, seek) {
    const card = $('step-' + s.n);
    if (card) {
      card.classList.remove('reveal-hidden');
      const v = card.querySelector('.verdict');
      v.className = 'verdict v-' + s.verdict;
      v.textContent = s.verdict.replace('_', ' ');
      card.classList.remove('v-blocked', 'v-detected', 'v-observed', 'v-blind', 'v-not_reached', 'v-unreachable');
      card.classList.add('v-' + s.verdict);
      if (!seek) card.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
    if (seek) return; // no canvas FX on seeks
    Canvas.clearFx();
    if (s.path && s.path.length) Canvas.showPath(s.path);
    if (s.target_id) Canvas.pulse(s.target_id);
    if (s.verdict === 'blocked' && s.blocked_at_id) {
      setTimeout(() => Canvas.flashBlock(s.blocked_at_id), 700);
    }
  }

  function resetCard(card) {
    card.classList.add('reveal-hidden');
    card.classList.remove('v-blocked', 'v-detected', 'v-observed', 'v-blind', 'v-not_reached', 'v-unreachable');
    card.classList.add('v-not_reached');
    const v = card.querySelector('.verdict');
    v.className = 'verdict pending';
    v.textContent = 'pending';
  }

  // ------------------------------------------------------------------
  // coverage matrix
  // ------------------------------------------------------------------
  const TAG_CLASS = { EDR: 'a', SYS: 'a', SIEM: 'v', AUD: 'v', WAF: 'r', FW: 'r', MGW: 'r' };

  function renderMatrix(rec) {
    const m = rec.matrix;
    let html = '<table class="matrix"><tr><th style="text-align:left">ATT&amp;CK data source</th>';
    for (const c of m.columns) {
      html += `<th>${esc(c.label)}${c.group ? `<span class="grp">${esc(c.group)}</span>` : ''}</th>`;
    }
    html += '</tr>';
    for (const row of m.rows) {
      html += `<tr><td class="ds">${esc(row.ds)}</td>`;
      for (const c of m.columns) {
        const tags = row.cells[c.id] || [];
        html += tags.length
          ? `<td>${tags.map((t) => `<span class="tg ${TAG_CLASS[t] || ''}">${esc(t)}</span>`).join('')}</td>`
          : `<td class="blank">\u00B7</td>`;
      }
      html += '</tr>';
    }
    html += '</table><p class="sum-list" style="margin-top:10px">Raw sensor placement per ATT&amp;CK data source. ' +
            'A dot means that data source simply does not exist there — events on it never reach any console. ' +
            'SIEM columns are not shown here: the SIEM only mirrors what is shipped to it.</p>';
    $('matrix-holder').innerHTML = html;
  }

  // ------------------------------------------------------------------
  // summary — observability, not percentages
  // ------------------------------------------------------------------
  function renderSummary(rec) {
    const s = rec.summary;
    const other = s.not_reached + s.unreachable;
    const chips = [
      ['c-blocked', s.blocked, 'blocked'],
      ['c-detected', s.detected, 'detected (alert fired)'],
      ['c-observed', s.observed, 'observed (rows, no alert)'],
      ['c-blind', s.blind, 'blind (nothing logged)'],
      ['c-other', other, 'not reached / unreachable'],
    ].map(([c, v, l]) => `<div class="schip ${c}"><b>${v}</b><span>${l}</span></div>`).join('');

    const stepLines = rec.steps.map((st) =>
      `<div><b style="color:var(--text)">#${st.n} ${esc(st.technique)} ${esc(st.name)}</b> ` +
      `&rarr; <i>${st.verdict.replace('_', ' ')}</i> (${esc(st.target || 'n/a')})</div>`).join('');

    const pct = s.attacker_events ? Math.round((s.visible_events / s.attacker_events) * 100) : 0;
    $('tab-summary').innerHTML =
      `<div class="sum-chips">${chips}</div>
       <div class="sum-note">
         The adversary executed <b>${s.attacker_events}</b> ground-truth events across the kill chain.
         Your design surfaced <b>${s.visible_events}</b> of them (${pct}%) in some console, mixed into
         <b>${s.noise_events}</b> benign rows — that ratio <i>is</i> your alert fatigue.
         Blocking is a control decision; seeing is a telemetry decision. The list below is observability accounting, not a score.
       </div>
       <div class="sum-list">${stepLines}</div>
       <div class="sum-note" style="margin-top:14px">
         <b>Things to try on this design:</b><br>
         &middot; wire a mail gateway between Internet and your workstations — step 1 stops being blind<br>
         &middot; set the firewall to <i>default-deny egress</i> and re-run — watch C2 die mid-chain<br>
         &middot; toggle <i>MFA</i> on the IdP before the cloud scenario<br>
         &middot; link the cloud services to your SIEM so cloud audit rows finally reach the SOC<br>
         &middot; add EDR to the sensor-less hosts, or a WAF in front of the app — then compare consoles
       </div>`;
  }

  boot();
})();
