/* editor.js — the scenario editor overlay.
 *
 * A second "page" (full-screen overlay) where the user can add, duplicate
 * and edit adversary scenarios. Built-in scenarios stay read-only: they
 * document real tradecraft, so the editor duplicates them into editable
 * copies instead of touching them.
 *
 * window.ScenarioEditor = { open(), close(), onSaved(cb) }
 *
 * Persisted through the API:
 *   GET    /api/scenarios          list (builtin + custom, flagged)
 *   GET    /api/scenarios/{id}     full detail
 *   POST   /api/scenarios          {scenario, orig_id?} upsert
 *   DELETE /api/scenarios/{id}     custom only
 *   GET    /api/meta               dropdown vocabularies
 */
(function () {
  'use strict';

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => [...(root || document).querySelectorAll(sel)];
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  const APIQ = window.XTPQ && window.XTPQ !== '__XTPQ__' ? window.XTPQ : '';
  const api = (p) => p + APIQ;

  let META = null;        // {data_sources, target_types, target_labels, tactics}
  let LIST = [];          // scenario summaries
  let current = null;     // {scenario, builtin, orig_id}

  let savedCb = null;     // app.js hook: refresh the scenario picker

  // ------------------------------------------------------------------
  // data helpers
  // ------------------------------------------------------------------
  async function fetchJSON(url, opts) {
    const r = await fetch(api(url), opts);
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || `${r.status} ${r.statusText}`);
    return body;
  }

  function blankScenario() {
    return {
      id: '', name: '', group: '', blurb: '',
      steps: [{
        tactic: 'initial-access', technique: '', name: '',
        procedure: '', command: '', cmd_source: 'custom scenario',
        target_type: 'workstation',
        emits: [{ ds: 'Process Creation', process: '', cmd: '' }],
      }],
    };
  }

  // ------------------------------------------------------------------
  // overlay shell
  // ------------------------------------------------------------------
  function ensureShell() {
    if ($('#scn-overlay')) return;
    const ov = document.createElement('div');
    ov.id = 'scn-overlay';
    ov.className = 'hidden';
    ov.innerHTML = `
      <header>
        <h2>Scenario editor</h2>
        <span class="scn-note">steps replay documented tradecraft — cite the procedure, pick real commands</span>
        <button class="btn" id="scn-close">Close</button>
      </header>
      <div class="scn-body">
        <aside class="scn-list">
          <button class="btn primary" id="scn-new">+ New scenario</button>
          <div id="scn-items"></div>
        </aside>
        <section class="scn-form" id="scn-form"></section>
      </div>`;
    document.body.appendChild(ov);

    $('#scn-close').onclick = close;
    $('#scn-new').onclick = () => openScenario(blankScenario(), false, null);
    // one delegated listener handles every button inside the step list
    $('#scn-form').addEventListener('click', onFormClick);
    $('#scn-form').addEventListener('input', onFormInput);
  }

  // ------------------------------------------------------------------
  // list pane
  // ------------------------------------------------------------------
  function renderList() {
    const box = $('#scn-items');
    box.innerHTML = LIST.map((s) => `
      <div class="scn-item${current && current.scenario.id === s.id ? ' sel' : ''}" data-id="${esc(s.id)}">
        <div class="si-head"><b>${esc(s.name)}</b>
          <span class="si-chip ${s.builtin ? 'bi' : 'cu'}">${s.builtin ? 'built-in' : 'custom'}</span></div>
        <div class="si-sub">${esc(s.group)} · ${s.steps.length} steps</div>
      </div>`).join('');
    $$('.scn-item', box).forEach((it) =>
      it.onclick = () => openById(it.dataset.id));
  }

  async function openById(id) {
    try {
      const full = await fetchJSON(`/api/scenarios/${encodeURIComponent(id)}`);
      openScenario(full, !!full.builtin, full.builtin ? null : id);
    } catch (e) { showFormError(String(e.message || e)); }
  }

  // ------------------------------------------------------------------
  // form pane
  // ------------------------------------------------------------------
  function openScenario(sc, builtin, origId) {
    current = { scenario: sc, builtin, orig_id: origId };
    renderList();
    renderForm();
  }

  function renderForm() {
    const f = $('#scn-form');
    if (!current) { f.innerHTML = '<div class="scn-empty">Pick a scenario or create a new one.</div>'; return; }
    const s = current.scenario;
    const ro = current.builtin;                       // built-ins are read-only

    f.innerHTML = `
      ${ro ? `<div class="scn-banner">Built-in scenario — documented tradecraft, read-only.
        <button class="btn" id="scn-dup" style="margin-left:10px">Duplicate to edit</button></div>` : ''}
      <div class="scn-grid">
        <label>Name <input id="scn-name" value="${esc(s.name)}" ${ro ? 'disabled' : ''}></label>
        <label>Adversary / group <input id="scn-group" value="${esc(s.group)}" placeholder="e.g. APT29" ${ro ? 'disabled' : ''}></label>
      </div>
      <label class="scn-blurb">Blurb (what the scenario demonstrates)
        <textarea id="scn-blurb" rows="2" ${ro ? 'disabled' : ''}>${esc(s.blurb)}</textarea></label>

      <div class="scn-sec">Kill chain steps</div>
      <div id="scn-steps">${s.steps.map((st, i) => stepFormHtml(st, i, ro)).join('')}</div>
      ${ro ? '' : `<button class="btn" data-act="add-step">+ Add step</button>`}

      <div class="scn-actions">
        <span id="scn-err" class="scn-err"></span>
        ${ro ? '' : `<button class="btn primary" id="scn-save">Save scenario</button>
                      <button class="btn danger" id="scn-del">Delete</button>`}
      </div>`;

    if (ro) $('#scn-dup').onclick = duplicateCurrent;
    else {
      $('#scn-save').onclick = saveCurrent;
      $('#scn-del').onclick = deleteCurrent;
    }
  }

  function stepFormHtml(st, i, ro) {
    const tactics = (META.tactics || []);
    const dlist = `scn-tactics`;
    const emits = (st.emits || []).map((ev, j) => emitFormHtml(ev, j, ro)).join('');
    const dis = ro ? 'disabled' : '';
    return `
      <div class="step-form" data-idx="${i}">
        <div class="sf-head">
          <span class="sf-n">#${i + 1}</span>
          <span class="sf-title">${esc(st.name || 'unnamed step')}</span>
          <span class="sf-btns">
            <button class="mini" data-act="up" title="Move up" ${ro ? 'disabled' : ''}>&uarr;</button>
            <button class="mini" data-act="down" title="Move down" ${ro ? 'disabled' : ''}>&darr;</button>
            <button class="mini danger" data-act="del-step" title="Remove step" ${ro ? 'disabled' : ''}>&times;</button>
          </span>
        </div>
        <div class="sf-grid">
          <label>Technique <input class="f-tech" value="${esc(st.technique)}" placeholder="T1566.001" ${dis}></label>
          <label>Step name <input class="f-name" value="${esc(st.name)}" ${dis}></label>
          <label>Tactic <input class="f-tactic" list="${dlist}" value="${esc(st.tactic)}" ${dis}></label>
          <label>Lands on
            <select class="f-target" ${dis}>
              ${META.target_types.map((t) =>
                `<option value="${t}"${st.target_type === t ? ' selected' : ''}>${esc(META.target_labels[t] || t)}</option>`).join('')}
            </select></label>
        </div>
        <datalist id="${dlist}">${tactics.map((t) => `<option value="${esc(t)}">`).join('')}</datalist>
        <label>Procedure (what the adversary actually did)
          <textarea class="f-proc" rows="2" ${dis}>${esc(st.procedure)}</textarea></label>
        <label>Command / evidence snippet
          <textarea class="f-cmd" rows="2" ${dis}>${esc(st.command)}</textarea></label>
        <div class="sf-grid">
          <label>Tradecraft source <input class="f-src" value="${esc(st.cmd_source || '')}" ${dis}></label>
          <label>Window (seconds, optional) <input class="f-win" type="number" min="10" max="3600" value="${st.window != null ? esc(st.window) : ''}" ${dis}></label>
        </div>
        <div class="sf-sec">Ground-truth events (tagged with ATT&amp;CK data sources)</div>
        <div class="emits">${emits}</div>
        ${ro ? '' : `<button class="btn" data-act="add-emit">+ Add event</button>`}
      </div>`;
  }

  function emitFormHtml(ev, j, ro) {
    const dis = ro ? 'disabled' : '';
    const det = ev.details ? JSON.stringify(ev.details) : '';
    return `
      <div class="emit" data-idx="${j}">
        <div class="em-grid">
          <label>Data source
            <select class="e-ds" ${dis}>
              ${META.data_sources.map((d) =>
                `<option value="${esc(d)}"${ev.ds === d ? ' selected' : ''}>${esc(d)}</option>`).join('')}
            </select></label>
          <label>at (0–1 of the window)
            <input class="e-at" type="number" min="0" max="1" step="0.05"
                   value="${ev.at != null ? esc(ev.at) : ''}" ${dis}></label>
          <label>Process <input class="e-proc" value="${esc(ev.process || '')}" ${dis}></label>
          <label>Command line <input class="e-cmd" value="${esc(ev.cmd || '')}" ${dis}></label>
        </div>
        <label>Details (JSON object, optional) <textarea class="e-det" rows="2" placeholder='{"dst": "203.0.113.66:443", "sni": "c2[.]net"}' ${dis}>${esc(det)}</textarea></label>
        <button class="mini danger" data-act="del-emit" title="Remove event" ${ro ? 'disabled' : ''}>&times; remove event</button>
      </div>`;
  }

  // ------------------------------------------------------------------
  // delegated form interactions
  // ------------------------------------------------------------------
  function onFormClick(ev) {
    const btn = ev.target.closest('[data-act]');
    if (!btn || current.builtin) return;
    const stepsBox = $('#scn-steps');
    const stepCard = btn.closest('.step-form');
    const emitCard = btn.closest('.emit');

    if (btn.dataset.act === 'add-step') {
      const div = document.createElement('div');
      div.innerHTML = stepFormHtml(blankScenario().steps[0],
                                   $$('.step-form', stepsBox).length, false);
      stepsBox.appendChild(div.firstElementChild);
      stepsBox.lastElementChild.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    } else if (btn.dataset.act === 'del-step' && stepCard) {
      stepCard.remove(); renumberSteps();
    } else if (btn.dataset.act === 'up' && stepCard) {
      const prev = stepCard.previousElementSibling;
      if (prev) { stepsBox.insertBefore(stepCard, prev); renumberSteps(); }
    } else if (btn.dataset.act === 'down' && stepCard) {
      const next = stepCard.nextElementSibling;
      if (next) { stepsBox.insertBefore(next, stepCard); renumberSteps(); }
    } else if (btn.dataset.act === 'add-emit' && stepCard) {
      const box = $('.emits', stepCard);
      const div = document.createElement('div');
      div.innerHTML = emitFormHtml({ ds: META.data_sources[0] }, box.children.length, false);
      box.appendChild(div.firstElementChild);
    } else if (btn.dataset.act === 'del-emit' && emitCard) {
      emitCard.remove();
    }
    // keep the visible step titles in sync while typing names
  }

  function onFormInput(ev) {
    const card = ev.target.closest('.step-form');
    if (!card) return;
    if (ev.target.classList.contains('f-name')) {
      $('.sf-title', card).textContent = ev.target.value || 'unnamed step';
    }
  }

  function renumberSteps() {
    $$('#scn-steps .step-form').forEach((c, i) => {
      c.dataset.idx = i;
      $('.sf-n', c).textContent = '#' + (i + 1);
    });
  }

  // ------------------------------------------------------------------
  // collect + save
  // ------------------------------------------------------------------
  function collect() {
    if (!current) return null;
    return {
      id: current.scenario.id,          // empty for new drafts -> server slugifies
      name: $('#scn-name').value.trim(),
      group: $('#scn-group').value.trim(),
      blurb: $('#scn-blurb').value.trim(),
      steps: $$('#scn-steps .step-form').map((card) => {
        const st = {
          tactic: $('.f-tactic', card).value.trim(),
          technique: $('.f-tech', card).value.trim(),
          name: $('.f-name', card).value.trim(),
          procedure: $('.f-proc', card).value.trim(),
          command: $('.f-cmd', card).value.trim(),
          cmd_source: $('.f-src', card).value.trim(),
          target_type: $('.f-target', card).value,
          emits: $$('.emit', card).map((er) => {
            const e = { ds: $('.e-ds', er).value };
            const at = $('.e-at', er).value;
            if (at !== '') e.at = parseFloat(at);
            if ($('.e-proc', er).value.trim()) e.process = $('.e-proc', er).value.trim();
            if ($('.e-cmd', er).value.trim()) e.cmd = $('.e-cmd', er).value.trim();
            const dtxt = $('.e-det', er).value.trim();
            if (dtxt) {
              try { e.details = JSON.parse(dtxt); }
              catch { e.badDetails = true; }
            }
            return e;
          }),
        };
        const win = $('.f-win', card).value;
        if (win !== '') st.window = parseFloat(win);
        return st;
      }),
    };
  }

  function showFormError(msg) {
    const el = $('#scn-err');
    if (el) el.textContent = msg;
  }

  async function saveCurrent() {
    showFormError('');
    const scn = collect();
    if (scn.steps.some((s) => s.emits.some((e) => e.badDetails))) {
      showFormError('Details must be a valid JSON object (e.g. {"dst": "1.2.3.4:443"}).');
      return;
    }
    try {
      const out = await fetchJSON('/api/scenarios', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: scn, orig_id: current.orig_id }),
      });
      current.orig_id = out.id;
      current.scenario.id = out.id;
      await loadList();
      renderList();
      showFormError('Saved ✔');
      if (savedCb) savedCb();
    } catch (e) {
      showFormError(String(e.message || e));
    }
  }

  async function deleteCurrent() {
    if (!current || current.builtin) return;
    if (!confirm(`Delete scenario "${current.scenario.name}"?`)) return;
    try {
      await fetchJSON(`/api/scenarios/${encodeURIComponent(current.scenario.id)}`, { method: 'DELETE' });
      current = null;
      await loadList();
      renderList(); renderForm();
      if (savedCb) savedCb();
    } catch (e) { showFormError(String(e.message || e)); }
  }

  async function duplicateCurrent() {
    if (!current) return;
    const copy = JSON.parse(JSON.stringify(current.scenario));
    delete copy.id; delete copy.builtin;
    copy.name = `${copy.name} (copy)`;
    openScenario(copy, false, null);
  }

  // ------------------------------------------------------------------
  // lifecycle
  // ------------------------------------------------------------------
  async function loadList() {
    LIST = await fetchJSON('/api/scenarios');
  }

  async function open() {
    ensureShell();
    $('#scn-overlay').classList.remove('hidden');
    if (!META) META = await fetchJSON('/api/meta');
    await loadList();
    renderList();
    if (!current && LIST.length) await openById(LIST[0].id);
    else renderForm();
  }

  function close() { $('#scn-overlay').classList.add('hidden'); }

  window.ScenarioEditor = {
    open, close,
    onSaved(cb) { savedCb = cb; },
  };
})();
