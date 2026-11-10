/* edr.js — the EDR telemetry profile overlay.
 *
 * A second "page" (full-screen overlay, same pattern as the scenario
 * editor) where you control which EDR capabilities are active: what the
 * agent reports (process / file / injection / network attribution /
 * logon sessions) and whether its behavioral prevention fires.
 *
 * The profile is GLOBAL — one EDR product, one policy — applied to every
 * host whose per-host EDR toggle is on. Changes persist in localStorage
 * and take effect on the NEXT simulation run (they are sent with every
 * /api/simulate request).
 *
 * window.EdrPage = { open(), close(), get() }
 *
 * API:
 *   GET /api/edr/caps   capability catalog + defaults
 */
(function () {
  'use strict';

  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => [...(root || document).querySelectorAll(sel)];
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

  const APIQ = window.XTPQ && window.XTPQ !== '__XTPQ__' ? window.XTPQ : '';
  const api = (p) => p + APIQ;

  const LS_KEY = 'secarch.edr_caps';
  let META = null;         // {capabilities:[{key,label,desc,ds,protect,default}], defaults:{}}

  function loadState() {
    // stored toggles merged over the defaults, so new capabilities added
    // later start in their documented default state
    const base = META ? META.defaults : {};
    let saved = {};
    try { saved = JSON.parse(localStorage.getItem(LS_KEY) || '{}'); } catch { /* ignore */ }
    const out = {};
    const caps = META ? META.capabilities : [];
    (caps.length ? caps.map((c) => c.key) : Object.keys({ ...base, ...saved }))
      .forEach((k) => {
        out[k] = typeof saved[k] === 'boolean' ? saved[k]
          : (typeof base[k] === 'boolean' ? base[k] : true);
      });
    return out;
  }

  function saveState(state) {
    localStorage.setItem(LS_KEY, JSON.stringify(state));
  }

  // ------------------------------------------------------------------
  // overlay shell
  // ------------------------------------------------------------------
  function ensureShell() {
    if ($('#edr-overlay')) return;
    const ov = document.createElement('div');
    ov.id = 'edr-overlay';
    ov.className = 'hidden';
    ov.innerHTML = `
      <header>
        <h2>EDR telemetry profile</h2>
        <span class="edr-note">one product, one policy — applied to every host with the EDR toggle on ·
          changes apply to the <b>next run</b></span>
        <button class="btn" id="edr-restore">Restore defaults</button>
        <button class="btn" id="edr-close">Close</button>
      </header>
      <div class="edr-body">
        <div class="edr-lead">An EDR is not one sensor. Each capability below is a telemetry
          stream (or a prevention) you can license, configure — or accidentally leave off.
          Switch them off and re-run a scenario to watch your coverage collapse in the
          consoles and the matrix.</div>
        <div id="edr-cards"></div>
        <div class="edr-hint" id="edr-hint"></div>
      </div>`;
    document.body.appendChild(ov);

    $('#edr-close').onclick = close;
    $('#edr-restore').onclick = () => {
      saveState({ ...META.defaults });
      render();
      flashHint('Profile reset to the product defaults.');
    };
    // one delegated listener handles every toggle
    $('#edr-cards').addEventListener('change', (ev) => {
      const box = ev.target.closest('input[data-cap]');
      if (!box) return;
      const state = loadState();
      state[box.dataset.cap] = box.checked;
      saveState(state);
      render();
      flashHint(box.checked ? 'Capability enabled — applies on the next run.'
                            : 'Capability disabled — applies on the next run.');
    });
  }

  function flashHint(msg) {
    const el = $('#edr-hint');
    el.textContent = msg;
    clearTimeout(flashHint._t);
    flashHint._t = setTimeout(() => { el.textContent = ''; }, 2500);
  }

  // ------------------------------------------------------------------
  // render
  // ------------------------------------------------------------------
  function render() {
    const state = loadState();
    $('#edr-cards').innerHTML = META.capabilities.map((c) => {
      const on = !!state[c.key];
      const feeds = c.protect
        ? `<span class="pf">prevention</span>`
        : (c.ds || []).map((d) => `<span>${esc(d)}</span>`).join('');
      return `
        <div class="edr-card ${on ? 'on' : 'off'}">
          <div class="edr-head">
            <input type="checkbox" data-cap="${esc(c.key)}" id="cap-${esc(c.key)}" ${on ? 'checked' : ''}>
            <b><label for="cap-${esc(c.key)}" style="cursor:pointer">${esc(c.label)}</label></b>
            <span class="edr-state">${on ? 'ACTIVE' : 'OFF'}</span>
          </div>
          <div class="edr-desc">${esc(c.desc)}</div>
          <div class="edr-feeds">${feeds}</div>
        </div>`;
    }).join('');
  }

  // ------------------------------------------------------------------
  // lifecycle
  // ------------------------------------------------------------------
  async function open() {
    ensureShell();
    $('#edr-overlay').classList.remove('hidden');
    if (!META) {
      META = await fetch(api('/api/edr/caps')).then((r) => r.json());
    }
    render();
  }

  function close() { $('#edr-overlay').classList.add('hidden'); }

  window.EdrPage = {
    open, close,
    get: loadState,          // app.js attaches this to /api/simulate
  };
})();
