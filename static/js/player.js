/* player.js — plays back a simulation "recording".
 *
 * The backend runs the whole kill chain in one shot and returns:
 *   rec.defender — rows the design's sensors actually produced (+ benign noise)
 *   rec.events   — full ground truth (rows marked covered / uncovered)
 *   rec.steps    — per-step verdicts with timing
 *
 * The player maps simulated seconds to wall-clock time, flushes rows into
 * the console, reveals adversary cards as each step starts and reports
 * progress. Seeking re-renders state without firing canvas FX.
 */
class Player {
  constructor(rec, hooks) {
    this.rec = rec;
    this.hooks = hooks;
    this.T = rec.duration || 300;
    this.SIM_RATE = 18;        // simulated seconds per real second at 1x
    this.speed = 1;
    this.t = 0;
    this.playing = false;
    this.done = false;
    this.showGT = false;       // include rows NO sensor saw (ground-truth check)
    this._timer = null;
    this._last = 0;
    this._prepare();
  }

  /* Merge defender rows with unseen attacker activity (dim red when shown). */
  _prepare() {
    const unseen = this.rec.events
      .filter((e) => e.malicious && !e.covered)
      .map((e) => ({
        ts: e.ts, host: e.host, ds: e.ds, process: e.process, cmd: e.cmd,
        details: e.details, sensor: '(no sensor saw this)', kind: 'unseen',
        alert: false, alert_reason: null, malicious: true, step: e.step,
        unseen: true,
      }));
    this.rows = [...this.rec.defender, ...unseen].sort((a, b) => a.ts - b.ts);
    this.ptr = 0;        // next row to flush
    this.stepIdx = 0;    // next step to reveal
  }

  /* ---- lifecycle ------------------------------------------------------ */
  start() {
    this.t = 0; this.ptr = 0; this.stepIdx = 0;
    this.done = false; this.playing = true;
    this._last = performance.now();
    clearInterval(this._timer);
    this._timer = setInterval(() => this._tick(), 120);
  }

  replay() { this.hooks.onReset(); this.start(); }

  pause() { this.playing = false; }

  resume() {
    if (this.done) { this.replay(); return; }
    this.playing = true; this._last = performance.now();
  }

  destroy() { clearInterval(this._timer); this.playing = false; }

  setSpeed(m) { this.speed = m; }

  setShowGT(v) {
    this.showGT = v;
    this.seekTime(this.t);   // rebuild the console at the current time
  }

  /* ---- main loop ------------------------------------------------------ */
  _tick() {
    if (!this.playing) return;
    const now = performance.now();
    const dt = Math.min(0.5, (now - this._last) / 1000);
    this._last = now;
    this.t = Math.min(this.T, this.t + dt * this.SIM_RATE * this.speed);
    this._flush();
    this._revealSteps(false);
    this.hooks.onProgress(this.t / this.T);
    if (this.t >= this.T) {
      this.pause(); this.done = true;
      this.hooks.onDone();
    }
  }

  _flush() {
    while (this.ptr < this.rows.length && this.rows[this.ptr].ts <= this.t) {
      this.hooks.onRow(this.rows[this.ptr]);
      this.ptr++;
    }
  }

  _revealSteps(seek) {
    while (this.stepIdx < this.rec.steps.length &&
           this.rec.steps[this.stepIdx].t_start <= this.t) {
      this.hooks.onStep(this.rec.steps[this.stepIdx], seek);
      this.stepIdx++;
    }
  }

  /* ---- seeking -------------------------------------------------------- */
  seekFrac(f) { this.seekTime(f * this.T); }

  nextStep() {
    const s = this.rec.steps.find((st) => st.t_start > this.t + 0.01);
    this.seekTime(s ? s.t_start + 0.1 : this.T);
  }

  seekTime(t) {
    this.t = Math.max(0, Math.min(this.T, t));
    // first row with ts > t
    let lo = 0, hi = this.rows.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (this.rows[mid].ts <= this.t) lo = mid + 1; else hi = mid;
    }
    this.ptr = lo;
    this.hooks.onSeek();                       // app clears console + cards
    this.stepIdx = 0;
    this._revealSteps(true);                   // re-render card states, no FX
    for (let i = 0; i < lo; i++) this.hooks.onRow(this.rows[i]);
    this.hooks.onProgress(this.t / this.T);
  }
}

window.Player = Player;
