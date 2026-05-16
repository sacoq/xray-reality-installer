/* =========================================================================
 * Lucide icon mounting.
 *
 * Replace every <i data-lucide="name"> in the DOM with a Lucide SVG. Runs
 * once on DOMContentLoaded and again ONLY when Alpine inserts new nodes
 * that actually contain unmounted icons — re-running on every subtree
 * mutation otherwise (Alpine fires hundreds of those on every poll cycle)
 * means a full O(N) document scan per frame, which on a heavy view (e.g.
 * a 50-row clients table) measurably drops FPS to 10–20 until the user
 * reloads.
 *
 * ``createIcons()`` itself REPLACES the <i> with an <svg> — that's a
 * childList mutation too. We must skip our own mutations or we'd loop
 * forever; the simplest filter is "only added nodes that still carry a
 * data-lucide attribute matter".
 *
 * Scheduled via ``requestIdleCallback`` (with RAF fallback) so we never
 * compete with the browser's render frame budget.
 * ======================================================================= */
(function () {
  "use strict";

  let scheduled = false;

  function refresh() {
    scheduled = false;
    if (window.lucide && typeof window.lucide.createIcons === "function") {
      try {
        window.lucide.createIcons();
      } catch (_) {
        /* swallow — icon library errors shouldn't take down the UI */
      }
    }
  }

  // Run when the browser is idle (gives priority to Alpine's render
  // cycle and the WebGL background animation). Falls back to RAF on
  // browsers without requestIdleCallback (mostly Safari).
  const queueIdle = (cb) => {
    if (typeof window.requestIdleCallback === "function") {
      window.requestIdleCallback(cb, { timeout: 200 });
    } else {
      window.requestAnimationFrame(cb);
    }
  };

  function schedule() {
    if (scheduled) return;
    scheduled = true;
    queueIdle(refresh);
  }

  // True iff ``node`` is — or contains — at least one element that
  // still needs mounting (still carries ``data-lucide``). Avoids waking
  // the observer on insertions of already-rendered SVGs (every call to
  // ``createIcons()`` swaps <i data-lucide=…> for <svg>, which is itself
  // a childList mutation we don't want to react to).
  function needsMount(node) {
    if (!node || node.nodeType !== 1) return false;
    if (node.hasAttribute && node.hasAttribute("data-lucide")) return true;
    if (node.querySelector) return node.querySelector("[data-lucide]") !== null;
    return false;
  }

  function attachObserver() {
    const obs = new MutationObserver((mutations) => {
      for (const m of mutations) {
        // Only ``childList`` is observed, but iterate ``addedNodes``
        // anyway so a mutation that only removed nodes (Alpine x-for
        // diff) is a free no-op.
        for (const n of m.addedNodes) {
          if (needsMount(n)) {
            schedule();
            return;
          }
        }
      }
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }

  function boot() {
    refresh();           // first pass on the initial DOM
    attachObserver();    // keep up with Alpine inserts/removes
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot, { once: true });
  } else {
    boot();
  }
})();
