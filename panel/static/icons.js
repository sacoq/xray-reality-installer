/* =========================================================================
 * Lucide icon mounting.
 *
 * Replace every <i data-lucide="name"> in the DOM with a Lucide SVG. Runs
 * once on DOMContentLoaded and again after any subtree change (Alpine.js
 * toggles `x-show`/`x-if` sections and inserts new nodes — those new nodes
 * won't have their SVGs rendered unless we re-mount icons).
 *
 * Debounced so rapid-fire Alpine reactivity doesn't thrash the DOM.
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

  function schedule() {
    if (scheduled) return;
    scheduled = true;
    // Next animation frame is sufficient for Alpine's render cycle and
    // avoids the 16ms jank of setTimeout.
    requestAnimationFrame(refresh);
  }

  function attachObserver() {
    const obs = new MutationObserver((mutations) => {
      for (const m of mutations) {
        if (m.addedNodes.length > 0) {
          schedule();
          return;
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
