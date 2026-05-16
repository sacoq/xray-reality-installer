/* =========================================================================
 * Ambient network background — subtle global "spider web".
 *
 * Uses Vanta.NET (three.js r134 + vanta.net) from a CDN. Renders a muted
 * 3D grid of points connected by thin lines that gently ripple around the
 * cursor — exactly the "global web that moves with the mouse" feeling
 * without the loud, oversaturated look of a spinning globe.
 *
 * Skipped on small screens and for users who prefer reduced motion
 * (also handled in CSS).
 * ======================================================================= */
(function () {
  "use strict";

  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  if (window.innerWidth < 640) return;

  // three.js r134 is the last version Vanta supports. Pin precise versions so
  // a future CDN update doesn't silently break us.
  const THREE_URL = "https://cdn.jsdelivr.net/npm/three@0.134.0/build/three.min.js";
  const VANTA_URL = "https://cdn.jsdelivr.net/npm/vanta@0.5.24/dist/vanta.net.min.js";

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = src;
      s.async = false;   // preserve order: three → vanta
      s.onload = resolve;
      s.onerror = () => reject(new Error("failed to load " + src));
      document.head.appendChild(s);
    });
  }

  async function init() {
    const mount = document.getElementById("globe-bg");
    if (!mount) return;

    try {
      await loadScript(THREE_URL);
      await loadScript(VANTA_URL);
    } catch (e) {
      // If the CDN is unreachable — leave the gradient background, no UI
      // degradation.
      console.warn("[net-bg] vanta failed to load", e);
      return;
    }

    const VANTA = window.VANTA;
    if (!VANTA || !VANTA.NET) return;

    // Tuned for a premium, muted look: low point count, wide spacing, faint
    // lines, small nodes. On the default config, vanta.net is quite loud —
    // these values dial it right down.
    // ``mouseControls`` / ``touchControls`` make Vanta listen on every
    // mousemove / touchmove and re-tilt the whole point cloud per
    // event. With many ``backdrop-filter: blur`` glass panels above the
    // WebGL canvas, every cursor twitch forces the GPU to recomposite
    // those layers — a noticeable FPS hit on integrated GPUs / high-DPI
    // displays. The cursor-following effect is a "nice to have" that
    // costs more than it adds, so we keep the gentle base animation but
    // disable input-driven re-tilts.
    VANTA.NET({
      el: mount,
      mouseControls: false,
      touchControls: false,
      gyroControls: false,
      minHeight: 200.0,
      minWidth: 200.0,
      scale: 1.0,
      scaleMobile: 1.0,
      color: 0x7c7fff,              // soft indigo line colour
      backgroundColor: 0x06070c,    // almost-black, matches our body bg
      backgroundAlpha: 0,           // transparent — body gradient shows through
      points: 9.0,
      maxDistance: 22.0,            // how far a line can stretch between nodes
      spacing: 18.0,
      showDots: true,
    });

    // Fade in once WebGL has composed its first frame.
    requestAnimationFrame(() => mount.classList.add("is-ready"));
  }

  if (document.readyState === "complete") {
    init();
  } else {
    window.addEventListener("load", init, { once: true });
  }
})();
