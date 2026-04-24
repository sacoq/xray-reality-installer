/* =========================================================================
 * Interactive globe background.
 *
 * Uses globe.gl (which bundles three.js + three-globe) from a CDN. We:
 *   - render a "hollow" globe (no texture) with dotted hex-polygon countries
 *     — gives a premium, wireframe feel without loading heavy textures
 *   - draw 18 animated arcs between random world coords — the "паутина"
 *   - slowly auto-rotate; subtly tilt the whole canvas based on mouse
 *
 * Skipped entirely on small screens and for users who prefer reduced motion
 * (handled in CSS). Runs after window `load` so it never blocks LCP.
 * ======================================================================= */
(function () {
  "use strict";

  // Respect user preferences and device limits early — this matches the CSS
  // `display: none` branch, so we don't even fetch dependencies there.
  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  if (window.innerWidth < 640) return;

  const GEOJSON_URL =
    "https://cdn.jsdelivr.net/npm/three-globe@2.31.1/example/img/ne_110m_admin_0_countries.geojson";

  function loadScript(src) {
    return new Promise((resolve, reject) => {
      const s = document.createElement("script");
      s.src = src;
      s.async = true;
      s.onload = resolve;
      s.onerror = () => reject(new Error("failed to load " + src));
      document.head.appendChild(s);
    });
  }

  // Generate N great-circle arcs between random points on the globe.
  function randomArcs(count) {
    const arcs = [];
    for (let i = 0; i < count; i++) {
      arcs.push({
        startLat: (Math.random() - 0.5) * 140,
        startLng: (Math.random() - 0.5) * 360,
        endLat:   (Math.random() - 0.5) * 140,
        endLng:   (Math.random() - 0.5) * 360,
        color:    Math.random() > 0.5 ? "#8b8dff" : "#5ee3d2",
      });
    }
    return arcs;
  }

  // A sparse ring of pulsing points near known PoPs, so the web has anchors.
  const ANCHORS = [
    { lat: 40.71, lng: -74.01 },   // New York
    { lat: 51.51, lng:  -0.13 },   // London
    { lat: 52.52, lng:  13.41 },   // Berlin
    { lat: 55.75, lng:  37.62 },   // Moscow
    { lat: 56.95, lng:  24.11 },   // Riga
    { lat: 35.68, lng: 139.69 },   // Tokyo
    { lat:  1.35, lng: 103.82 },   // Singapore
    { lat: -33.87, lng: 151.21 },  // Sydney
    { lat: 37.77, lng: -122.42 },  // SF
    { lat: 19.43, lng: -99.13 },   // Mexico City
    { lat: 48.86, lng:   2.35 },   // Paris
    { lat: 25.28, lng:  55.31 },   // Dubai
  ];

  async function init() {
    const mount = document.getElementById("globe-bg");
    if (!mount) return;

    try {
      await loadScript("https://cdn.jsdelivr.net/npm/globe.gl@2.33.1/dist/globe.gl.min.js");
    } catch (e) {
      // If globe.gl can't load (offline CDN etc.) — just leave the plain
      // gradient background; no UI degradation.
      console.warn("[globe-bg] globe.gl failed to load", e);
      return;
    }

    const Globe = window.Globe;
    if (!Globe) return;

    const w = () => mount.clientWidth || window.innerWidth;
    const h = () => mount.clientHeight || window.innerHeight;

    const globe = Globe()(mount)
      .width(w())
      .height(h())
      .backgroundColor("rgba(0,0,0,0)")
      .showGlobe(false)          // hollow — countries as hex dots only
      .showAtmosphere(true)
      .atmosphereColor("#7c7cff")
      .atmosphereAltitude(0.20)
      .arcsData(randomArcs(22))
      .arcColor("color")
      .arcStroke(0.3)
      .arcAltitude(0.25)
      .arcAltitudeAutoScale(0.5)
      .arcDashLength(0.35)
      .arcDashGap(0.25)
      .arcDashInitialGap(() => Math.random())
      .arcDashAnimateTime(() => 3500 + Math.random() * 2500)
      .pointsData(ANCHORS)
      .pointAltitude(0.002)
      .pointRadius(0.25)
      .pointColor(() => "rgba(180, 183, 255, 0.9)")
      .pointsMerge(true);

    // Load country geojson → hex-dotted outlines.
    try {
      const countries = await fetch(GEOJSON_URL).then((r) => r.json());
      const features = countries.features.filter(
        (f) => f.properties.ISO_A2 !== "AQ"  // Antarctica just looks weird
      );
      globe
        .hexPolygonsData(features)
        .hexPolygonResolution(3)
        .hexPolygonMargin(0.4)
        .hexPolygonUseDots(true)
        .hexPolygonColor(() => "rgba(140, 140, 200, 0.55)");
    } catch (_) {
      /* geojson is optional cosmetic — ignore failures */
    }

    // OrbitControls: auto-rotate gently; no user interaction.
    const controls = globe.controls();
    controls.enableZoom = false;
    controls.enablePan = false;
    controls.enableRotate = false;
    controls.autoRotate = true;
    controls.autoRotateSpeed = 0.35;

    // Initial camera — pulled back, so the globe sits roughly centered and
    // visible without being overwhelming.
    globe.pointOfView({ lat: 20, lng: 0, altitude: 2.4 }, 0);

    // Mouse parallax — tilt the whole mount element via CSS transform. This
    // is much smoother than fighting three.js camera every frame and doesn't
    // interfere with auto-rotate.
    let targetX = 0, targetY = 0;
    let curX = 0, curY = 0;
    window.addEventListener(
      "pointermove",
      (e) => {
        targetX = (e.clientX / window.innerWidth - 0.5) * 2;
        targetY = (e.clientY / window.innerHeight - 0.5) * 2;
      },
      { passive: true }
    );

    function tick() {
      curX += (targetX - curX) * 0.04;
      curY += (targetY - curY) * 0.04;
      mount.style.transform =
        `perspective(1400px) ` +
        `rotateX(${(-curY * 2.6).toFixed(3)}deg) ` +
        `rotateY(${(curX * 4.2).toFixed(3)}deg) ` +
        `scale(1.08)`;
      requestAnimationFrame(tick);
    }
    tick();

    // Resize handling.
    window.addEventListener(
      "resize",
      () => {
        globe.width(w()).height(h());
      },
      { passive: true }
    );

    // Fade-in once first frame is drawn.
    requestAnimationFrame(() => mount.classList.add("is-ready"));

    // Re-seed arcs every 15s for continuous motion.
    setInterval(() => globe.arcsData(randomArcs(22)), 15000);
  }

  if (document.readyState === "complete") {
    init();
  } else {
    window.addEventListener("load", init, { once: true });
  }
})();
