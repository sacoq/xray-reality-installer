/* xray-panel SPA controller. */

function panel() {
  return {
    view: "dashboard",
    me: null,
    servers: [],
    selected: null,
    sysinfo: null,
    clients: [],
    clientPage: 1,
    clientPageSize: 25,
    clientPages: 1,
    clientTotal: 0,
    clientSearch: "",
    clientLoading: false,
    clientSearchTimer: null,
    pollTimer: null,
    liveData: null,        // {servers: {id: {online_clients, net_rx_bps, ...}}, ts}
    livePollTimer: null,   // separate 8 s poller for /api/servers/live
    live: null,            // per-server detail live block (from /api/servers/{id}/stats)

    // Fleet statistics and chart instances.
    statistics: null,
    statsPeriod: "30d",
    statsServerId: 0,
    statsLoading: false,
    statsErr: "",
    statsCharts: [],
    speedtestBusy: false,
    warpBusy: false,
    tspuBusy: false,

    // Existing-config (locked) node import.
    openCustomNode: false,
    customInspecting: false,
    customBusy: false,
    customErr: "",
    customInbounds: [],
    customNode: {
      name: "", display_name: "", public_host: "",
      agent_url: "", agent_token: "", custom_inbound_tag: "",
      public_key: "", pool_tier: "", bandwidth_mbps: 0,
    },

    openAddServer: false,
    addBusy: false,
    addErr: "",
    newServer: {
      name: "", public_host: "", agent_url: "", agent_token: "",
      port: 443, sni: "rutube.ru", dest: "rutube.ru:443",
      // Auto-balance tier the new node lands in. Empty = not in pool.
      // 'primary' = foreign exit (legacy ⚡ pool); 'fallback' = whitelist
      // bypass node clients fall to when primary tier is unreachable.
      pool_tier: "",
      // Reality stream transport. ``tcp`` (default), ``grpc`` (matches
      // the example config that ships with this repo — serviceName =
      // ``apisub``) or ``xhttp`` (path = ``/sub``). When grpc/xhttp
      // is picked, the per-client ``flow=xtls-rprx-vision`` is force-
      // cleared because xray-core rejects vision on multiplexed
      // transports.
      transport: "tcp",
      transport_path: "",
      bandwidth_mbps: 0,
    },

    // Bulk-upgrade modal state. ``upgradeRows`` is the per-node version
    // snapshot we display before the user fires the upgrade. Once the
    // user kicks the job, ``upgradeJob`` is hydrated from the backend
    // and refreshed via polling, replacing the old single-shot
    // ``upgradeResults`` table with a live per-node status view.
    upgradeAllOpen: false,
    upgradingAll: false,
    upgradeAllErr: "",
    upgradeRepo: "github.com/sacoq/xray-reality-installer",
    upgradeRows: [],
    upgradeJob: null,         // {id, total, done, nodes, succeeded, failed, running}
    upgradeJobId: null,
    upgradePollTimer: null,
    upgradeReconnectAttempts: 0,

    // enrollment
    enrollments: [],
    openEnroll: false,
    enrollBusy: false,
    enrollErr: "",
    newEnroll: {
      name: "", display_name: "", in_pool: false, mode: "standalone",
      // Tier the freshly-enrolled node will join. Mirrors
      // ``Server.pool_tier`` semantics: '' = not in pool,
      // 'primary' = ⚡ foreign exit, 'fallback' = 🛡 whitelist bypass.
      pool_tier: "",
      upstream_server_id: null,
      public_host: "", port: 443, sni: "rutube.ru",
      dest: "rutube.ru:443", agent_port: 8765,
      transport: "tcp",
      transport_path: "",
    },
    enrollCreated: null,

    // Open the enrollment modal with a specific preset.
    // Accepts either:
    //   * a plain boolean (legacy) → interpreted as ``{pool: boolean}``;
    //   * an object
    //     ``{pool?: boolean, balancer?: boolean, whitelist?: boolean,
    //        fallback?: boolean}``.
    // ``balancer=true`` sets mode=balancer and forces in_pool=false.
    // ``whitelist=true`` sets mode=whitelist-front (RU↔foreign chain) and
    // defaults the tier to ``fallback`` so the РФ-фронт shows up in the
    // urltest fallback bucket as soon as it's enrolled.
    // ``fallback=true`` is a standalone fallback node — admin's own
    // whitelist-bypass server that isn't a chain-of-two.
    openEnrollFor(opts) {
      let pool = false;
      let balancer = false;
      let whitelist = false;
      let fallback = false;
      if (typeof opts === "boolean") {
        pool = opts;
      } else if (opts && typeof opts === "object") {
        pool = !!opts.pool;
        balancer = !!opts.balancer;
        whitelist = !!opts.whitelist;
        fallback = !!opts.fallback;
      }
      let mode = "standalone";
      if (balancer) mode = "balancer";
      else if (whitelist) mode = "whitelist-front";
      let tier = "";
      if (balancer) tier = "";
      else if (whitelist || fallback) tier = "fallback";
      else if (pool) tier = "primary";
      this.newEnroll = {
        name: "",
        display_name: "",
        in_pool: tier === "primary",
        pool_tier: tier,
        mode,
        // Default to the first available standalone server when picking
        // a whitelist-front. The user can change it in the modal.
        upstream_server_id: whitelist ? this.firstStandaloneServerId() : null,
        public_host: "",
        port: 443,
        sni: "rutube.ru",
        dest: "rutube.ru:443",
        agent_port: 8765,
        transport: "tcp",
        transport_path: "",
      };
      this.enrollCreated = null;
      this.enrollErr = "";
      this.openEnroll = true;
    },

    // ---------- auto-balance tier helpers ----------
    // Render the per-row tier badge in the dashboard / enrollment
    // listings. Mirrors panel/auto_balance.py:label_prefix_for so the UI
    // and the rendered subscription always agree.
    poolTierIcon(tier) {
      const t = (tier || "").trim().toLowerCase();
      if (t === "primary") return "\u26A1";
      if (t === "fallback") return "\uD83D\uDEE1";
      return "";
    },
    poolTierLabel(tier) {
      const t = (tier || "").trim().toLowerCase();
      if (t === "primary") return "\u26A1 Primary (зарубеж)";
      if (t === "fallback") return "\uD83D\uDEE1 Fallback (обход whitelist)";
      return "Не в пуле";
    },
    // Read the effective tier of a server row regardless of which form
    // (raw ``pool_tier`` or legacy ``in_pool``) the API returned.
    serverTier(s) {
      const t = ((s && s.pool_tier) || "").toLowerCase();
      if (t) return t;
      if (s && s.in_pool) return "primary";
      return "";
    },
    // Keep ``in_pool`` synced with ``pool_tier`` whenever the admin
    // flips the tier in a CRUD form. The backend reconciles the two
    // again on its side, but mirroring here means the in_pool checkbox
    // tracks the tier in real time.
    syncInPoolFromTier(target) {
      if (!target) return;
      target.in_pool = (target.pool_tier === "primary");
    },

    // ---------- transport helpers ----------
    // Per-transport placeholder shown in the "service name / path" input
    // when the admin leaves it empty. Matches the defaults the backend
    // applies in xray_config.build_inbound (apisub / /sub).
    transportPlaceholder(transport) {
      const t = (transport || "tcp").toLowerCase();
      if (t === "grpc") return "apisub";
      if (t === "xhttp") return "/sub";
      return "";
    },
    transportPathLabel(transport) {
      const t = (transport || "tcp").toLowerCase();
      if (t === "grpc") return "gRPC serviceName";
      if (t === "xhttp") return "xHTTP path";
      return "";
    },
    // Short badge text for the dashboard server row + selected detail.
    transportBadge(server) {
      const t = ((server && server.transport) || "tcp").toLowerCase();
      if (t === "grpc") {
        const p = (server.transport_path || "").trim() || "apisub";
        return "grpc · " + p;
      }
      if (t === "xhttp") {
        const p = (server.transport_path || "").trim() || "/sub";
        return "xhttp · " + p;
      }
      return "tcp";
    },

    firstStandaloneServerId() {
      for (const s of this.servers || []) {
        if ((s.mode || "standalone") === "standalone") return s.id;
      }
      return null;
    },

    standaloneServers() {
      return (this.servers || []).filter(
        (s) => (s.mode || "standalone") === "standalone",
      );
    },

    serverById(id) {
      if (id == null) return null;
      return (this.servers || []).find((s) => s.id === id) || null;
    },

    upstreamLabel(id) {
      const s = this.serverById(id);
      if (!s) return "—";
      return s.display_name || s.name;
    },

    // subscriptions
    subs: [],
    openAddSub: false,
    subBusy: false,
    subErr: "",
    newSub: { name: "", include_all: true, client_ids: [] },
    editingSub: null,
    allClientsForSub: [],

    openAddClient: false,
    addClientErr: "",
    newClient: { email: "", label: "", data_limit_gib: 0, expires_in_days: 0,
                 sni_choice: "", sni_custom: "" },

    // per-client edit (limits / expiry)
    editingClient: null,
    editClient: { data_limit_gib: 0, expires_at_str: "" },
    editClientErr: "",

    // api tokens
    tokens: [],
    openAddToken: false,
    newToken: { name: "" },
    addTokenErr: "",
    createdToken: null,

    // edit-server modal
    editingServer: null,
    editServerErr: "",
    editServerBusy: false,
    // Ready-made SNI presets that are widely reachable from RU/EU data centers
    // and pose as "normal Russian web traffic" for DPI masking.
    sniPresets: [
      { label: "ya.ru (Яндекс)",          sni: "ya.ru",          dest: "ya.ru:443" },
      { label: "yandex.ru (Яндекс)",      sni: "yandex.ru",      dest: "yandex.ru:443" },
      { label: "dzen.ru (Яндекс)",        sni: "dzen.ru",        dest: "dzen.ru:443" },
      { label: "mail.ru (VK)",            sni: "mail.ru",        dest: "mail.ru:443" },
      { label: "ok.ru (VK)",              sni: "ok.ru",          dest: "ok.ru:443" },
      { label: "vk.com (VK)",             sni: "vk.com",         dest: "vk.com:443" },
      { label: "avito.ru (CloudFront)",   sni: "avito.ru",       dest: "avito.ru:443" },
      { label: "kinopoisk.ru (Яндекс)",   sni: "kinopoisk.ru",   dest: "kinopoisk.ru:443" },
      { label: "www.cloudflare.com",      sni: "www.cloudflare.com", dest: "www.cloudflare.com:443" },
      { label: "github.com",              sni: "github.com",     dest: "github.com:443" },
    ],

    linkFor: null,
    showLogs: false,
    logsText: "",
    logsBusy: false,

    // Live status line shown in a banner while the UI polls a node after
    // requesting a reboot (empty string = no banner).
    rebootStatus: "",

    // global toast ("Скопировано" / errors)
    toast: "",
    toastErr: false,
    toastTimer: null,

    pw: { current: "", next: "", msg: "", ok: false },

    // theme
    theme: "dark",

    // audit log
    logs: [],
    logsLimit: 100,
    logsOffset: 0,
    logsFilter: "",

    // 2FA
    totpSetup: { secret: "", uri: "", code: "", msg: "", ok: false },
    totpDisable: { code: "", msg: "", ok: false },

    // telegram
    telegram: { bot_token: "", bot_token_set: false, chat_id: "", msg: "", ok: false },

    // bulk create
    openBulkClient: false,
    bulkClient: {
      email_prefix: "user", count: 10, label: "",
      data_limit_gib: 0, expires_in_days: 0,
      busy: false, err: "",
    },

    // tg bots
    bots: [],
    openBotForm: false,
    botForm: {
      id: null, name: "", bot_token: "", owner_chat_id: "", welcome_text: "",
      default_server_id: null, server_ids: [], default_days: 30,
      default_data_limit_bytes: 0, device_limit: 3, enabled: true,
      profile_title: "", support_url: "", announce: "",
      provider_id: "", routing: "", update_interval_hours: 24,
      subscription_domain: "", brand_name: "", logo_url: "",
      page_subtitle: "", page_help_text: "", page_buy_url: "",
      referral_mode: "off", referral_levels: 1,
      referral_l1_days: 0, referral_l2_days: 0, referral_l3_days: 0,
      referral_l1_percent: 0, referral_l2_percent: 0, referral_l3_percent: 0,
      referral_payout_url: "",
    },
    botFormErr: "",
    botPlans: [],
    botServerOverrides: {},
    panelSettings: { subscription_url_base: "", public_url: "" },

    // Panel-wide auto-balance / probe knobs (GET / PATCH
    // /api/load-balancer/settings). The defaults here are only shown
    // before the first load — once the dashboard fetches them, the
    // payload from the backend wins. Editable inline in the dashboard
    // panel «⚡🛡 Авто-балансировка».
    lbSettings: {
      probe_url: "https://www.gstatic.com/generate_204",
      probe_interval_seconds: 30,
      tolerance_ms: 50,
    },
    lbSettingsLoaded: false,
    lbSettingsBusy: false,
    lbSettingsErr: "",
    lbSettingsMsg: "",

    domainBackend: "",
    domainBusy: false,
    domainResult: "",
    domainResultOk: false,
    openBotUsersModal: false,
    botUsersBot: null,
    botUsers: [],
    botsPollTimer: null,

    // payments
    plans: [],
    orders: [],
    paymentSettings: {
      stars_enabled: false,
      cryptobot_enabled: false,
      cryptobot_token_masked: "",
      cryptobot_testnet: false,
      freekassa_enabled: false,
      freekassa_merchant_id: "",
      freekassa_secret1_masked: "",
      freekassa_secret2_masked: "",
      freekassa_payment_system_id: "",
    },
    paymentSettingsInput: {
      cryptobot_token: "",
      freekassa_merchant_id: "",
      freekassa_secret1: "",
      freekassa_secret2: "",
      freekassa_payment_system_id: "",
    },
    openPlan: false,
    planEdit: {
      id: null, name: "", duration_days: 30, enabled: true,
      sort_order: 0, data_limit_bytes: 0,
      price_stars: 0, price_crypto_usdt_cents: 0, price_rub_kopecks: 0,
      _data_limit_gb: 0,
      _price_crypto_usdt: 0,
      _price_rub: 0,
    },

    async init() {
      this.applyStoredTheme();
      this.clientPageSize = window.innerWidth < 768 ? 25 : 50;
      try {
        const r = await fetch("/api/auth/me");
        if (!r.ok) { window.location.href = "/ui/login"; return; }
        this.me = await r.json();
      } catch (_) { window.location.href = "/ui/login"; return; }
      await this.loadServers();
      // Fire an initial live poll immediately so server cards have
      // online-client counts from the first render, then every ~8 s.
      await this.refreshLive();
      this.livePollTimer = setInterval(() => this.refreshLive(), 5000);
    },

    async refreshLive() {
      // Batch live snapshot for all server cards. Best-effort — if the
      // endpoint doesn't exist (old panel) or the request fails we just
      // keep the last known data (or null).
      if (this.view === "dashboard") {
        try {
          const r = await fetch("/api/servers/live");
          if (r.ok) this.liveData = await r.json();
        } catch (_) {}
      }
    },

    serverLive(serverId) {
      // Helper for templates: return the live entry for a server, or null.
      if (!this.liveData || !this.liveData.servers) return null;
      return this.liveData.servers[String(serverId)] || null;
    },

    stopLivePoll() {
      if (this.livePollTimer) {
        clearInterval(this.livePollTimer);
        this.livePollTimer = null;
      }
      this.liveData = null;
    },

    async loadServers() {
      const r = await fetch("/api/servers");
      if (r.status === 401) { window.location.href = "/ui/login"; return; }
      this.servers = await r.json();
    },

    async loadEnrollments() {
      const r = await fetch("/api/enrollments");
      if (!r.ok) return;
      this.enrollments = await r.json();
    },

    async loadSubscriptions() {
      const r = await fetch("/api/subscriptions");
      if (!r.ok) return;
      this.subs = await r.json();
    },

    async loadAllClientsForSub() {
      // Collect clients from every server for the subscription picker.
      const servers = this.servers;
      const batches = await Promise.all(servers.map(async (s) => {
        try {
          const r = await fetch("/api/servers/" + s.id + "/clients");
          if (!r.ok) return [];
          const list = await r.json();
          return list.map((c) => ({ ...c, server_name: s.name }));
        } catch (_) { return []; }
      }));
      this.allClientsForSub = batches.flat();
    },

    async switchView(v) {
      this.view = v;
      // The dashboard view is the only one that renders the per-server
      // detail pane. On every other view the live polling of
      // ``/api/servers/{id}/stats`` would keep mutating ``selected``
      // and ``clients`` for nothing — Alpine still re-evaluates every
      // reactive binding on a (now-hidden) heavy clients table on each
      // tick, which combined with the page's WebGL background and many
      // ``backdrop-filter: blur`` glass panels visibly drops FPS to
      // 10–20 until the user hard-reloads.
      if (v !== "dashboard") {
        this.stopServerPoll();
      }
      if (v !== "statistics") this.destroyStatisticsCharts();
      if (v === "statistics") await this.loadStatistics();
      if (v === "enrollments") await this.loadEnrollments();
      if (v === "subscriptions") { await this.loadSubscriptions(); }
      if (v === "tokens") await this.loadTokens();
      if (v === "bots") {
        await this.loadBots();
        await this.loadPanelSettings();
        this.startBotsPoll();
      } else {
        this.stopBotsPoll();
      }
      if (v === "payments") { await this.loadPayments(); }
      if (v === "logs") { this.logsOffset = 0; await this.loadLogs(); }
      if (v === "account") await this.loadTelegram();
    },

    stopServerPoll() {
      // Idempotent — callable from anywhere that wants to silence the
      // 5s server-stats refresh (switching views, deleting the server,
      // returning to the server list).
      if (this.pollTimer) {
        clearInterval(this.pollTimer);
        this.pollTimer = null;
      }
      this.selected = null;
      this.clients = [];
      this.live = null;
      this.sysinfo = null;
      this.clientPage = 1;
      this.clientPages = 1;
      this.clientTotal = 0;
      clearTimeout(this.clientSearchTimer);
    },

    closeServerDetail() {
      this.stopServerPoll();
    },

    async selectServer(id) {
      const r = await fetch("/api/servers/" + id);
      if (!r.ok) return;
      this.selected = await r.json();
      this.clientPage = 1;
      this.clientSearch = "";
      this.clients = [];
      await Promise.all([this.refreshStats(), this.loadClientPage(1)]);
      clearInterval(this.pollTimer);
      this.pollTimer = setInterval(() => this.refreshStats(), 5000);
    },

    async refreshStats() {
      // Bail out unless the user is actually looking at the server
      // detail pane. Alpine doesn't garbage-collect bindings of a
      // hidden ``x-show`` subtree, so writing to ``this.selected`` from
      // a stale interval still triggers diffs all over the page.
      if (!this.selected || this.view !== "dashboard") return;
      try {
        const ids = this.clients.map((client) => client.id).join(",");
        const query = new URLSearchParams({ include_clients: "false" });
        if (ids) query.set("client_ids", ids);
        const selectedId = this.selected.id;
        const r = await fetch(
          "/api/servers/" + selectedId + "/stats?" + query.toString(),
        );
        if (!r.ok) return;
        const data = await r.json();
        if (!this.selected || this.selected.id !== selectedId) return;
        this.sysinfo = data.sysinfo;
        this.live = data.live || null;
        const liveById = data.client_live || {};
        for (const client of this.clients) {
          const rate = liveById[String(client.id)];
          if (rate) Object.assign(client, rate);
          else Object.assign(client, { online: false, up_bps: 0, down_bps: 0 });
        }
        this.selected.online = data.online;
      } catch (_) {}
    },

    async loadClientPage(page = this.clientPage) {
      if (!this.selected) return;
      const selectedId = this.selected.id;
      const targetPage = Math.max(1, Number(page || 1));
      const query = new URLSearchParams({
        page: String(targetPage),
        page_size: String(this.clientPageSize),
      });
      if (this.clientSearch.trim()) query.set("q", this.clientSearch.trim());
      this.clientLoading = true;
      try {
        const r = await fetch(
          "/api/servers/" + selectedId + "/clients/page?" + query.toString(),
        );
        if (!r.ok) return;
        const data = await r.json();
        if (!this.selected || this.selected.id !== selectedId) return;
        this.clients = data.items || [];
        this.clientPage = Number(data.page || 1);
        this.clientPages = Number(data.pages || 1);
        this.clientTotal = Number(data.total || 0);
      } finally {
        if (this.selected && this.selected.id === selectedId) {
          this.clientLoading = false;
        }
      }
    },

    debounceClientSearch() {
      clearTimeout(this.clientSearchTimer);
      this.clientSearchTimer = setTimeout(() => this.loadClientPage(1), 250);
    },

    async goClientPage(page) {
      const target = Math.max(1, Math.min(this.clientPages, Number(page || 1)));
      if (target === this.clientPage) return;
      await this.loadClientPage(target);
    },

    _mergeClients(incoming) {
      // Reconcile the client list in-place keyed by ``id`` instead of
      // replacing the whole array. Alpine's ``x-for`` reuses DOM nodes
      // by key, but assigning a brand-new array still forces a diff over
      // every row — and on mobile that visibly re-renders the table mid
      // touch-scroll, so the user perceives a "page reload" while they
      // are flinging through the client list. Mutating the existing
      // entries in place keeps the same node identities and lets the
      // browser's momentum scroll stay anchored.
      const byId = new Map(incoming.map((c) => [c.id, c]));
      for (let i = this.clients.length - 1; i >= 0; i--) {
        const cur = this.clients[i];
        const next = byId.get(cur.id);
        if (!next) {
          this.clients.splice(i, 1);
        } else {
          Object.assign(cur, next);
          byId.delete(cur.id);
        }
      }
      for (const c of incoming) {
        if (byId.has(c.id)) this.clients.push(c);
      }
    },

    // ---------- fleet statistics ----------
    async loadStatistics() {
      this.statsLoading = true;
      this.statsErr = "";
      try {
        const query = new URLSearchParams({ period: this.statsPeriod });
        if (Number(this.statsServerId || 0) > 0) {
          query.set("server_id", String(this.statsServerId));
        }
        const r = await fetch("/api/statistics?" + query.toString());
        if (!r.ok) {
          const j = await r.json().catch(() => ({}));
          this.statsErr = j.detail || ("Ошибка " + r.status);
          return;
        }
        this.statistics = await r.json();
        this.$nextTick(() => this.renderStatisticsCharts());
      } catch (err) {
        this.statsErr = String(err || "Ошибка загрузки статистики");
      } finally {
        this.statsLoading = false;
      }
    },

    async setStatsPeriod(period) {
      this.statsPeriod = period;
      await this.loadStatistics();
    },

    destroyStatisticsCharts() {
      for (const chart of this.statsCharts) {
        try { chart.destroy(); } catch (_) {}
      }
      this.statsCharts = [];
    },

    renderStatisticsCharts() {
      this.destroyStatisticsCharts();
      if (!window.Chart || !this.statistics) return;
      const points = this.statistics.series || [];
      const isDark = this.theme === "dark";
      const grid = isDark ? "rgba(100,116,139,.16)" : "rgba(51,65,85,.12)";
      const text = isDark ? "#94a3b8" : "#475569";
      const labels = points.map((p) => this.fmtChartDate(p.ts));
      const common = {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        interaction: { mode: "index", intersect: false },
        plugins: { legend: { labels: { color: text, boxWidth: 10 } } },
        scales: {
          x: { ticks: { color: text, maxTicksLimit: 12 }, grid: { color: grid } },
          y: { beginAtZero: true, ticks: { color: text }, grid: { color: grid } },
        },
      };
      const resourceEl = document.getElementById("stats-resource-chart");
      if (resourceEl) {
        this.statsCharts.push(new Chart(resourceEl, {
          type: "line",
          data: {
            labels,
            datasets: [
              { label: "Общая", data: points.map((p) => p.load_percent || 0), borderColor: "#22c55e", backgroundColor: "rgba(34,197,94,.1)", tension: .22, pointRadius: 0, fill: true },
              { label: "CPU", data: points.map((p) => p.cpu_percent || 0), borderColor: "#fb7185", tension: .22, pointRadius: 0 },
              { label: "RAM", data: points.map((p) => p.memory_percent || 0), borderColor: "#f59e0b", tension: .22, pointRadius: 0 },
              { label: "Сеть", data: points.map((p) => p.network_percent || 0), borderColor: "#22d3ee", tension: .22, pointRadius: 0 },
            ],
          },
          options: { ...common, scales: { ...common.scales, y: { ...common.scales.y, suggestedMax: 100, max: 100 } } },
        }));
      }
      const trafficEl = document.getElementById("stats-traffic-chart");
      if (trafficEl) {
        const hourly = this.statsPeriod === "24h";
        this.statsCharts.push(new Chart(trafficEl, {
          type: "bar",
          data: {
            labels,
            datasets: hourly ? [
              { label: "Download, Мбит/с", data: points.map((p) => Number(p.net_rx_bps || 0) * 8 / 1e6), backgroundColor: "rgba(34,211,238,.65)" },
              { label: "Upload, Мбит/с", data: points.map((p) => Number(p.net_tx_bps || 0) * 8 / 1e6), backgroundColor: "rgba(251,113,133,.65)" },
            ] : [
              { label: "Download, ГиБ/день", data: points.map((p) => Number(p.traffic_down_bytes || 0) / 1073741824), backgroundColor: "rgba(34,211,238,.65)" },
              { label: "Upload, ГиБ/день", data: points.map((p) => Number(p.traffic_up_bytes || 0) / 1073741824), backgroundColor: "rgba(251,113,133,.65)" },
            ],
          },
          options: common,
        }));
      }
      const speedRows = (this.statistics.speedtests || []).filter((row) => !row.error);
      const speedEl = document.getElementById("stats-speed-chart");
      if (speedEl) {
        this.statsCharts.push(new Chart(speedEl, {
          type: "line",
          data: {
            labels: speedRows.map((row) => this.fmtChartDate(row.tested_at)),
            datasets: [
              { label: "Download, Мбит/с", data: speedRows.map((row) => row.download_mbps || 0), borderColor: "#22d3ee", tension: .2, pointRadius: 2 },
              { label: "Upload, Мбит/с", data: speedRows.map((row) => row.upload_mbps || 0), borderColor: "#a78bfa", tension: .2, pointRadius: 2 },
            ],
          },
          options: common,
        }));
      }
    },

    fmtChartDate(value) {
      if (!value) return "";
      const date = new Date(value);
      if (Number.isNaN(date.getTime())) return String(value);
      const options = this.statsPeriod === "24h"
        ? { hour: "2-digit", minute: "2-digit" }
        : { day: "2-digit", month: "short" };
      return date.toLocaleString("ru-RU", options);
    },

    // ---------- custom config node ----------
    openCustomNodeModal() {
      this.customNode = {
        name: "", display_name: "", public_host: "",
        agent_url: "", agent_token: "", custom_inbound_tag: "",
        public_key: "", pool_tier: "", bandwidth_mbps: 0,
      };
      this.customInbounds = [];
      this.customErr = "";
      this.openCustomNode = true;
    },

    selectedCustomInbound() {
      return this.customInbounds.find(
        (item) => item.tag === this.customNode.custom_inbound_tag,
      ) || null;
    },

    async inspectCustomNode() {
      this.customInspecting = true;
      this.customErr = "";
      this.customInbounds = [];
      try {
        const r = await fetch("/api/servers/custom/inspect", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            agent_url: this.customNode.agent_url,
            agent_token: this.customNode.agent_token,
          }),
        });
        if (!r.ok) {
          const j = await r.json().catch(() => ({}));
          this.customErr = j.detail || ("Ошибка " + r.status);
          return;
        }
        const data = await r.json();
        this.customInbounds = data.inbounds || [];
        if (this.customInbounds.length) {
          this.customNode.custom_inbound_tag = this.customInbounds[0].tag;
          this.customNode.public_key = this.customInbounds[0].public_key || "";
        } else {
          this.customErr = "VLESS+Reality inbound с tag не найден";
        }
      } finally {
        this.customInspecting = false;
      }
    },

    syncCustomInbound() {
      const inbound = this.selectedCustomInbound();
      if (inbound && inbound.public_key) this.customNode.public_key = inbound.public_key;
    },

    async createCustomNode() {
      const inbound = this.selectedCustomInbound();
      if (!inbound) {
        this.customErr = "Сначала проверь агент и выбери inbound";
        return;
      }
      this.customBusy = true;
      this.customErr = "";
      try {
        const payload = {
          name: this.customNode.name,
          display_name: this.customNode.display_name || "",
          mode: "custom",
          custom_inbound_tag: this.customNode.custom_inbound_tag,
          public_host: this.customNode.public_host,
          agent_url: this.customNode.agent_url,
          agent_token: this.customNode.agent_token,
          public_key: this.customNode.public_key || null,
          port: 443,
          sni: "placeholder.invalid",
          dest: "placeholder.invalid:443",
          pool_tier: this.customNode.pool_tier || "",
          in_pool: this.customNode.pool_tier === "primary",
          bandwidth_mbps: Number(this.customNode.bandwidth_mbps || 0),
        };
        const r = await fetch("/api/servers", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(payload),
        });
        if (!r.ok) {
          const j = await r.json().catch(() => ({}));
          this.customErr = j.detail || ("Ошибка " + r.status);
          return;
        }
        this.openCustomNode = false;
        await this.loadServers();
        this.flash("Custom-нода добавлена; её xray-параметры заблокированы");
      } finally {
        this.customBusy = false;
      }
    },

    async addServer() {
      this.addBusy = true; this.addErr = "";
      // Mirror the tier into ``in_pool`` so callers reading the legacy
      // field still get the right value. Backend reconciles either way,
      // but sending both keeps server-side audit logs accurate.
      const payload = {
        ...this.newServer,
        in_pool: this.newServer.pool_tier === "primary",
      };
      try {
        const r = await fetch("/api/servers", {
          method: "POST",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(payload),
        });
        if (!r.ok) {
          const j = await r.json().catch(()=>({}));
          this.addErr = j.detail || ("Ошибка " + r.status);
          return;
        }
        this.openAddServer = false;
        this.newServer = { name: "", public_host: "", agent_url: "", agent_token: "",
          port: 443, sni: "rutube.ru", dest: "rutube.ru:443", pool_tier: "",
          transport: "tcp", transport_path: "", bandwidth_mbps: 0 };
        await this.loadServers();
      } finally { this.addBusy = false; }
    },

    // Open the bulk-upgrade modal and kick off a per-node version
    // probe in parallel. Each probe hits GET /api/servers/<id>/version,
    // which the agent serves from its update-cache file (no GitHub I/O
    // here — the systemd timer keeps that fresh). We render
    // installed/latest pairs so the admin sees what's about to change
    // before confirming.
    openUpgradeAll() {
      this.upgradeAllErr = "";
      this.upgradeJob = null;
      this.upgradeJobId = null;
      this.upgradingAll = false;
      this.upgradeReconnectAttempts = 0;
      this._stopUpgradePoll();
      this.upgradeRows = (this.servers || []).map((s) => ({
        server_id: s.id,
        name: s.name,
        installed: "",
        latest: "",
        status: "",
        error: "",
        loading: true,
      }));
      this.upgradeAllOpen = true;
      // Re-trigger Lucide so the modal's icons render.
      this.$nextTick(() => { try { lucide.createIcons(); } catch (_) {} });
      // Probe versions in parallel; failures stay as "—" and don't
      // block the upgrade button.
      this.upgradeRows.forEach((row) => this.probeVersion(row));
    },

    resetUpgradeModal() {
      this._stopUpgradePoll();
      this.upgradeJob = null;
      this.upgradeJobId = null;
      this.upgradingAll = false;
      this.upgradeAllErr = "";
      this.upgradeReconnectAttempts = 0;
      // Re-probe versions so the admin sees fresh state without
      // closing/reopening the modal.
      this.upgradeRows = (this.servers || []).map((s) => ({
        server_id: s.id,
        name: s.name,
        installed: "",
        latest: "",
        status: "",
        error: "",
        loading: true,
      }));
      this.upgradeRows.forEach((row) => this.probeVersion(row));
    },

    // Human-friendly "7 / 12" pair for the progress bar header.
    get upgradeProgressLabel() {
      const j = this.upgradeJob;
      if (!j) return this.upgradingAll ? "…" : "";
      const done = (j.succeeded || 0) + (j.failed || 0);
      return done + " / " + (j.total || 0);
    },

    // 0..100. Empty job is still 0 (we show “starting…” above the bar).
    get upgradeProgressPct() {
      const j = this.upgradeJob;
      if (!j || !j.total) return 0;
      const done = (j.succeeded || 0) + (j.failed || 0);
      return Math.max(0, Math.min(100, Math.round((done / j.total) * 100)));
    },

    async probeVersion(row) {
      try {
        const r = await fetch("/api/servers/" + row.server_id + "/version");
        if (!r.ok) {
          const j = await r.json().catch(()=>({}));
          row.error = j.detail || ("HTTP " + r.status);
          return;
        }
        const j = await r.json();
        row.installed = j.installed || "";
        row.latest = j.latest || "";
        row.status = j.status || "";
      } catch (e) {
        row.error = "недоступно";
      } finally {
        row.loading = false;
      }
    },

    // Kick off a background bulk-upgrade and start polling for live
    // per-node status. We:
    //   1) POST /api/admin/upgrade-jobs → returns ``job_id`` and the
    //      initial node list.
    //   2) Start a 1s poll on /api/admin/upgrade-jobs/{job_id} so the
    //      modal shows each agent flipping running→ok/error as it
    //      happens.
    //   3) Stop polling once the job reports ``done``.
    //
    // When the panel host itself is being upgraded the poll request
    // can briefly fail (xray-panel.service restart) — we tolerate a
    // handful of failures and keep polling so the modal recovers
    // automatically once the panel comes back.
    async upgradeAll() {
      if (this.upgradingAll || this.upgradeJob) return;
      this.upgradingAll = true;
      this.upgradeAllErr = "";
      this.upgradeReconnectAttempts = 0;
      try {
        const r = await fetch("/api/admin/upgrade-jobs", { method: "POST" });
        if (!r.ok) {
          const j = await r.json().catch(()=>({}));
          this.upgradeAllErr = j.detail || ("Ошибка " + r.status);
          this.upgradingAll = false;
          return;
        }
        const j = await r.json();
        this.upgradeJobId = j.job_id;
        this.upgradeJob = j;
        this.$nextTick(() => { try { lucide.createIcons(); } catch (_) {} });
        this._startUpgradePoll();
      } catch (e) {
        this.upgradeAllErr =
          "Не удалось запустить апгрейд — проверь связь с панелью и попробуй ещё раз.";
        this.upgradingAll = false;
      }
    },

    _startUpgradePoll() {
      this._stopUpgradePoll();
      this.upgradePollTimer = setInterval(
        () => this._pollUpgradeJob(),
        1000,
      );
    },

    _stopUpgradePoll() {
      if (this.upgradePollTimer) {
        clearInterval(this.upgradePollTimer);
        this.upgradePollTimer = null;
      }
    },

    async _pollUpgradeJob() {
      const jid = this.upgradeJobId;
      if (!jid) { this._stopUpgradePoll(); return; }
      try {
        const r = await fetch("/api/admin/upgrade-jobs/" + jid);
        if (!r.ok) {
          // 404 = the panel restarted and lost the in-memory job
          // (e.g. local agent upgrade kicked xray-panel.service). Stop
          // polling, leave the last snapshot on screen, surface a hint.
          if (r.status === 404) {
            this._stopUpgradePoll();
            this.upgradingAll = false;
            if (this.upgradeJob) this.upgradeJob.done = true;
            this.upgradeAllErr =
              "Панель перезапустилась во время апгрейда — " +
              "проверь версии вручную в списке нод.";
            return;
          }
          // 5xx / 401 — keep polling, the panel-host upgrade can drop
          // a few requests while xray-panel restarts.
          this._noteUpgradeReconnect();
          return;
        }
        const j = await r.json();
        this.upgradeJob = j;
        this.upgradeReconnectAttempts = 0;
        this.$nextTick(() => { try { lucide.createIcons(); } catch (_) {} });
        if (j.done) {
          this._stopUpgradePoll();
          this.upgradingAll = false;
        }
      } catch (e) {
        // Network/connection refused — panel may be restarting.
        this._noteUpgradeReconnect();
      }
    },

    _noteUpgradeReconnect() {
      this.upgradeReconnectAttempts += 1;
      // After ~60 consecutive failures (~60s with 1s poll) give up so
      // we don't poll forever if the panel never comes back.
      if (this.upgradeReconnectAttempts > 60) {
        this._stopUpgradePoll();
        this.upgradingAll = false;
        if (this.upgradeJob) this.upgradeJob.done = true;
        this.upgradeAllErr =
          "Нет связи с панелью больше минуты. Проверь статус вручную.";
      }
    },

    openEditServer() {
      if (!this.selected) return;
      this.editingServer = {
        id: this.selected.id,
        name: this.selected.name,
        display_name: this.selected.display_name || "",
        tags_text: (this.selected.tags || []).join(", "),
        warp_enabled: !!this.selected.warp_enabled,
        warp_domains_text: (this.selected.warp_domains || []).join("\n"),
        warp_license: "",
        warp_status: null,
        in_pool: !!this.selected.in_pool,
        // Auto-balance tier (primary / fallback / none). Falls back to
        // ``in_pool`` for legacy server rows so the admin still sees the
        // right tier in the dropdown when the row predates pool_tier.
        pool_tier: this.serverTier(this.selected),
        // Initial mode of the row. The template branches on this to
        // hide the upstream picker for balancer rows; ``saveServer``
        // never sends ``mode`` itself — instead the backend flips it
        // automatically when ``upstream_server_id`` is set / cleared.
        mode: this.selected.mode || "standalone",
        // Currently-attached foreign exit (only meaningful for
        // ``whitelist-front`` rows). Coerced to a number-or-null so
        // the ``<select x-model.number>`` round-trip works cleanly —
        // Alpine writes ``NaN`` into the model when the picker resets
        // to "— without exit —" otherwise.
        upstream_server_id: this.selected.upstream_server_id == null
          ? null
          : Number(this.selected.upstream_server_id),
        public_host: this.selected.public_host,
        port: this.selected.port,
        sni: this.selected.sni,
        dest: this.selected.dest,
        transport: (this.selected.transport || "tcp"),
        transport_path: (this.selected.transport_path || ""),
        bandwidth_mbps: Number(this.selected.bandwidth_mbps || 0),
        agent_url: this.selected.agent_url,
        agent_token: "",  // empty = keep existing
      };
      this.editServerErr = "";
      this.checkWarpStatus();
    },
    applyPreset(preset) {
      if (!this.editingServer) return;
      this.editingServer.sni = preset.sni;
      this.editingServer.dest = preset.dest;
    },
    async saveServer() {
      if (!this.editingServer) return;
      const tier = (this.editingServer.pool_tier || "").toLowerCase();
      const body = {
        name: this.editingServer.name,
        display_name: this.editingServer.display_name || "",
        tags: (this.editingServer.tags_text || "")
          .split(/[\n,]/).map(v => v.trim()).filter(Boolean),
        warp_enabled: !!this.editingServer.warp_enabled,
        warp_domains: (this.editingServer.warp_domains_text || "")
          .split(/[\n,]/).map(v => v.trim()).filter(Boolean),
        // Send both fields so both old and new backend code paths see
        // the right value. The server reconciles them on its side.
        in_pool: tier === "primary",
        pool_tier: tier,
        public_host: this.editingServer.public_host,
        port: Number(this.editingServer.port),
        sni: this.editingServer.sni,
        dest: this.editingServer.dest,
        transport: (this.editingServer.transport || "tcp"),
        transport_path: (this.editingServer.transport_path || ""),
        bandwidth_mbps: Number(this.editingServer.bandwidth_mbps || 0),
        agent_url: this.editingServer.agent_url,
      };
      if ((this.editingServer.mode || "standalone") === "custom") {
        for (const key of [
          "public_host", "port", "sni", "dest", "transport",
          "transport_path", "agent_url",
        ]) delete body[key];
      }
      // Foreign-upstream knob — always send it for non-balancer rows
      // (including ``null`` when cleared) so the backend can flip the
      // mode in either direction. Balancer rows reject the field
      // server-side, so omit it for them.
      if (!["balancer", "custom"].includes(this.editingServer.mode || "standalone")) {
        const up = this.editingServer.upstream_server_id;
        body.upstream_server_id = (up == null || up === "" || Number.isNaN(Number(up)))
          ? null
          : Number(up);
      }
      // Only send a new token if the user typed one (keeps the existing secret
      // intact when the field is left blank).
      if (this.editingServer.agent_token && this.editingServer.agent_token.trim()) {
        body.agent_token = this.editingServer.agent_token.trim();
      }
      this.editServerBusy = true; this.editServerErr = "";
      try {
        const r = await fetch("/api/servers/" + this.editingServer.id, {
          method: "PATCH",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(body),
        });
        if (!r.ok) {
          const j = await r.json().catch(()=>({}));
          this.editServerErr = j.detail || ("Ошибка " + r.status);
          return;
        }
        const updated = await r.json();
        this.selected = { ...this.selected, ...updated };
        this.editingServer = null;
        await this.loadServers();
        await this.refreshStats();
        this.flash("Сервер обновлён — возьми новый vless:// если менял SNI/dest/порт");
      } finally { this.editServerBusy = false; }
    },

    async checkWarpStatus() {
      if (!this.editingServer) return;
      const serverId = this.editingServer.id;
      try {
        const r = await fetch("/api/servers/" + serverId + "/warp");
        const j = await r.json().catch(() => ({}));
        if (!r.ok) throw new Error(j.detail || ("Ошибка " + r.status));
        if (this.editingServer?.id === serverId) this.editingServer.warp_status = j;
      } catch (e) {
        if (this.editingServer?.id === serverId) {
          this.editingServer.warp_status = { reachable: false, message: String(e.message || e) };
        }
      }
    },

    async installWarp() {
      if (!this.editingServer || this.warpBusy) return;
      this.warpBusy = true; this.editServerErr = "";
      try {
        const r = await fetch(
          "/api/servers/" + this.editingServer.id + "/warp/install",
          {
            method: "POST",
            headers: {"content-type":"application/json"},
            body: JSON.stringify({license_key: this.editingServer.warp_license || ""}),
          },
        );
        const j = await r.json().catch(() => ({}));
        if (!r.ok) {
          this.editServerErr = j.detail || ("Ошибка " + r.status);
          return;
        }
        this.editingServer.warp_status = j;
        this.editingServer.warp_enabled = true;
        if (!this.editingServer.warp_domains_text.trim()) {
          this.editingServer.warp_domains_text = [
            "domain:deepmind.com", "domain:deepmind.google",
            "domain:geller-pa.googleapis.com", "domain:generativelanguage.googleapis.com",
            "domain:proactivebackend-pa.googleapis.com", "domain:ai.google.dev",
            "domain:generativeai.google", "domain:makersuite.google.com",
            "domain:aistudio.google.com", "domain:bard.google.com",
            "domain:gemini.google", "domain:gemini.google.com",
            "domain:notebooklm.google.com", "domain:clients6.google.com",
            "domain:notebooklm.google", "domain:jules.google", "domain:jules.google.com",
            "domain:labs.google", "domain:aisandbox-pa.googleapis.com",
            "domain:stitch.withgoogle.com", "domain:robinfrontend-pa.googleapis.com",
            "domain:aida.googleapis.com", "domain:antigravity-pa.googleapis.com",
            "domain:antigravity.googleapis.com", "domain:antigravity.google",
            "domain:antigravity-unleash.goog", "domain:firebaseinstallations.googleapis.com",
            "domain:speechs3proto2-pa.googleapis.com", "geosite:google-gemini", "geosite:google",
          ].join("\n");
        }
        this.flash("WARP установлен и проверен. Сохрани параметры, чтобы включить outbound.");
      } finally { this.warpBusy = false; }
    },

    async checkTspu(serverId = null) {
      const id = Number(serverId || this.selected?.id || 0);
      if (!id || this.tspuBusy) return;
      this.tspuBusy = true;
      try {
        const r = await fetch("/api/servers/" + id + "/tspu/check", {method:"POST"});
        const j = await r.json().catch(() => ({}));
        if (!r.ok) {
          this.flash(j.detail || ("Ошибка " + r.status), true);
          return;
        }
        await this.loadServers();
        if (this.selected?.id === id) {
          const sr = await fetch("/api/servers/" + id);
          if (sr.ok) this.selected = await sr.json();
        }
        if (j.blocked) {
          this.flash("ТСПУ: IP отмечен как заблокированный, нода исключена из пула");
        } else if (j.error) {
          this.flash("ТСПУ: проверка завершилась с ошибкой: " + j.error, true);
        } else {
          this.flash("ТСПУ: блокировка IP не обнаружена");
        }
      } finally { this.tspuBusy = false; }
    },

    async deleteSelectedServer() {
      if (!this.selected) return;
      if (!confirm("Удалить сервер " + this.selected.name + "? Эта операция не удаляет xray с самого сервера.")) return;
      await fetch("/api/servers/" + this.selected.id, { method: "DELETE" });
      this.stopServerPoll();
      await this.loadServers();
    },

    // ---------- server management ----------
    async xrayAction(action) {
      if (!this.selected) return;
      const label = { restart:"перезапустить", start:"запустить", stop:"остановить" }[action] || action;
      if (!confirm("Точно " + label + " xray на " + this.selected.name + "?")) return;
      const r = await fetch("/api/servers/" + this.selected.id + "/xray/" + action, { method: "POST" });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.flash(j.detail || "Ошибка " + r.status, true);
        return;
      }
      const d = await r.json().catch(()=>({}));
      this.flash("xray " + action + ": " + (d.xray_active ? "active" : "down"));
      await this.refreshStats();
      await this.loadServers();
    },

    async openXrayLogs() {
      if (!this.selected) return;
      this.logsBusy = true; this.logsText = ""; this.showLogs = true;
      try {
        const r = await fetch("/api/servers/" + this.selected.id + "/xray/logs?lines=300");
        if (!r.ok) { this.logsText = "Ошибка загрузки логов."; return; }
        const j = await r.json();
        this.logsText = (j.lines || []).join("\n") || "(журнал пуст)";
      } finally { this.logsBusy = false; }
    },

    async rebootServer() {
      if (!this.selected) return;
      // Two-step confirmation: typing the server name to avoid fat-finger
      // reboots. On bare-metal / cloud VMs a failed boot means SSH down
      // until the user opens the hosting provider's console.
      const name = this.selected.name;
      const typed = prompt(
        "Перезагрузка всего сервера — xray и SSH будут недоступны минимум минуту, и если ядро/fsck зависнет на старте, потребуется консоль хостера для ручного восстановления.\n\n" +
        "Для подтверждения введи имя сервера:\n" + name
      );
      if (typed === null) return;
      if (typed.trim() !== name) {
        this.flash("Имя не совпало — ребут отменён", true);
        return;
      }
      const r = await fetch("/api/servers/" + this.selected.id + "/reboot", {
        method: "POST",
        headers: {"content-type":"application/json"},
        body: JSON.stringify({ delay_seconds: 5 }),
      });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.flash(j.detail || ("Ошибка " + r.status), true);
        return;
      }
      this.rebootStatus = "Ребут запущен — жду первый /health с ноды…";
      this.flash("Перезагрузка запланирована — слежу за возвращением сервера");
      this._pollReboot(this.selected.id);
    },

    // Poll the node's health endpoint after a reboot. Moves through states
    // (scheduled → offline → online) and flashes once the node is back.
    // Times out after ~5 min — if the node doesn't come back by then the
    // user almost certainly needs the hosting provider's console.
    async _pollReboot(serverId) {
      const started = Date.now();
      const deadline = started + 5 * 60_000;   // 5 minutes
      let sawOffline = false;
      while (Date.now() < deadline) {
        await new Promise(res => setTimeout(res, 8000));
        if (!this.selected || this.selected.id !== serverId) {
          // user navigated away; stop polling silently
          this.rebootStatus = "";
          return;
        }
        try {
          const r = await fetch("/api/servers/" + serverId);
          if (!r.ok) throw new Error("status " + r.status);
          const s = await r.json();
          const secs = Math.floor((Date.now() - started) / 1000);
          if (!s.online) {
            sawOffline = true;
            this.rebootStatus = `Сервер оффлайн (${secs}с) — ждём возвращения…`;
          } else if (!sawOffline) {
            // Might still be pre-reboot — keep waiting for at least one
            // offline reading before declaring success.
            this.rebootStatus = `Всё ещё отвечает (${secs}с) — жду старт ребута…`;
          } else {
            this.rebootStatus = "";
            this.selected = { ...this.selected, ...s };
            await this.loadServers();
            await this.refreshStats();
            this.flash("Сервер вернулся онлайн после ребута");
            return;
          }
        } catch (_) {
          // /api/servers/{id} itself failed — probably panel hiccup, keep polling
          sawOffline = true;
          const secs = Math.floor((Date.now() - started) / 1000);
          this.rebootStatus = `Нет ответа от панели/ноды (${secs}с)…`;
        }
      }
      this.rebootStatus = "";
      this.flash("Сервер не поднялся за 5 минут — открой консоль у хостера", true);
    },

    async resyncConfig() {
      if (!this.selected) return;
      const r = await fetch("/api/servers/" + this.selected.id + "/resync", { method: "POST" });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.flash(j.detail || "Ошибка " + r.status, true);
        return;
      }
      this.flash("Конфиг пересобран и запушен на " + this.selected.name);
      await this.refreshStats();
    },

    async runNodeSpeedtest(serverId = null) {
      const id = Number(serverId || this.selected?.id || 0);
      if (!id || this.speedtestBusy) return;
      this.speedtestBusy = true;
      try {
        const r = await fetch("/api/servers/" + id + "/speedtest", { method: "POST" });
        const data = await r.json().catch(() => ({}));
        if (!r.ok || data.error) {
          this.flash(data.detail || data.error || ("Ошибка " + r.status), true);
          return;
        }
        this.flash(
          "Speedtest: ↓ " + Number(data.download_mbps || 0).toFixed(1)
          + " / ↑ " + Number(data.upload_mbps || 0).toFixed(1) + " Мбит/с",
        );
        await this.loadServers();
        await this.refreshLive();
        if (this.selected && this.selected.id === id) {
          const sr = await fetch("/api/servers/" + id);
          if (sr.ok) this.selected = { ...this.selected, ...(await sr.json()) };
        }
        if (this.view === "statistics") await this.loadStatistics();
      } finally {
        this.speedtestBusy = false;
      }
    },

    async rotateKeys() {
      if (!this.selected) return;
      if (!confirm("Сгенерировать новые Reality-ключи для " + this.selected.name + "?\nСтарые vless://-ссылки перестанут работать — клиентам нужно будет переимпортировать новые.")) return;
      const r = await fetch("/api/servers/" + this.selected.id + "/rotate-keys", { method: "POST" });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.flash(j.detail || "Ошибка " + r.status, true);
        return;
      }
      const s = await r.json();
      this.selected = { ...this.selected, public_key: s.public_key, short_id: s.short_id };
      await this.refreshStats();
      this.flash("Ключи обновлены");
    },

    async addClient() {
      if (!this.selected) return;
      this.addClientErr = "";
      const gib = Number(this.newClient.data_limit_gib || 0);
      const days = Number(this.newClient.expires_in_days || 0);
      // Per-client SNI: dropdown carries either an existing SNI from
      // selected.snis, the empty string ("inherit server default"), or
      // the sentinel "__custom__" — in the last case, take the value
      // from the "Свой SNI…" text input.
      let sni = null;
      const choice = (this.newClient.sni_choice || "").trim();
      if (choice === "__custom__") {
        const custom = (this.newClient.sni_custom || "").trim().toLowerCase();
        if (!custom) {
          this.addClientErr = "Укажи свой SNI или выбери из списка";
          return;
        }
        sni = custom;
      } else if (choice) {
        sni = choice;
      }
      const payload = {
        email: this.newClient.email,
        label: this.newClient.label || null,
        sni: sni,
        data_limit_bytes: gib > 0 ? Math.round(gib * 1073741824) : null,
        expires_at: days > 0
          ? new Date(Date.now() + days * 86400000).toISOString()
          : null,
      };
      const r = await fetch("/api/servers/" + this.selected.id + "/clients", {
        method: "POST",
        headers: {"content-type":"application/json"},
        body: JSON.stringify(payload),
      });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.addClientErr = j.detail || ("Ошибка " + r.status);
        return;
      }
      // Server may have grown a new SNI in extra_snis as a side
      // effect of this create call — reload the server so the
      // dropdown reflects it next time.
      const created = await r.json().catch(() => null);
      if (created && created.server_id) {
        const sr = await fetch("/api/servers/" + created.server_id);
        if (sr.ok) {
          const s = await sr.json();
          this.selected = { ...this.selected, ...s };
        }
      }
      this.openAddClient = false;
      this.newClient = { email: "", label: "", data_limit_gib: 0, expires_in_days: 0,
                         sni_choice: "", sni_custom: "" };
      await this.loadClientPage(1);
      await this.loadServers();
    },

    async deleteClient(c) {
      if (!confirm("Удалить ключ " + c.email + "?")) return;
      await fetch("/api/servers/" + this.selected.id + "/clients/" + c.id, { method: "DELETE" });
      await this.loadClientPage(this.clientPage);
      await this.loadServers();
    },

    async toggleClient(c) {
      const r = await fetch(
        "/api/servers/" + this.selected.id + "/clients/" + c.id,
        {
          method: "PATCH",
          headers: {"content-type":"application/json"},
          body: JSON.stringify({ enabled: !c.enabled }),
        },
      );
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.flash(j.detail || ("Ошибка " + r.status), true);
        return;
      }
      this.flash(c.enabled ? "Ключ отключён" : "Ключ включён");
      await this.loadClientPage(this.clientPage);
    },

    async addServerSni() {
      if (!this.selected) return;
      const input = window.prompt(
        "Новый SNI для ноды (хост вида ya.ru, mail.ru, vk.com)\n" +
        "Сразу попадёт в xray serverNames + станет доступен в дропдауне нового ключа.",
        ""
      );
      if (input === null) return;
      const v = input.trim().toLowerCase();
      if (!v) return;
      const r = await fetch("/api/servers/" + this.selected.id + "/snis", {
        method: "POST",
        headers: {"content-type":"application/json"},
        body: JSON.stringify({ sni: v }),
      });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.flash(j.detail || ("Ошибка " + r.status), true);
        return;
      }
      const s = await r.json();
      this.selected = { ...this.selected, ...s };
      this.flash("SNI добавлен");
    },

    async removeServerSni(sni) {
      if (!this.selected) return;
      if (!confirm("Убрать SNI " + sni + " из списка ноды?")) return;
      const r = await fetch(
        "/api/servers/" + this.selected.id + "/snis/" + encodeURIComponent(sni),
        { method: "DELETE" },
      );
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.flash(j.detail || ("Ошибка " + r.status), true);
        return;
      }
      const s = await r.json();
      this.selected = { ...this.selected, ...s };
      this.flash("SNI удалён");
    },

    async changeClientSni(c) {
      // Show the user the available list (server's known SNIs) and a
      // free-text fallback. Empty input clears the pin (revert to
      // server default). New SNIs auto-extend the server's
      // ``serverNames`` and trigger a config push on the agent.
      if (!this.selected) return;
      const existing = (this.selected.snis || []).join(", ");
      const help = existing
        ? "Доступные SNI на ноде: " + existing + "\n(пусто = по умолчанию " + this.selected.sni + ")"
        : "Введи SNI (пусто = по умолчанию " + this.selected.sni + ")";
      const input = window.prompt(help, c.sni_pinned ? c.sni : "");
      if (input === null) return; // user cancelled
      const r = await fetch(
        "/api/servers/" + this.selected.id + "/clients/" + c.id,
        {
          method: "PATCH",
          headers: {"content-type":"application/json"},
          body: JSON.stringify({ sni: input.trim() }),
        },
      );
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.flash(j.detail || ("Ошибка " + r.status), true);
        return;
      }
      // Re-pull the server so the dropdown/badge see any new SNI
      // that just got auto-registered.
      const sr = await fetch("/api/servers/" + this.selected.id);
      if (sr.ok) {
        const s = await sr.json();
        this.selected = { ...this.selected, ...s };
      }
      this.flash(input.trim() ? "SNI ключа обновлён" : "SNI сброшен на дефолтный");
      await this.loadClientPage(this.clientPage);
    },

    async resetClientUsage(c) {
      if (!confirm("Сбросить счётчик трафика для " + c.email + "?")) return;
      const r = await fetch(
        "/api/servers/" + this.selected.id + "/clients/" + c.id + "/reset-usage",
        { method: "POST" },
      );
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.flash(j.detail || ("Ошибка " + r.status), true);
        return;
      }
      this.flash("Счётчик сброшен");
      await this.loadClientPage(this.clientPage);
    },

    openEditClient(c) {
      this.editingClient = c;
      this.editClient.data_limit_gib = c.data_limit_bytes
        ? +(c.data_limit_bytes / 1073741824).toFixed(3)
        : 0;
      this.editClient.expires_at_str = c.expires_at
        ? this._toDatetimeLocal(c.expires_at)
        : "";
      this.editClientErr = "";
    },

    extendClientExpiry(days) {
      // Add `days` to the current expiry (or now, if none set).
      const base = this.editClient.expires_at_str
        ? new Date(this.editClient.expires_at_str)
        : new Date();
      const next = new Date(base.getTime() + days * 86400000);
      this.editClient.expires_at_str = this._toDatetimeLocal(next.toISOString());
    },

    async saveClientLimits() {
      if (!this.editingClient) return;
      const gib = Number(this.editClient.data_limit_gib || 0);
      const payload = {
        data_limit_bytes: gib > 0 ? Math.round(gib * 1073741824) : null,
        expires_at: this.editClient.expires_at_str
          ? new Date(this.editClient.expires_at_str).toISOString()
          : null,
      };
      const r = await fetch(
        "/api/servers/" + this.selected.id
          + "/clients/" + this.editingClient.id,
        {
          method: "PATCH",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(payload),
        },
      );
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.editClientErr = j.detail || ("Ошибка " + r.status);
        return;
      }
      this.editingClient = null;
      this.flash("Лимиты сохранены");
      await this.loadClientPage(this.clientPage);
    },

    _toDatetimeLocal(iso) {
      // <input type="datetime-local"> wants "YYYY-MM-DDTHH:MM" in LOCAL time.
      if (!iso) return "";
      const d = new Date(iso);
      if (Number.isNaN(d.getTime())) return "";
      const pad = (n) => String(n).padStart(2, "0");
      return d.getFullYear() + "-" + pad(d.getMonth()+1) + "-" + pad(d.getDate())
           + "T" + pad(d.getHours()) + ":" + pad(d.getMinutes());
    },

    // ---------- api tokens ----------
    async loadTokens() {
      const r = await fetch("/api/tokens");
      if (!r.ok) return;
      this.tokens = await r.json();
    },

    async addToken() {
      this.addTokenErr = "";
      const r = await fetch("/api/tokens", {
        method: "POST",
        headers: {"content-type":"application/json"},
        body: JSON.stringify({ name: this.newToken.name }),
      });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.addTokenErr = j.detail || ("Ошибка " + r.status);
        return;
      }
      this.createdToken = await r.json();
      this.newToken.name = "";
      await this.loadTokens();
    },

    async deleteToken(t) {
      if (!confirm("Удалить токен «" + t.name + "»? Все боты/скрипты, использующие его, перестанут работать.")) return;
      await fetch("/api/tokens/" + t.id, { method: "DELETE" });
      await this.loadTokens();
    },

    // ---------- tg bots ----------
    async loadBots() {
      const r = await fetch("/api/bots");
      if (!r.ok) return;
      this.bots = await r.json();
    },
    startBotsPoll() {
      this.stopBotsPoll();
      // Light poll so the "running" indicator flips to green after the
      // reconcile loop picks up a freshly created bot.
      this.botsPollTimer = setInterval(() => { if (this.view === "bots") this.loadBots(); }, 5000);
    },
    stopBotsPoll() {
      if (this.botsPollTimer) { clearInterval(this.botsPollTimer); this.botsPollTimer = null; }
    },
    openBotEditor(b) {
      this.botFormErr = "";
      if (b) {
        this.botForm = {
          id: b.id, name: b.name, bot_token: "",
          owner_chat_id: b.owner_chat_id, welcome_text: b.welcome_text,
          default_server_id: b.default_server_id,
          server_ids: Array.isArray(b.server_ids) ? [...b.server_ids] : [],
          default_days: b.default_days,
          default_data_limit_bytes: b.default_data_limit_bytes,
          device_limit: b.device_limit, enabled: b.enabled,
          profile_title: b.profile_title || "",
          support_url: b.support_url || "",
          announce: b.announce || "",
          provider_id: b.provider_id || "",
          routing: b.routing || "",
          update_interval_hours: b.update_interval_hours || 24,
          subscription_domain: b.subscription_domain || "",
          brand_name: b.brand_name || "",
          logo_url: b.logo_url || "",
          page_subtitle: b.page_subtitle || "",
          page_help_text: b.page_help_text || "",
          page_buy_url: b.page_buy_url || "",
          referral_mode: b.referral_mode || "off",
          referral_levels: b.referral_levels || 1,
          referral_l1_days: b.referral_l1_days || 0,
          referral_l2_days: b.referral_l2_days || 0,
          referral_l3_days: b.referral_l3_days || 0,
          referral_l1_percent: b.referral_l1_percent || 0,
          referral_l2_percent: b.referral_l2_percent || 0,
          referral_l3_percent: b.referral_l3_percent || 0,
          referral_payout_url: b.referral_payout_url || "",
        };
        this.loadBotPlans(b.id);
        this.loadBotServerOverrides(b.id);
      } else {
        this.botForm = {
          id: null, name: "", bot_token: "", owner_chat_id: "", welcome_text: "",
          default_server_id: null, server_ids: [], default_days: 30,
          default_data_limit_bytes: 0, device_limit: 3, enabled: true,
          profile_title: "", support_url: "", announce: "",
          provider_id: "", routing: "", update_interval_hours: 24,
          subscription_domain: "", brand_name: "", logo_url: "",
          page_subtitle: "", page_help_text: "", page_buy_url: "",
          referral_mode: "off", referral_levels: 1,
          referral_l1_days: 0, referral_l2_days: 0, referral_l3_days: 0,
          referral_l1_percent: 0, referral_l2_percent: 0, referral_l3_percent: 0,
          referral_payout_url: "",
        };
        this.botPlans = [];
        this.botServerOverrides = {};
      }
      this.openBotForm = true;
    },
    async saveBot() {
      this.botFormErr = "";
      const payload = {
        name: this.botForm.name,
        owner_chat_id: String(this.botForm.owner_chat_id || ""),
        welcome_text: this.botForm.welcome_text || "",
        default_server_id: this.botForm.default_server_id || null,
        server_ids: (this.botForm.server_ids || []).map(Number),
        default_days: Number(this.botForm.default_days) || 0,
        default_data_limit_bytes: Number(this.botForm.default_data_limit_bytes) || 0,
        device_limit: Number(this.botForm.device_limit) || 0,
        enabled: !!this.botForm.enabled,
        profile_title: this.botForm.profile_title || "",
        support_url: this.botForm.support_url || "",
        announce: this.botForm.announce || "",
        provider_id: this.botForm.provider_id || "",
        routing: this.botForm.routing || "",
        update_interval_hours: Number(this.botForm.update_interval_hours || 24),
        subscription_domain: this.botForm.subscription_domain || "",
        brand_name: this.botForm.brand_name || "",
        logo_url: this.botForm.logo_url || "",
        page_subtitle: this.botForm.page_subtitle || "",
        page_help_text: this.botForm.page_help_text || "",
        page_buy_url: this.botForm.page_buy_url || "",
        referral_mode: this.botForm.referral_mode || "off",
        referral_levels: Math.max(1, Math.min(3, Number(this.botForm.referral_levels) || 1)),
        referral_l1_days: Number(this.botForm.referral_l1_days) || 0,
        referral_l2_days: Number(this.botForm.referral_l2_days) || 0,
        referral_l3_days: Number(this.botForm.referral_l3_days) || 0,
        referral_l1_percent: Math.max(0, Math.min(100, Number(this.botForm.referral_l1_percent) || 0)),
        referral_l2_percent: Math.max(0, Math.min(100, Number(this.botForm.referral_l2_percent) || 0)),
        referral_l3_percent: Math.max(0, Math.min(100, Number(this.botForm.referral_l3_percent) || 0)),
        referral_payout_url: this.botForm.referral_payout_url || "",
      };
      if (this.botForm.bot_token) payload.bot_token = this.botForm.bot_token.trim();
      let r;
      if (this.botForm.id) {
        r = await fetch("/api/bots/" + this.botForm.id, {
          method: "PATCH",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(payload),
        });
      } else {
        if (!payload.bot_token) { this.botFormErr = "Укажи bot_token"; return; }
        r = await fetch("/api/bots", {
          method: "POST",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(payload),
        });
      }
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.botFormErr = j.detail || ("Ошибка " + r.status);
        return;
      }
      this.openBotForm = false;
      await this.loadBots();
    },
    toggleBotServer(sid, checked) {
      sid = Number(sid);
      const cur = new Set((this.botForm.server_ids || []).map(Number));
      if (checked) cur.add(sid); else cur.delete(sid);
      this.botForm.server_ids = Array.from(cur);
    },
    async toggleBot(b) {
      const r = await fetch("/api/bots/" + b.id, {
        method: "PATCH",
        headers: {"content-type":"application/json"},
        body: JSON.stringify({ enabled: !b.enabled }),
      });
      if (!r.ok) { this.showToast("Не удалось переключить бота", true); return; }
      await this.loadBots();
    },
    async deleteBot(b) {
      if (!confirm("Удалить бота «" + b.name + "»? Его пользователи останутся в БД, но ключи перестанут обновляться.")) return;
      await fetch("/api/bots/" + b.id, { method: "DELETE" });
      await this.loadBots();
    },
    // ---- per-bot plans ----
    async loadBotPlans(botId) {
      const r = await fetch("/api/bots/" + botId + "/plans");
      this.botPlans = r.ok ? await r.json() : [];
    },
    addBotPlan() {
      this.botPlans.push({
        id: null, bot_id: this.botForm.id,
        name: "30 дней", duration_days: 30,
        data_limit_bytes: 0,
        price_stars: 0, price_crypto_usdt_cents: 0, price_rub_kopecks: 0,
        enabled: true, sort_order: this.botPlans.length,
      });
    },
    async saveBotPlan(p) {
      const payload = {
        name: p.name || "30 дней",
        duration_days: Number(p.duration_days) || 30,
        data_limit_bytes: Number(p.data_limit_bytes) || 0,
        price_stars: Number(p.price_stars) || 0,
        price_crypto_usdt_cents: Number(p.price_crypto_usdt_cents) || 0,
        price_rub_kopecks: Number(p.price_rub_kopecks) || 0,
        enabled: !!p.enabled,
        sort_order: Number(p.sort_order) || 0,
      };
      let r;
      if (p.id) {
        r = await fetch("/api/bots/" + this.botForm.id + "/plans/" + p.id, {
          method: "PATCH",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(payload),
        });
      } else {
        r = await fetch("/api/bots/" + this.botForm.id + "/plans", {
          method: "POST",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(payload),
        });
      }
      if (!r.ok) { this.showToast("Не удалось сохранить тариф", true); return; }
      await this.loadBotPlans(this.botForm.id);
      this.showToast("Тариф сохранён");
    },
    async deleteBotPlan(p) {
      if (!p.id) {
        this.botPlans = this.botPlans.filter(x => x !== p);
        return;
      }
      if (!confirm("Удалить тариф «" + p.name + "»?")) return;
      const r = await fetch("/api/bots/" + this.botForm.id + "/plans/" + p.id, { method: "DELETE" });
      if (!r.ok) { this.showToast("Не удалось удалить тариф", true); return; }
      await this.loadBotPlans(this.botForm.id);
    },
    // ---- per-bot server name overrides ----
    async loadBotServerOverrides(botId) {
      const r = await fetch("/api/bots/" + botId + "/server-overrides");
      const map = {};
      if (r.ok) {
        const rows = await r.json();
        for (const row of rows) map[row.server_id] = row.display_name || "";
      }
      this.botServerOverrides = map;
    },
    async saveBotServerOverrides() {
      const payload = [];
      for (const sid in this.botServerOverrides) {
        const name = (this.botServerOverrides[sid] || "").trim();
        if (!name) continue;
        payload.push({ server_id: Number(sid), display_name: name });
      }
      const r = await fetch("/api/bots/" + this.botForm.id + "/server-overrides", {
        method: "PUT",
        headers: {"content-type":"application/json"},
        body: JSON.stringify(payload),
      });
      if (!r.ok) { this.showToast("Не удалось сохранить названия", true); return; }
      this.showToast("Названия серверов сохранены");
    },
    // ---- panel-wide settings (subscription_url_base / public_url) ----
    async loadPanelSettings() {
      const r = await fetch("/api/panel-settings");
      if (!r.ok) return;
      this.panelSettings = await r.json();
      this.loadDomainBackend();
    },
    async loadDomainBackend() {
      try {
        const r = await fetch("/api/domain/backend");
        if (!r.ok) return;
        const j = await r.json();
        this.domainBackend = j.backend || "";
      } catch (_) {}
    },
    async _provisionDomain(domain) {
      if (!domain) return;
      this.domainBusy = true;
      this.domainResult = "";
      try {
        const r = await fetch("/api/domain/provision", {
          method: "POST",
          headers: {"content-type":"application/json"},
          body: JSON.stringify({ domain }),
        });
        const j = await r.json().catch(() => ({}));
        this.domainResult = j.message || (r.ok ? "OK" : ("Ошибка " + r.status));
        this.domainResultOk = !!j.ok;
        if (j.backend) this.domainBackend = j.backend;
      } catch (e) {
        this.domainResult = "Сеть/сервер недоступны: " + e;
        this.domainResultOk = false;
      } finally {
        this.domainBusy = false;
      }
    },
    async provisionGlobalDomain() {
      await this._provisionDomain((this.panelSettings.subscription_url_base || "").trim());
    },
    async provisionBotDomain() {
      await this._provisionDomain((this.botForm.subscription_domain || "").trim());
    },
    async savePanelSettings() {
      const r = await fetch("/api/panel-settings", {
        method: "PATCH",
        headers: {"content-type":"application/json"},
        body: JSON.stringify({
          subscription_url_base: (this.panelSettings.subscription_url_base || "").trim(),
          public_url: (this.panelSettings.public_url || "").trim(),
        }),
      });
      if (!r.ok) { this.showToast("Не удалось сохранить", true); return; }
      this.panelSettings = await r.json();
      this.showToast("Сохранено");
    },
    // ---- panel-wide auto-balance / probe knobs ----
    // Lazy-load on first open of the dashboard panel «⚡🛡 Авто-балансировка»;
    // GET is cheap (single row) but we cache so toggling the panel doesn't
    // re-fetch on every Alpine render.
    async loadLbSettings(force) {
      if (this.lbSettingsLoaded && !force) return;
      this.lbSettingsErr = "";
      try {
        const r = await fetch("/api/load-balancer/settings");
        if (!r.ok) {
          const j = await r.json().catch(() => ({}));
          this.lbSettingsErr = j.detail || ("HTTP " + r.status);
          return;
        }
        this.lbSettings = await r.json();
        this.lbSettingsLoaded = true;
      } catch (e) {
        this.lbSettingsErr = "сеть недоступна";
      }
    },
    // PATCH /api/load-balancer/settings. The backend validates the URL,
    // clamps the interval to [5, 600] seconds and the tolerance to
    // [0, 5000] ms, so we just forward the form values.
    async saveLbSettings() {
      this.lbSettingsBusy = true;
      this.lbSettingsErr = "";
      this.lbSettingsMsg = "";
      try {
        const body = {
          probe_url: (this.lbSettings.probe_url || "").trim(),
          probe_interval_seconds: Number(this.lbSettings.probe_interval_seconds) || 30,
          tolerance_ms: Number(this.lbSettings.tolerance_ms) || 0,
        };
        const r = await fetch("/api/load-balancer/settings", {
          method: "PATCH",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(body),
        });
        if (!r.ok) {
          const j = await r.json().catch(() => ({}));
          this.lbSettingsErr = j.detail || ("Ошибка " + r.status);
          return;
        }
        this.lbSettings = await r.json();
        this.lbSettingsLoaded = true;
        this.lbSettingsMsg = "Сохранено — клиенты увидят новые параметры при следующем обновлении подписки.";
      } catch (e) {
        this.lbSettingsErr = "сеть недоступна";
      } finally {
        this.lbSettingsBusy = false;
      }
    },
    async openBotUsers(b) {
      this.botUsersBot = b;
      this.openBotUsersModal = true;
      const r = await fetch("/api/bots/" + b.id + "/users");
      this.botUsers = r.ok ? await r.json() : [];
    },
    async toggleBotUserBan(u) {
      const r = await fetch("/api/bots/" + u.bot_id + "/users/" + u.id + "/ban", {
        method: "POST",
        headers: {"content-type":"application/json"},
        body: JSON.stringify({ banned: !u.banned }),
      });
      if (!r.ok) { this.showToast("Не удалось изменить бан", true); return; }
      if (this.botUsersBot) await this.openBotUsers(this.botUsersBot);
      await this.loadBots();
    },

    // ---------- payments ----------
    async loadPayments() {
      await Promise.all([
        this.loadPlans(),
        this.loadPaymentSettings(),
        this.loadOrders(),
      ]);
    },
    async loadPlans() {
      const r = await fetch("/api/plans");
      if (!r.ok) return;
      this.plans = await r.json();
    },
    async loadPaymentSettings() {
      const r = await fetch("/api/payment-settings");
      if (!r.ok) return;
      this.paymentSettings = await r.json();
    },
    async loadOrders() {
      const r = await fetch("/api/orders?limit=100");
      if (!r.ok) return;
      this.orders = await r.json();
    },
    async savePaymentSettings(patch) {
      // For secret-like fields an empty string means "user left the
      // input blank; don't overwrite" — skip them. Booleans and
      // non-secret strings (merchant_id) go through as-is.
      const secretFields = new Set([
        "cryptobot_token",
        "freekassa_secret1",
        "freekassa_secret2",
      ]);
      const body = {};
      for (const [k, v] of Object.entries(patch || {})) {
        if (v === undefined) continue;
        if (secretFields.has(k) && (v === "" || v === null)) continue;
        body[k] = v;
      }
      if (Object.keys(body).length === 0) return;
      const r = await fetch("/api/payment-settings", {
        method: "PATCH",
        headers: {"content-type":"application/json"},
        body: JSON.stringify(body),
      });
      if (!r.ok) { this.showToast("Не удалось сохранить настройки", true); return; }
      this.paymentSettings = await r.json();
    },
    openPlanEditor(p) {
      if (p) {
        this.planEdit = {
          id: p.id, name: p.name, duration_days: p.duration_days,
          enabled: !!p.enabled, sort_order: p.sort_order || 0,
          data_limit_bytes: p.data_limit_bytes || 0,
          price_stars: p.price_stars || 0,
          price_crypto_usdt_cents: p.price_crypto_usdt_cents || 0,
          price_rub_kopecks: p.price_rub_kopecks || 0,
          _data_limit_gb: (p.data_limit_bytes || 0) / (1024 ** 3),
          _price_crypto_usdt: (p.price_crypto_usdt_cents || 0) / 100,
          _price_rub: (p.price_rub_kopecks || 0) / 100,
        };
      } else {
        this.planEdit = {
          id: null, name: "", duration_days: 30, enabled: true,
          sort_order: (this.plans.length || 0) * 10,
          data_limit_bytes: 0,
          price_stars: 0, price_crypto_usdt_cents: 0, price_rub_kopecks: 0,
          _data_limit_gb: 0, _price_crypto_usdt: 0, _price_rub: 0,
        };
      }
      this.openPlan = true;
    },
    async savePlan() {
      const p = this.planEdit;
      const payload = {
        name: (p.name || "").trim(),
        duration_days: Math.max(1, Math.round(p.duration_days || 0)),
        enabled: !!p.enabled,
        sort_order: Math.max(0, Math.round(p.sort_order || 0)),
        data_limit_bytes: Math.max(0, Math.round((p._data_limit_gb || 0) * (1024 ** 3))),
        price_stars: Math.max(0, Math.round(p.price_stars || 0)),
        price_crypto_usdt_cents: Math.max(0, Math.round((p._price_crypto_usdt || 0) * 100)),
        price_rub_kopecks: Math.max(0, Math.round((p._price_rub || 0) * 100)),
      };
      if (!payload.name) { this.showToast("Нужно название", true); return; }
      let r;
      if (p.id) {
        r = await fetch("/api/plans/" + p.id, {
          method: "PATCH",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(payload),
        });
      } else {
        r = await fetch("/api/plans", {
          method: "POST",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(payload),
        });
      }
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.showToast(j.detail || ("Ошибка " + r.status), true);
        return;
      }
      this.openPlan = false;
      await this.loadPlans();
    },
    async togglePlan(p) {
      const r = await fetch("/api/plans/" + p.id, {
        method: "PATCH",
        headers: {"content-type":"application/json"},
        body: JSON.stringify({ enabled: !p.enabled }),
      });
      if (!r.ok) { this.showToast("Не удалось переключить тариф", true); return; }
      await this.loadPlans();
    },
    async deletePlan(p) {
      if (!confirm("Удалить тариф «" + p.name + "»? Существующие заказы сохранятся.")) return;
      const r = await fetch("/api/plans/" + p.id, { method: "DELETE" });
      if (!r.ok) { this.showToast("Ошибка удаления", true); return; }
      await this.loadPlans();
    },
    orderAmountLabel(o) {
      if (!o) return "";
      if (o.currency === "XTR") return o.amount + " ⭐";
      if (o.currency === "USDT") return (o.amount / 100).toFixed(2) + " USDT";
      if (o.currency === "RUB") return (o.amount / 100).toFixed(0) + " ₽";
      return String(o.amount);
    },
    publicUrlGuess() {
      return window.location.origin || "";
    },

    // ---------- enrollment ----------
    async createEnrollment() {
      this.enrollBusy = true; this.enrollErr = "";
      try {
        const r = await fetch("/api/enrollments", {
          method: "POST",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(this.newEnroll),
        });
        if (!r.ok) {
          const j = await r.json().catch(()=>({}));
          this.enrollErr = j.detail || ("Ошибка " + r.status);
          return;
        }
        this.enrollCreated = await r.json();
        // Reset to defaults; the «⚡», «🎯», «🛡» and «🇷🇺→🌍»
        // buttons set them again through openEnrollFor when the user
        // reopens the wizard.
        this.newEnroll = { name: "", display_name: "", in_pool: false,
                           pool_tier: "",
                           mode: "standalone",
                           upstream_server_id: null,
                           public_host: "", port: 443, sni: "rutube.ru",
                           dest: "rutube.ru:443", agent_port: 8765 };
        await this.loadEnrollments();
      } finally { this.enrollBusy = false; }
    },

    async deleteEnrollment(id) {
      if (!confirm("Удалить enrollment? Установочная команда перестанет работать.")) return;
      await fetch("/api/enrollments/" + id, { method: "DELETE" });
      await this.loadEnrollments();
    },

    // ---------- subscriptions ----------
    async createSubscription() {
      this.subBusy = true; this.subErr = "";
      try {
        const r = await fetch("/api/subscriptions", {
          method: "POST",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(this.newSub),
        });
        if (!r.ok) {
          const j = await r.json().catch(()=>({}));
          this.subErr = j.detail || ("Ошибка " + r.status);
          return;
        }
        this.openAddSub = false;
        this.newSub = { name: "", include_all: true, client_ids: [] };
        await this.loadSubscriptions();
      } finally { this.subBusy = false; }
    },

    async openEditSub(s) {
      this.editingSub = {
        ...s,
        client_ids: [...(s.client_ids || [])],
        profile_title: s.profile_title || "",
        support_url: s.support_url || "",
        announce: s.announce || "",
        provider_id: s.provider_id || "",
        routing: s.routing || "",
        update_interval_hours: s.update_interval_hours || 24,
      };
      await this.loadSubscriptions();
      if (!this.servers.length) await this.loadServers();
      await this.loadAllClientsForSub();
    },

    async saveSub() {
      if (!this.editingSub) return;
      const body = {
        name: this.editingSub.name,
        include_all: !!this.editingSub.include_all,
        client_ids: this.editingSub.client_ids,
        profile_title: this.editingSub.profile_title || "",
        support_url: this.editingSub.support_url || "",
        announce: this.editingSub.announce || "",
        provider_id: this.editingSub.provider_id || "",
        routing: this.editingSub.routing || "",
        update_interval_hours: Number(this.editingSub.update_interval_hours || 24),
      };
      const r = await fetch("/api/subscriptions/" + this.editingSub.id, {
        method: "PATCH",
        headers: {"content-type":"application/json"},
        body: JSON.stringify(body),
      });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.flash(j.detail || "Ошибка " + r.status, true);
        return;
      }
      this.editingSub = null;
      await this.loadSubscriptions();
      this.flash("Подписка обновлена");
    },

    toggleSubClient(id) {
      if (!this.editingSub) return;
      const arr = this.editingSub.client_ids;
      const i = arr.indexOf(id);
      if (i === -1) arr.push(id); else arr.splice(i, 1);
    },

    async deleteSub(id) {
      if (!confirm("Удалить подписку? URL станет недействительным.")) return;
      await fetch("/api/subscriptions/" + id, { method: "DELETE" });
      await this.loadSubscriptions();
    },

    // ---------- clipboard / feedback ----------
    showLink(c) { this.linkFor = c; },
    copyText(text) {
      if (!text) { this.flash("Нечего копировать", true); return; }
      const ok = (s) => {
        this.flash(s ? "Скопировано" : "Не удалось скопировать — выделите и нажмите Ctrl+C", !s);
      };
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(text).then(() => ok(true), () => this.copyFallback(text, ok));
        return;
      }
      this.copyFallback(text, ok);
    },
    copyFallback(text, ok) {
      try {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.position = "fixed";
        ta.style.top = "-9999px";
        ta.style.opacity = "0";
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        ta.setSelectionRange(0, text.length);
        const done = document.execCommand("copy");
        document.body.removeChild(ta);
        ok(done);
      } catch (_) { ok(false); }
    },
    copyLink() {
      if (!this.linkFor) return;
      this.copyText(this.linkFor.vless_link);
    },
    flash(msg, isErr) {
      this.toast = msg; this.toastErr = !!isErr;
      clearTimeout(this.toastTimer);
      this.toastTimer = setTimeout(() => { this.toast = ""; }, 2500);
    },

    async logout() {
      await fetch("/api/auth/logout", { method: "POST" });
      window.location.href = "/ui/login";
    },

    async changePassword() {
      this.pw.msg = "";
      const r = await fetch("/api/auth/password", {
        method: "POST",
        headers: {"content-type":"application/json"},
        body: JSON.stringify({ current_password: this.pw.current, new_password: this.pw.next }),
      });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.pw.msg = j.detail || ("Ошибка " + r.status); this.pw.ok = false;
      } else {
        this.pw.msg = "Пароль обновлён."; this.pw.ok = true;
        this.pw.current = this.pw.next = "";
      }
    },

    // ---------- fmt helpers ----------
    fmtBytes(n) {
      n = Number(n || 0);
      if (n < 1024) return n + " B";
      const u = ["KB","MB","GB","TB","PB"];
      let i = -1; do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
      return n.toFixed(1) + " " + u[i];
    },
    fmtBps(bps) {
      // Format bytes-per-second as a human-readable speed string.
      // bps = 0 shows "—" to avoid cluttering the UI with "0 B/s".
      bps = Number(bps || 0);
      if (bps <= 0) return "—";
      return this.fmtBytes(bps) + "/s";
    },
    fmtBpsCompact(bps) {
      // Compact speed for tight UI slots: e.g. "12.3 M/s", "1.5 G/s".
      bps = Number(bps || 0);
      if (bps <= 0) return "—";
      const u = ["B","KB","MB","GB","TB"];
      let i = -1; do { bps /= 1024; i++; } while (bps >= 1024 && i < u.length - 1);
      return bps.toFixed(1) + " " + u[i] + "/s";
    },
    fmtUptime(s) {
      s = Number(s || 0);
      const d = Math.floor(s / 86400); s %= 86400;
      const h = Math.floor(s / 3600); s %= 3600;
      const m = Math.floor(s / 60);
      if (d) return d + "д " + h + "ч";
      if (h) return h + "ч " + m + "м";
      return m + "м";
    },
    fmtDate(s) {
      if (!s) return "";
      try { return new Date(s).toLocaleString("ru-RU"); } catch (_) { return String(s); }
    },
    memPct() {
      const t = this.sysinfo?.mem_total || 0;
      const u = this.sysinfo?.mem_used || 0;
      return t ? Math.round(u * 100 / t) : 0;
    },
    diskPct() {
      const t = this.sysinfo?.disk_total || 0;
      const u = this.sysinfo?.disk_used || 0;
      return t ? Math.round(u * 100 / t) : 0;
    },
    swapPct() {
      const t = this.sysinfo?.swap_total || 0;
      const u = this.sysinfo?.swap_used || 0;
      return t ? Math.round(u * 100 / t) : 0;
    },
    quotaPct(c) {
      if (!c || !c.data_limit_bytes) return 0;
      const used = Number(c.total_up || 0) + Number(c.total_down || 0);
      return Math.max(0, Math.min(100, Math.round(used * 100 / c.data_limit_bytes)));
    },

    // ---------- theme ----------
    applyStoredTheme() {
      let t = "dark";
      try { t = localStorage.getItem("xnpanel.theme") || "dark"; } catch (_) {}
      this.theme = t;
      document.documentElement.setAttribute("data-theme", t);
    },
    toggleTheme() {
      this.theme = (this.theme === "dark") ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", this.theme);
      try { localStorage.setItem("xnpanel.theme", this.theme); } catch (_) {}
      // Re-render the sun/moon icon after Alpine swaps the <i> attribute.
      this.$nextTick(() => window.lucide && window.lucide.createIcons());
      if (this.view === "statistics") {
        this.$nextTick(() => this.renderStatisticsCharts());
      }
    },

    // ---------- audit log ----------
    async loadLogs() {
      this.logsOffset = 0;
      const q = new URLSearchParams({
        limit: this.logsLimit, offset: this.logsOffset,
      });
      if (this.logsFilter) q.set("action", this.logsFilter);
      const r = await fetch("/api/logs?" + q.toString());
      if (!r.ok) { this.logs = []; return; }
      this.logs = await r.json();
    },
    async loadMoreLogs() {
      this.logsOffset += this.logsLimit;
      const q = new URLSearchParams({
        limit: this.logsLimit, offset: this.logsOffset,
      });
      if (this.logsFilter) q.set("action", this.logsFilter);
      const r = await fetch("/api/logs?" + q.toString());
      if (!r.ok) return;
      const more = await r.json();
      this.logs = [...this.logs, ...more];
    },

    // ---------- 2FA ----------
    async start2FA() {
      this.totpSetup = { secret: "", uri: "", code: "", msg: "", ok: false };
      const r = await fetch("/api/auth/2fa/setup", { method: "POST" });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.totpSetup.msg = j.detail || "Не удалось начать настройку";
        return;
      }
      const j = await r.json();
      this.totpSetup.secret = j.secret;
      this.totpSetup.uri = j.provisioning_uri;
      this.$nextTick(() => {
        const el = this.$refs.totpQr;
        if (el && window.QRCode) {
          el.innerHTML = "";
          window.QRCode.toCanvas(j.provisioning_uri, { width: 180, margin: 1 }, (err, canvas) => {
            if (!err && canvas) el.appendChild(canvas);
          });
        }
      });
    },
    cancel2FA() {
      this.totpSetup = { secret: "", uri: "", code: "", msg: "", ok: false };
    },
    async finish2FA() {
      this.totpSetup.msg = "";
      const r = await fetch("/api/auth/2fa/enable", {
        method: "POST",
        headers: {"content-type":"application/json"},
        body: JSON.stringify({ secret: this.totpSetup.secret, code: this.totpSetup.code }),
      });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.totpSetup.msg = j.detail || "Неверный код";
        this.totpSetup.ok = false;
        return;
      }
      this.totpSetup.msg = "2FA включена.";
      this.totpSetup.ok = true;
      // Reload `me` so the UI flips to "enabled" card.
      try {
        const m = await fetch("/api/auth/me");
        this.me = await m.json();
      } catch (_) {}
      this.totpSetup.secret = ""; this.totpSetup.code = "";
    },
    async disable2FA() {
      this.totpDisable.msg = "";
      const r = await fetch("/api/auth/2fa/disable", {
        method: "POST",
        headers: {"content-type":"application/json"},
        body: JSON.stringify({ code: this.totpDisable.code }),
      });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.totpDisable.msg = j.detail || "Неверный код";
        this.totpDisable.ok = false;
        return;
      }
      this.totpDisable.msg = "2FA отключена.";
      this.totpDisable.ok = true;
      this.totpDisable.code = "";
      try {
        const m = await fetch("/api/auth/me");
        this.me = await m.json();
      } catch (_) {}
    },

    // ---------- telegram ----------
    async loadTelegram() {
      const r = await fetch("/api/notifications/telegram");
      if (!r.ok) return;
      const j = await r.json();
      this.telegram.bot_token_set = !!j.bot_token_set;
      this.telegram.chat_id = j.chat_id || "";
      this.telegram.bot_token = "";
      this.telegram.msg = "";
    },
    async saveTelegram() {
      this.telegram.msg = "";
      // Empty bot_token with an already-set token means "keep current". We tell
      // the user to retype because the server never returns the plaintext.
      if (!this.telegram.bot_token && this.telegram.bot_token_set) {
        this.telegram.msg = "Впиши bot token ещё раз — текущее значение не возвращается сервером.";
        this.telegram.ok = false;
        return;
      }
      const r = await fetch("/api/notifications/telegram", {
        method: "POST",
        headers: {"content-type":"application/json"},
        body: JSON.stringify({
          bot_token: this.telegram.bot_token || "",
          chat_id: this.telegram.chat_id || "",
        }),
      });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.telegram.msg = j.detail || "Ошибка";
        this.telegram.ok = false;
        return;
      }
      const j = await r.json();
      this.telegram.bot_token_set = !!j.bot_token_set;
      this.telegram.bot_token = "";
      this.telegram.msg = "Сохранено.";
      this.telegram.ok = true;
    },
    async testTelegram() {
      this.telegram.msg = "";
      const r = await fetch("/api/notifications/telegram/test", { method: "POST" });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.telegram.msg = j.detail || "Не отправилось";
        this.telegram.ok = false;
        return;
      }
      this.telegram.msg = "Тест отправлен.";
      this.telegram.ok = true;
    },

    // ---------- bulk client create ----------
    async bulkCreateClients() {
      if (!this.selected) return;
      const b = this.bulkClient;
      b.busy = true; b.err = "";
      try {
        const payload = {
          email_prefix: b.email_prefix.trim(),
          count: Math.max(1, Math.min(500, Number(b.count) || 1)),
          flow: "xtls-rprx-vision",
        };
        if (b.label && b.label.trim()) payload.label = b.label.trim();
        if (Number(b.data_limit_gib) > 0) {
          payload.data_limit_bytes = Math.floor(Number(b.data_limit_gib) * 1024 * 1024 * 1024);
        }
        if (Number(b.expires_in_days) > 0) {
          const exp = new Date(Date.now() + Number(b.expires_in_days) * 86400 * 1000);
          payload.expires_at = exp.toISOString();
        }
        const r = await fetch("/api/servers/" + this.selected.id + "/clients/bulk", {
          method: "POST",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(payload),
        });
        if (!r.ok) {
          const j = await r.json().catch(()=>({}));
          b.err = j.detail || ("Ошибка " + r.status);
          return;
        }
        const created = await r.json();
        this.openBulkClient = false;
        this.flash("Создано ключей: " + created.length);
        await this.loadClientPage(1);
        await this.loadServers();
      } finally { b.busy = false; }
    },
  };
}
