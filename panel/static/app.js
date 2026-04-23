/* xray-panel SPA controller. */

function panel() {
  return {
    view: "dashboard",
    me: null,
    servers: [],
    selected: null,
    sysinfo: null,
    clients: [],
    pollTimer: null,

    openAddServer: false,
    addBusy: false,
    addErr: "",
    newServer: {
      name: "", public_host: "", agent_url: "", agent_token: "",
      port: 443, sni: "rutube.ru", dest: "rutube.ru:443",
    },

    openAddClient: false,
    addClientErr: "",
    newClient: { email: "", label: "" },

    linkFor: null,

    pw: { current: "", next: "", msg: "", ok: false },

    async init() {
      try {
        const r = await fetch("/api/auth/me");
        if (!r.ok) { window.location.href = "/ui/login"; return; }
        this.me = await r.json();
      } catch (_) { window.location.href = "/ui/login"; return; }
      await this.loadServers();
    },

    async loadServers() {
      const r = await fetch("/api/servers");
      if (r.status === 401) { window.location.href = "/ui/login"; return; }
      this.servers = await r.json();
    },

    async selectServer(id) {
      const r = await fetch("/api/servers/" + id);
      if (!r.ok) return;
      this.selected = await r.json();
      await this.refreshStats();
      clearInterval(this.pollTimer);
      this.pollTimer = setInterval(() => this.refreshStats(), 5000);
    },

    async refreshStats() {
      if (!this.selected) return;
      try {
        const r = await fetch("/api/servers/" + this.selected.id + "/stats");
        if (!r.ok) return;
        const data = await r.json();
        this.sysinfo = data.sysinfo;
        this.clients = data.clients || [];
        this.selected.online = data.online;
      } catch (_) {}
    },

    async addServer() {
      this.addBusy = true; this.addErr = "";
      try {
        const r = await fetch("/api/servers", {
          method: "POST",
          headers: {"content-type":"application/json"},
          body: JSON.stringify(this.newServer),
        });
        if (!r.ok) {
          const j = await r.json().catch(()=>({}));
          this.addErr = j.detail || ("Ошибка " + r.status);
          return;
        }
        this.openAddServer = false;
        this.newServer = { name: "", public_host: "", agent_url: "", agent_token: "",
          port: 443, sni: "rutube.ru", dest: "rutube.ru:443" };
        await this.loadServers();
      } finally { this.addBusy = false; }
    },

    async deleteSelectedServer() {
      if (!this.selected) return;
      if (!confirm("Удалить сервер " + this.selected.name + "?")) return;
      await fetch("/api/servers/" + this.selected.id, { method: "DELETE" });
      this.selected = null;
      clearInterval(this.pollTimer);
      await this.loadServers();
    },

    async addClient() {
      if (!this.selected) return;
      this.addClientErr = "";
      const r = await fetch("/api/servers/" + this.selected.id + "/clients", {
        method: "POST",
        headers: {"content-type":"application/json"},
        body: JSON.stringify(this.newClient),
      });
      if (!r.ok) {
        const j = await r.json().catch(()=>({}));
        this.addClientErr = j.detail || ("Ошибка " + r.status);
        return;
      }
      this.openAddClient = false;
      this.newClient = { email: "", label: "" };
      await this.refreshStats();
      await this.loadServers();
    },

    async deleteClient(c) {
      if (!confirm("Удалить ключ " + c.email + "?")) return;
      await fetch("/api/servers/" + this.selected.id + "/clients/" + c.id, { method: "DELETE" });
      await this.refreshStats();
      await this.loadServers();
    },

    showLink(c) { this.linkFor = c; },
    copyLink() {
      if (!this.linkFor) return;
      navigator.clipboard.writeText(this.linkFor.vless_link).catch(()=>{});
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
    fmtUptime(s) {
      s = Number(s || 0);
      const d = Math.floor(s / 86400); s %= 86400;
      const h = Math.floor(s / 3600); s %= 3600;
      const m = Math.floor(s / 60);
      if (d) return d + "д " + h + "ч";
      if (h) return h + "ч " + m + "м";
      return m + "м";
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
  };
}
