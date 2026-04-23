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

    // enrollment
    enrollments: [],
    openEnroll: false,
    enrollBusy: false,
    enrollErr: "",
    newEnroll: {
      name: "", public_host: "", port: 443, sni: "rutube.ru",
      dest: "rutube.ru:443", agent_port: 8765,
    },
    enrollCreated: null,

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
    newClient: { email: "", label: "" },

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
      const all = [];
      for (const s of servers) {
        try {
          const r = await fetch("/api/servers/" + s.id + "/clients");
          if (!r.ok) continue;
          const list = await r.json();
          for (const c of list) all.push({ ...c, server_name: s.name });
        } catch (_) {}
      }
      this.allClientsForSub = all;
    },

    async switchView(v) {
      this.view = v;
      if (v === "enrollments") await this.loadEnrollments();
      if (v === "subscriptions") { await this.loadSubscriptions(); }
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

    openEditServer() {
      if (!this.selected) return;
      this.editingServer = {
        id: this.selected.id,
        name: this.selected.name,
        public_host: this.selected.public_host,
        port: this.selected.port,
        sni: this.selected.sni,
        dest: this.selected.dest,
        agent_url: this.selected.agent_url,
        agent_token: "",  // empty = keep existing
      };
      this.editServerErr = "";
    },
    applyPreset(preset) {
      if (!this.editingServer) return;
      this.editingServer.sni = preset.sni;
      this.editingServer.dest = preset.dest;
    },
    async saveServer() {
      if (!this.editingServer) return;
      const body = {
        name: this.editingServer.name,
        public_host: this.editingServer.public_host,
        port: Number(this.editingServer.port),
        sni: this.editingServer.sni,
        dest: this.editingServer.dest,
        agent_url: this.editingServer.agent_url,
      };
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

    async deleteSelectedServer() {
      if (!this.selected) return;
      if (!confirm("Удалить сервер " + this.selected.name + "? Эта операция не удаляет xray с самого сервера.")) return;
      await fetch("/api/servers/" + this.selected.id, { method: "DELETE" });
      this.selected = null;
      clearInterval(this.pollTimer);
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
        this.newEnroll = { name: "", public_host: "", port: 443, sni: "rutube.ru",
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
      this.editingSub = { ...s, client_ids: [...(s.client_ids || [])] };
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
  };
}
