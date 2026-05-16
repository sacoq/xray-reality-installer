"""HTML rendering for the public subscription landing page.

This is the page admins link end users to via ``/page/{token}`` — it
shows subscription status, deep-link buttons for the most popular
clients (Streisand, v2RayTun, Hiddify, Happ, INCY, Nekobox), the
copy-link button, and per-device install instructions detected from
the User-Agent header.

The page is fully customisable per bot via :class:`models.TgBot`:
``brand_name``, ``logo_url``, ``page_subtitle``, ``page_help_text``,
``page_buy_url``, and ``support_url``.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Optional

from .models import TgBot


# Sensible defaults that match the panel's overall look and let the
# page work even when the admin hasn't filled in any branding yet.
_DEFAULT_BRAND = "VPN"
_DEFAULT_LOGO = "https://i.ibb.co/Xx9wfHXv/favicon.png"


def _h(value: object) -> str:
    """HTML-escape ``value``, treating ``None`` as the empty string."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


class PageBranding:
    """Resolved branding values for the subscription page.

    Pulled from a :class:`TgBot` row when the token belongs to a bot
    user, with sensible defaults for admin-issued subscription tokens.
    """

    __slots__ = (
        "brand_name", "logo_url", "subtitle", "help_text",
        "support_url", "buy_url",
    )

    def __init__(
        self,
        *,
        brand_name: str = "",
        logo_url: str = "",
        subtitle: str = "",
        help_text: str = "",
        support_url: str = "",
        buy_url: str = "",
    ) -> None:
        self.brand_name = (brand_name or "").strip() or _DEFAULT_BRAND
        self.logo_url = (logo_url or "").strip() or _DEFAULT_LOGO
        self.subtitle = (subtitle or "").strip()
        self.help_text = help_text or ""
        self.support_url = (support_url or "").strip()
        self.buy_url = (buy_url or "").strip()

    @classmethod
    def from_bot(cls, bot: "Optional[TgBot]") -> "PageBranding":
        if bot is None:
            return cls()
        return cls(
            brand_name=getattr(bot, "brand_name", "") or "",
            logo_url=getattr(bot, "logo_url", "") or "",
            subtitle=getattr(bot, "page_subtitle", "") or "",
            help_text=getattr(bot, "page_help_text", "") or "",
            support_url=getattr(bot, "support_url", "") or "",
            buy_url=getattr(bot, "page_buy_url", "") or "",
        )


def _layout(*, title: str, body: str, branding: PageBranding) -> str:
    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <title>{_h(title)}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        body {{ font-family: 'DM Sans', system-ui, sans-serif; }}
        .glass {{ background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.08); }}
        .neon-text {{ text-shadow: 0 0 25px rgb(0 243 255), 0 0 50px rgb(0 243 255); }}
        .grid-bg {{ background-image: linear-gradient(to right, rgba(0,243,255,0.04) 1px, transparent 1px), linear-gradient(to bottom, rgba(0,243,255,0.04) 1px, transparent 1px); background-size: 40px 40px; }}
        .fade-in {{ animation: fadeInUp 0.8s ease forwards; }}
        @keyframes fadeInUp {{ from {{ opacity: 0; transform: translateY(40px); }} to {{ opacity: 1; transform: translateY(0); }} }}
        .app-card {{ transition: all 0.2s ease; }}
        .app-card:hover {{ transform: translateY(-3px); background-color: rgb(39 39 42); }}
    </style>
</head>
<body class="bg-zinc-950 text-white min-h-screen grid-bg overflow-auto">
    <div class="absolute inset-0 bg-gradient-to-br from-cyan-500/5 via-transparent to-purple-500/5"></div>
    <div class="max-w-md w-full mx-auto px-5 py-10 relative z-10">
        <div class="flex justify-center mb-8">
            <div class="flex items-center gap-3">
                <img src="{_h(branding.logo_url)}" alt="{_h(branding.brand_name)}" class="w-11 h-11 object-contain drop-shadow-lg" referrerpolicy="no-referrer">
                <span class="text-3xl font-semibold tracking-tighter">{_h(branding.brand_name)}</span>
            </div>
        </div>
        {body}
    </div>
</body>
</html>
"""


def render_not_found(branding: PageBranding) -> str:
    body = f"""
    <div class="glass rounded-3xl p-10 text-center fade-in">
        <div class="mx-auto w-20 h-20 rounded-2xl bg-zinc-900 flex items-center justify-center mb-6 border border-cyan-500/20">
            <svg xmlns="http://www.w3.org/2000/svg" class="w-10 h-10 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 10l-4 4m0 0l-4-4m4 4V3" />
            </svg>
        </div>
        <h1 class="text-3xl font-semibold tracking-tight mb-2 neon-text">Подписка не найдена</h1>
        <p class="text-zinc-400 mb-8">Токен недействителен или подписка была удалена.</p>
        {_buy_button(branding) or ""}
        {_support_link(branding) or ""}
    </div>
    """
    return _layout(
        title=f"Подписка не найдена — {branding.brand_name}",
        body=body, branding=branding,
    )


def render_expired(
    branding: PageBranding, *, expires_at: datetime
) -> str:
    expire_date = expires_at.strftime("%d.%m.%Y")
    body = f"""
    <div class="glass rounded-3xl p-10 text-center fade-in">
        <div class="mx-auto w-20 h-20 rounded-2xl bg-gradient-to-br from-orange-500 to-red-600 flex items-center justify-center mb-6 shadow-lg shadow-orange-500/30">
            <svg xmlns="http://www.w3.org/2000/svg" class="w-10 h-10 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 01-18 0 9 9 0 0118 0z" />
            </svg>
        </div>
        <h1 class="text-3xl font-semibold tracking-tight mb-2 neon-text">Подписка истекла</h1>
        <p class="text-zinc-400 mb-2">Действовала до <span class="text-orange-400 font-medium">{_h(expire_date)}</span></p>
        <div class="my-8 text-sm text-zinc-500">К сожалению, срок действия вашей подписки закончился.<br>Продлите её, чтобы продолжить пользоваться VPN.</div>
        {_buy_button(branding, primary=True) or ""}
        {_support_link(branding) or ""}
    </div>
    """
    return _layout(
        title=f"Подписка истекла — {branding.brand_name}",
        body=body, branding=branding,
    )


def render_active(
    branding: PageBranding,
    *,
    sub_url: str,
    expires_at: "Optional[datetime]" = None,
) -> str:
    sub_url_safe = _h(sub_url)
    sub_url_js = sub_url.replace("\\", "\\\\").replace("'", "\\'")

    if expires_at is not None:
        now = datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        delta = expires_at - now
        total_seconds = int(delta.total_seconds())
        days_left = total_seconds // 86400
        hours_left = (total_seconds % 86400) // 3600
        minutes_left = (total_seconds % 3600) // 60
        expire_date_str = expires_at.strftime("%d.%m.%Y")
        if days_left > 3:
            expire_text = f"Подписка активна до {expire_date_str}"
            color_class = "text-emerald-400"
            show_renew = False
        elif days_left >= 1:
            days_word = "день" if days_left == 1 else "дня" if days_left <= 4 else "дней"
            expire_text = (
                f"Подписка истекает через {days_left} {days_word} {hours_left} ч."
            )
            color_class = "text-amber-400"
            show_renew = True
        elif total_seconds > 0:
            expire_text = (
                f"Подписка истекает через {hours_left} ч. {minutes_left:02d} мин."
            )
            color_class = "text-red-400"
            show_renew = True
        else:
            expire_text = f"Истекла {expire_date_str}"
            color_class = "text-red-400"
            show_renew = True
    else:
        expire_text = "Подписка активна — без ограничений по сроку"
        color_class = "text-emerald-400"
        show_renew = False

    renew_html = ""
    if show_renew and branding.buy_url:
        renew_html = f"""
        <a href="{_h(branding.buy_url)}" target="_blank"
           class="block w-full bg-gradient-to-r from-amber-500 to-orange-500 text-white font-semibold py-4 rounded-2xl text-center mt-4 hover:scale-[1.02] transition-all">
            Продлить подписку
        </a>
        """

    help_block = ""
    if branding.help_text.strip():
        help_block = (
            "<div class=\"mt-6 text-sm text-zinc-400 leading-relaxed\">"
            f"{branding.help_text}</div>"
        )

    body = f"""
    <div class="glass rounded-3xl p-8 fade-in">
        <div class="text-center mb-8">
            <div class="mx-auto w-20 h-20 rounded-2xl bg-gradient-to-br from-emerald-500 to-teal-500 flex items-center justify-center mb-5 shadow-xl shadow-emerald-500/40">
                <svg xmlns="http://www.w3.org/2000/svg" class="w-12 h-12 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="3">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 01-18 0 9 9 0 0118 0z" />
                </svg>
            </div>
            <h1 class="text-3xl font-semibold tracking-tight neon-text">Подписка активна</h1>
            {('<p class="mt-2 text-zinc-400">' + _h(branding.subtitle) + '</p>') if branding.subtitle else ''}
            <div class="mt-4 text-base {color_class}">{_h(expire_text)}</div>
            {renew_html}
        </div>

        <div class="mb-6 text-center">
            <button id="show-instructions-btn"
                    class="bg-zinc-900 hover:bg-zinc-800 border border-white/20 hover:border-cyan-400 text-white px-6 py-3 rounded-2xl text-sm font-medium transition-all">
                📱 Показать инструкцию для моего устройства
            </button>
        </div>

        <div id="device-banner" class="hidden bg-zinc-900/90 border border-cyan-400/30 rounded-3xl p-7 mb-8">
            <div class="flex items-center gap-3 mb-5">
                <div id="device-icon" class="text-4xl"></div>
                <div id="device-title" class="font-semibold text-xl"></div>
            </div>
            <div id="instructions-content" class="text-zinc-300 text-[15px] leading-relaxed space-y-3"></div>
        </div>

        <div class="mb-8">
            <p class="text-xs uppercase tracking-widest text-zinc-500 mb-4">Подключить в одно касание</p>
            <div class="grid grid-cols-3 gap-3">
                {_app_cards(sub_url_safe)}
            </div>
        </div>

        <div>
            <p class="text-xs uppercase tracking-widest text-zinc-500 mb-3">Ручное добавление</p>
            <div class="bg-zinc-900/80 border border-white/10 rounded-2xl p-4 font-mono text-sm break-all text-cyan-300" id="sub-link">{sub_url_safe}</div>
            <button onclick="copyLink()"
                    class="mt-3 w-full bg-white text-zinc-900 hover:bg-cyan-300 font-semibold py-4 rounded-2xl transition-all active:scale-95">
                📋 Скопировать ссылку
            </button>
        </div>

        {help_block}
        {_support_link(branding, dim=True) or ""}
    </div>
{_active_page_script(sub_url_js)}
    """
    return _layout(
        title=f"{branding.brand_name} — управление подпиской",
        body=body, branding=branding,
    )


def _app_cards(sub_url_safe: str) -> str:
    rows = [
        ("Streisand", f"streisand://import/{sub_url_safe}",
         "https://is1-ssl.mzstatic.com/image/thumb/Purple211/v4/1e/29/e0/1e29e04f-273b-9186-5f12-9bbe48c0fce2/AppIcon-0-0-1x_U007epad-0-0-0-1-0-85-220.png/512x512bb.jpg"),
        ("v2RayTun", f"v2raytun://import/{sub_url_safe}",
         "https://is1-ssl.mzstatic.com/image/thumb/Purple211/v4/6f/be/75/6fbe75c4-c509-c2a0-b012-82525dccbcc5/AppIcon-0-0-1x_U007epad-0-1-85-220.png/1200x630wa.jpg"),
        ("Hiddify", f"hiddify://install-config/?url={sub_url_safe}",
         "https://avatars.mds.yandex.net/i?id=1dea41121220f84a4a3a6e6aa6b20b39_l-12569754-images-thumbs&n=13"),
        ("Happ", f"happ://add/{sub_url_safe}",
         "https://is1-ssl.mzstatic.com/image/thumb/Purple221/v4/1a/9a/3f/1a9a3f3f-491e-1ab9-b7e4-d45c9f254606/App_Icon-marketing.lsr/512x512bb.jpg"),
        ("INCY", f"incy://import/{sub_url_safe}",
         "https://is1-ssl.mzstatic.com/image/thumb/PurpleSource211/v4/a4/5a/ce/a45aceca-7ef5-0b20-1dae-62648096fbe9/Placeholder.mill/200x200bb-75.webp"),
        ("Nekobox", f"nekobox://install-config?url={sub_url_safe}",
         "https://raw.githubusercontent.com/MatsuriDayo/NekoBoxForAndroid/main/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png"),
    ]
    cards = []
    for name, href, icon in rows:
        cards.append(
            f"""
            <a href="{_h(href)}" class="app-card bg-zinc-900/70 hover:bg-zinc-800 p-3 rounded-2xl text-center">
                <img src="{_h(icon)}" alt="{_h(name)}" class="w-14 h-14 mx-auto rounded-2xl" referrerpolicy="no-referrer">
                <div class="text-xs mt-2">{_h(name)}</div>
            </a>
            """
        )
    return "".join(cards)


def _buy_button(
    branding: PageBranding, *, primary: bool = False
) -> "Optional[str]":
    if not branding.buy_url:
        return None
    klass = (
        "block w-full bg-gradient-to-r from-cyan-400 to-blue-500 font-semibold py-4 rounded-2xl text-lg hover:scale-[1.02] transition-all"
        if primary
        else "block w-full bg-white text-zinc-900 font-medium py-4 rounded-2xl hover:bg-cyan-300 transition-all hover:scale-[1.02] text-lg"
    )
    return (
        f'<a href="{_h(branding.buy_url)}" class="{klass}">'
        f'Купить подписку</a>'
    )


def _support_link(
    branding: PageBranding, *, dim: bool = False
) -> "Optional[str]":
    if not branding.support_url:
        return None
    klass = (
        "block w-full mt-4 text-zinc-500 hover:text-zinc-300 py-3 text-sm text-center"
        if dim
        else "block w-full mt-4 border border-white/20 hover:border-white/40 py-3.5 rounded-2xl text-sm font-medium text-center"
    )
    return (
        f'<a href="{_h(branding.support_url)}" class="{klass}">'
        f'Написать в поддержку</a>'
    )


def _active_page_script(sub_url_js: str) -> str:
    # Plain JS (no f-string substitutions inside) so we don't accidentally
    # eat ``{`` characters in the device-detection switch.
    return """<script>
const __SUB_URL__ = '""" + sub_url_js + """';
function copyLink() {
    navigator.clipboard.writeText(__SUB_URL__).then(() => {
        const btn = event.target;
        const original = btn.textContent;
        btn.textContent = '✓ Скопировано!';
        setTimeout(() => { btn.textContent = original; }, 2000);
    });
}
function detectDevice() {
  const ua = navigator.userAgent.toLowerCase();
  if (/windows/.test(ua)) {
    return { icon: '💻', title: 'Windows (Happ)', instructions:
      '<p><strong>1.</strong> Скачай и установи Happ:</p>' +
      '<p><a href="https://github.com/Happ-proxy/happ-desktop/releases/latest/download/setup-Happ.x64.exe" target="_blank" class="text-cyan-400">Скачать Happ для Windows</a></p>' +
      '<p><strong>2.</strong> Нажми кнопку «Happ» выше — подписка добавится автоматически.</p>' +
      '<p><strong>3.</strong> Если кнопка не сработала: «Скопировать ссылку» → в Happ «+» → «Добавить из буфера обмена».</p>'
    };
  }
  if (/iphone|ipad|ipod/.test(ua)) {
    return { icon: '🍎', title: 'iPhone / iPad (Happ)', instructions:
      '<p><strong>1.</strong> Установи Happ из App Store: <a href="https://apps.apple.com/ru/app/happ-proxy-utility-plus/id6746188973" target="_blank" class="text-cyan-400">App Store</a>.</p>' +
      '<p><strong>2.</strong> Нажми кнопку «Happ» выше.</p>' +
      '<p><strong>3.</strong> Если не сработало — «Скопировать ссылку», открой Happ → «+» → «Добавить из буфера».</p>'
    };
  }
  if (/android/.test(ua)) {
    if (/android tv|smart-tv|googletv/.test(ua)) {
      return { icon: '📺', title: 'Android TV (Happ)', instructions:
        '<p><strong>1.</strong> Установи Happ для TV из Google Play.</p>' +
        '<p><strong>2.</strong> На телефоне нажми «Скопировать ссылку».</p>' +
        '<p><strong>3.</strong> На Android TV открой Happ → «Ручной ввод» и вставь ссылку.</p>'
      };
    }
    return { icon: '🤖', title: 'Android (Happ)', instructions:
      '<p><strong>1.</strong> Установи Happ: <a href="https://play.google.com/store/apps/details?id=com.happproxy" target="_blank" class="text-cyan-400">Google Play</a>.</p>' +
      '<p><strong>2.</strong> Нажми кнопку «Happ» выше.</p>' +
      '<p><strong>3.</strong> Если не добавилось: «Скопировать ссылку» → в Happ «+» → «Добавить из буфера обмена».</p>'
    };
  }
  if (/macintosh|mac os x/.test(ua)) {
    return { icon: '💻', title: 'macOS (Happ)', instructions:
      '<p><strong>1.</strong> Установи Happ: <a href="https://apps.apple.com/ru/app/happ-proxy-utility-plus/id6746188973" target="_blank" class="text-cyan-400">App Store</a>.</p>' +
      '<p><strong>2.</strong> Нажми кнопку «Happ» выше.</p>' +
      '<p><strong>3.</strong> Если не сработало — скопируй ссылку и добавь вручную в Happ.</p>'
    };
  }
  return { icon: '🌐', title: 'Общая инструкция', instructions:
    '<p>Выбери приложение выше или скопируй ссылку и добавь её в свой VPN-клиент вручную.</p>'
  };
}
function showDeviceInstructions() {
  const device = detectDevice();
  const banner = document.getElementById('device-banner');
  document.getElementById('device-icon').textContent = device.icon;
  document.getElementById('device-title').textContent = device.title;
  document.getElementById('instructions-content').innerHTML = device.instructions;
  banner.classList.remove('hidden');
}
document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('show-instructions-btn').addEventListener('click', showDeviceInstructions);
});
</script>"""
