"""Static informational sites, managed independently of Xray and certificates."""
import hashlib
import html
import pathlib
import re
import subprocess
import threading
from datetime import datetime, timezone

LOCK = threading.Lock()
NGINX_DIR = pathlib.Path('/etc/nginx/conf.d')
WWW_DIR = pathlib.Path('/var/www')
BACKUP_DIR = pathlib.Path('/var/lib/xnpanel/origin-backups')
DESIGNS = [
    ('Дом и чистота', '#436a42', '#f6f5ee', 'Меньше уборки. Больше времени для себя.',
     'Гид по домашней технике: сравните пылесосы и найдите подходящий формат уборки.',
     [('Вертикальные пылесосы', '◒', 'Для ежедневной уборки кухни, прихожей и небольших комнат.'),
      ('Роботы-пылесосы', '◉', 'Поддержание чистоты по расписанию. Навигация, щётки и уход.'),
      ('Моющие пылесосы', '▣', 'Сухая и влажная уборка: сравните вес, объём бака и расходники.')],
     [('Что выбрать для дома с питомцами?', 'Проверьте наличие турбощётки, удобство очистки контейнера и доступность сменных фильтров.'),
      ('Может ли робот заменить обычный пылесос?', 'Робот помогает поддерживать чистоту. Для мебели и локальной уборки часто нужен отдельный прибор.'),
      ('Что проверить перед покупкой?', 'Сопоставьте площадь, тип покрытия, вес устройства и доступность расходников для конкретной модели.')]),
    ('Мастерская дома', '#255cad', '#f2f5fa', 'Техника заслуживает второго шанса.',
     'Справочник по уходу за бытовой техникой. Что проверить самостоятельно и когда нужен специалист.',
     [('Стиральные машины', '▣', 'Фильтры, загрузка и режимы: привычки, которые помогают технике служить дольше.'),
      ('Холодильники', '▤', 'Температура, уплотнители и свободное пространство вокруг корпуса.'),
      ('Посудомоечные машины', '▥', 'Правильная загрузка, очистка фильтра и выбор моющего средства.')],
     [('Когда нельзя включать прибор?', 'При запахе гари, повреждённом кабеле или протечке отключите питание безопасным способом и вызовите специалиста.'),
      ('Можно ли разобрать прибор самому?', 'Следуйте инструкции производителя. Работы с газом, электрикой и герметичными контурами поручите квалифицированному специалисту.'),
      ('Как подготовиться к диагностике?', 'Запишите модель, симптомы и код ошибки. Сохраните документы о покупке и обслуживании.')]),
    ('Тёплый угол', '#9b513c', '#faf3eb', 'Дом, в который хочется возвращаться.',
     'Идеи для спокойного и удобного пространства. Текстиль, свет и хранение без лишних вещей.',
     [('Домашний текстиль', '▧', 'Спокойные оттенки, мягкие фактуры и простые сочетания.'),
      ('Освещение', '◠', 'Рабочий свет днём и мягкое освещение вечером.'),
      ('Удобное хранение', '▦', 'Корзины, полки и органайзеры для вещей, которыми пользуются каждый день.')],
     [('С чего начать обновление комнаты?', 'Определите, что мешает комфорту. Иногда достаточно переместить светильник и освободить рабочую поверхность.'),
      ('Как сочетать цвета?', 'Выберите нейтральную основу и один-два акцента. Сравнивайте материалы при дневном свете.'),
      ('Как не купить лишнего?', 'Измерьте место, проверьте уход за материалом и заранее решите, где вещь будет храниться.')]),
]


def site_html(seed):
    brand, accent, paper, title, lead, items, questions = DESIGNS[int(hashlib.sha256(seed.encode()).hexdigest()[:8], 16) % len(DESIGNS)]
    esc = html.escape
    cards = ''.join(f'<article class="card"><div class="product" aria-hidden="true">{symbol}</div><h3>{esc(name)}</h3><p>{esc(description)}</p><a href="#faq">Как выбрать →</a></article>' for name, symbol, description in items)
    faq = ''.join(f'<details><summary>{esc(q)}</summary><p>{esc(a)}</p></details>' for q, a in questions)
    return f'''<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(brand)} — идеи и подборки</title><style>
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:{paper};color:#232723;font:16px/1.65 system-ui,sans-serif}}header,main,footer{{max-width:1180px;margin:auto;padding:24px}}header{{display:flex;justify-content:space-between;align-items:center;gap:18px;border-bottom:1px solid #23272318}}.brand{{font-size:22px;font-weight:800;letter-spacing:-.7px;text-decoration:none;color:{accent}}}nav{{display:flex;gap:26px}}a{{color:{accent}}}nav a{{text-decoration:none;color:#454b45;font-size:14px}}.hero{{display:grid;grid-template-columns:1.3fr 1fr;gap:50px;align-items:center;padding:75px 0}}.tag{{font-size:12px;letter-spacing:1px;text-transform:uppercase;color:{accent}}}h1{{font-size:clamp(38px,5.5vw,70px);line-height:1.08;letter-spacing:-2.6px;margin:20px 0}}h2{{font-size:34px;letter-spacing:-1px}}h3{{font-size:23px;line-height:1.2;margin:18px 0}}p{{color:#626862}}.lead{{font-size:19px;max-width:560px}}.button{{display:inline-block;padding:15px 25px;border-radius:50px;background:{accent};color:white;text-decoration:none;margin-top:15px}}.art{{min-height:320px;background:{accent};border-radius:160px 160px 30px 30px;display:grid;place-items:center;color:{paper};font:180px/1 Georgia;box-shadow:20px 20px 0 #23272308}}.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:22px}}.card{{background:white;border:1px solid #23272312;border-radius:22px;padding:24px}}.product{{height:180px;background:{paper};border-radius:14px;display:grid;place-items:center;font:100px/1 Georgia;color:{accent}}}.card a{{font-weight:600;text-decoration:none}}section{{padding:28px 0}}.help{{background:white;border-radius:24px;padding:35px;border:1px solid #23272316}}details{{border-bottom:1px solid #23272320;padding:20px 0}}summary{{cursor:pointer;font-weight:650}}footer{{margin-top:55px;border-top:1px solid #23272320;color:#6a706a;font-size:12px}}a:focus-visible,summary:focus-visible{{outline:3px solid {accent};outline-offset:5px}}@media(max-width:750px){{.hero{{grid-template-columns:1fr;gap:28px;padding:40px 0}}.art{{min-height:200px;font-size:130px;border-radius:100px 100px 24px 24px}}.grid{{grid-template-columns:1fr}}nav{{gap:12px}}nav a:first-child{{display:none}}h1{{letter-spacing:-1px}}header,main,footer{{padding:20px}}.help{{padding:24px}}}}
</style></head><body><header><a class="brand" href="/">{esc(brand)}</a><nav><a href="#catalog">Подборки</a><a href="#faq">Вопросы</a><a href="#help">Помощь</a></nav></header><main><div class="hero"><div><div class="tag">Идеи для повседневной жизни</div><h1>{esc(title)}</h1><p class="lead">{esc(lead)}</p><a class="button" href="#catalog">Посмотреть подборку →</a></div><div class="art" aria-hidden="true">{items[0][1]}</div></div><section id="catalog"><h2>С чего начнём?</h2><div class="grid">{cards}</div></section><section id="faq"><h2>Полезно знать</h2>{faq}</section><section id="help"><div class="help"><div class="tag">Справочный центр</div><h2>Поможем сделать выбор</h2><p>Ответы на частые вопросы собраны выше. Точные характеристики и совместимость проверяйте по документации производителя.</p><a href="#faq">Открыть ответы на вопросы →</a></div></section></main><footer>{esc(brand)} · Демонстрационный информационный каталог. Онлайн-заказы и платежи не принимаются.</footer></body></html>'''


def update_site(job_id):
    if not re.fullmatch(r'[a-f0-9]{12}', job_id):
        raise ValueError('invalid job id')
    with LOCK:
        target = NGINX_DIR / ('xnpanel-cdn-' + job_id + '.conf')
        if target.is_symlink():
            raise ValueError('symlink config not supported')
        previous = target.read_text()
        root = WWW_DIR / ('xnpanel-cdn-' + job_id)
        expected = 'root ' + str(root) + ';'
        pattern = r"location\s*=\s*/\s*\{\s*default_type\s+text/plain;\s*return\s+200\s+'CDN origin ready';\s*\}"
        if expected not in previous and not re.search(pattern, previous):
            raise ValueError('Unknown origin layout; no changes applied')
        replacement = expected + '\n index index.html;\n location / { try_files $uri $uri/ =404; }'
        updated = re.sub(pattern, lambda _: replacement, previous, count=1)
        if root.is_symlink():
            raise ValueError('symlink web root not supported')
        root.mkdir(parents=True, exist_ok=True)
        page = root / 'index.html'
        if page.is_symlink():
            raise ValueError('symlink page not supported')
        before_page = page.read_bytes() if page.exists() else None
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        backup = BACKUP_DIR / (job_id + '-' + stamp)
        backup.mkdir(parents=True, mode=0o700)
        (backup / 'nginx.conf').write_text(previous)
        if before_page is not None:
            (backup / 'index.html').write_bytes(before_page)
        try:
            page.write_text(site_html(job_id), encoding='utf-8')
            page.chmod(0o644)
            root.chmod(0o755)
            target.write_text(updated)
            subprocess.run(['nginx', '-t'], check=True, capture_output=True, timeout=15)
            subprocess.run(['systemctl', 'reload', 'nginx'], check=True, capture_output=True, timeout=20)
        except Exception:
            target.write_text(previous)
            if before_page is None:
                page.unlink(missing_ok=True)
            else:
                page.write_bytes(before_page)
            subprocess.run(['nginx', '-t'], check=True, capture_output=True, timeout=15)
            subprocess.run(['systemctl', 'reload', 'nginx'], check=True, capture_output=True, timeout=20)
            raise
        return {'ok': True, 'job_id': job_id, 'site_updated': True}
