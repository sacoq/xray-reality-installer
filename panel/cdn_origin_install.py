"""Install an isolated nginx CDN origin with DNS-based certificate renewal."""
import json,sys,subprocess,pathlib,re,os,hashlib,html

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

def install_site(c):
    root=pathlib.Path('/var/www/xnpanel-cdn-'+c['id']); root.mkdir(parents=True,exist_ok=True)
    (root/'index.html').write_text(site_html(c['id']),encoding='utf-8'); (root/'index.html').chmod(0o644); root.chmod(0o755)


def render(c):
    origin=c['origin']; port=int(c['origin_port']); upstream=int(c['inbound_port']); path=c['path']
    if not re.fullmatch(r'[a-z0-9.-]+',origin) or not re.fullmatch(r'/[a-zA-Z0-9/_-]+/',path):raise ValueError('invalid origin/path')
    if not 1024<=port<=65535 or not 1024<=upstream<=65535:raise ValueError('invalid ports')
    return f"""server {{
 listen {port} ssl http2; server_name {origin};
 ssl_certificate /etc/letsencrypt/live/{origin}/fullchain.pem;
 ssl_certificate_key /etc/letsencrypt/live/{origin}/privkey.pem;
 client_max_body_size 0; proxy_read_timeout 3600s; proxy_send_timeout 3600s;
 root /var/www/xnpanel-cdn-{c['id']};
 index index.html;
 location / {{ try_files $uri $uri/ =404; }}
 location {path} {{
  proxy_http_version 1.1; proxy_set_header Host $host; proxy_set_header Connection "";
  proxy_buffering off; proxy_request_buffering off;
  proxy_pass http://127.0.0.1:{upstream};
 }}
}}
"""

def main(c):
    conf=render(c)
    install_site(c)
    def run(*args):subprocess.run(args,check=True,capture_output=True,text=True)
    run('bash','-lc','export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq nginx certbot python3-certbot-dns-cloudflare')
    cred=pathlib.Path('/etc/letsencrypt/xnpanel-cdn-'+c['id']+'.ini')
    fd=os.open(cred,os.O_CREAT|os.O_WRONLY|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as f:f.write('dns_cloudflare_api_token = '+c['cloudflare_token']+'\n')
    os.chmod(cred,0o600)
    run('certbot','certonly','--dns-cloudflare','--dns-cloudflare-credentials',str(cred),'--dns-cloudflare-propagation-seconds','30','-d',c['origin'],'--non-interactive','--agree-tos','-m',c['email'])
    target=pathlib.Path('/etc/nginx/conf.d/xnpanel-cdn-'+c['id']+'.conf')
    previous=target.read_text() if target.exists() else None
    target.write_text(conf)
    try:run('nginx','-t')
    except Exception:
        if previous is None:target.unlink(missing_ok=True)
        else:target.write_text(previous)
        raise
    run('systemctl','enable','--now','nginx');run('systemctl','reload','nginx')
    hook=pathlib.Path('/etc/letsencrypt/renewal-hooks/deploy/xnpanel-nginx')
    hook.parent.mkdir(parents=True,exist_ok=True);hook.write_text('#!/bin/sh\nnginx -t && systemctl reload nginx\n');hook.chmod(0o700)
    status=subprocess.run(['ufw','status'],capture_output=True,text=True)
    if status.returncode==0 and 'Status: active' in status.stdout:run('ufw','allow',str(c['origin_port'])+'/tcp')
    print('origin ready')
if __name__=='__main__':main(json.loads(pathlib.Path(sys.argv[1]).read_text()))
