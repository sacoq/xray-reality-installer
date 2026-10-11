import importlib.util
from pathlib import Path
from unittest.mock import patch
import pytest

spec = importlib.util.spec_from_file_location('origin_site', Path(__file__).parents[1] / 'agent' / 'origin_site.py')
site = importlib.util.module_from_spec(spec)
spec.loader.exec_module(site)


def setup_origin(tmp_path, monkeypatch):
    for key in ['NGINX_DIR', 'WWW_DIR', 'BACKUP_DIR']:
        monkeypatch.setattr(site, key, tmp_path / key)
        getattr(site, key).mkdir()
    target = site.NGINX_DIR / 'xnpanel-cdn-012345abcdef.conf'
    original = "server { listen 24443 ssl; location = / { default_type text/plain; return 200 'CDN origin ready'; } location /content/v1/private/ { proxy_pass http://127.0.0.1:34443; } }"
    target.write_text(original)
    return target, original


def test_site_preserves_proxy_and_repeat_is_idempotent(tmp_path, monkeypatch):
    target, original = setup_origin(tmp_path, monkeypatch)
    with patch.object(site.subprocess, 'run') as run:
        assert site.update_site('012345abcdef')['ok']
        first = target.read_text()
        assert 'location /content/v1/private/ { proxy_pass http://127.0.0.1:34443; }' in first
        assert 'listen 24443 ssl;' in first
        site.update_site('012345abcdef')
        assert target.read_text() == first
        assert all('xray' not in str(call) for call in run.call_args_list)
    assert len(list(site.BACKUP_DIR.iterdir())) == 2


def test_failed_validation_restores_previous_files(tmp_path, monkeypatch):
    target, original = setup_origin(tmp_path, monkeypatch)
    with patch.object(site.subprocess, 'run', side_effect=[RuntimeError('invalid nginx'), None, None]):
        with pytest.raises(RuntimeError):
            site.update_site('012345abcdef')
    assert target.read_text() == original
    assert not (site.WWW_DIR / 'xnpanel-cdn-012345abcdef' / 'index.html').exists()


def test_unknown_config_and_path_traversal_rejected(tmp_path, monkeypatch):
    target, _ = setup_origin(tmp_path, monkeypatch)
    target.write_text('unrelated config')
    with pytest.raises(ValueError):
        site.update_site('012345abcdef')
    with pytest.raises(ValueError):
        site.update_site('../../passwd')
    assert target.read_text() == 'unrelated config'


def test_three_topics_and_no_vpn_brand():
    pages = {site.site_html(str(i)) for i in range(50)}
    assert len(pages) == 3
    assert all('ZaNet' not in p and 'xanka' not in p and '<html lang="ru">' in p for p in pages)
