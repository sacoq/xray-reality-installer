from pathlib import Path


def test_installer_retries_only_transient_enrollment_completion() -> None:
    script = Path('install.sh').read_text(encoding='utf-8')
    assert 'for attempt in 1 2 3' in script
    assert '--connect-timeout 8 --max-time 45' in script
    assert '"503"' in script and '"504"' in script
    assert 'idempotent for that pending' in script
