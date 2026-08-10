# Weekly project audit — 2026-08-10

- **HEAD:** `8f1727d436ea7b9d062f3800274367c44346c82c`
- **Baseline:** `9be081b220915850ae291b1666eb954a9479cefe`
- **AI provider:** `deterministic-only`
- **Tests exit code:** `1`

## Week-over-week change summary

```text
.github/workflows/weekly-ai-audit.yml |   38 ++
 README.md                             |   39 +-
 agent/agent.py                        |  283 ++++++++-
 agent/session_security.py             |  299 ++++++++++
 panel/agent_client.py                 |   23 +
 panel/app.py                          |  888 +++++++++++++++++++---------
 panel/backups.py                      | 1032 +++++++++++++++++++++++++++++++++
 panel/database.py                     |   34 ++
 panel/metrics_sync.py                 |  387 ++++++++++++-
 panel/models.py                       |   47 ++
 panel/requirements.txt                |    1 +
 panel/restore_helper.py               |  154 +++++
 panel/schemas.py                      |   68 +++
 panel/static/app.js                   |  490 +++++++++++++++-
 panel/templates/app.html              |  359 +++++++++++-
 panel/tg_bots.py                      |  235 +++++++-
 panel/xray_config.py                  |   19 +-
 scripts/weekly_ai_audit.py            |  128 ++++
 tests/test_backups.py                 |  140 +++++
 tests/test_hysteria_hot_auth.py       |   56 +-
 tests/test_session_security.py        |  135 +++++
 tests/test_upgrade_queue_rounds.py    |   94 +++
 tests/test_upgrade_status.py          |   34 ++
 tests/test_uptime_history.py          |   77 +++
 24 files changed, 4744 insertions(+), 316 deletions(-)
```

## Automated tests

```text
EE......EEEEEE
======================================================================
ERROR: test_agent_port_conflicts (unittest.loader._FailedTest.test_agent_port_conflicts)
----------------------------------------------------------------------
ImportError: Failed to import test module: test_agent_port_conflicts
Traceback (most recent call last):
  File "/usr/lib/python3.12/unittest/loader.py", line 394, in _find_test_path
    module = self._get_module_from_name(name)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/unittest/loader.py", line 337, in _get_module_from_name
    __import__(name)
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/tests/test_agent_port_conflicts.py", line 7, in <module>
    from fastapi import HTTPException
ModuleNotFoundError: No module named 'fastapi'


======================================================================
ERROR: test_backups (unittest.loader._FailedTest.test_backups)
----------------------------------------------------------------------
ImportError: Failed to import test module: test_backups
Traceback (most recent call last):
  File "/usr/lib/python3.12/unittest/loader.py", line 394, in _find_test_path
    module = self._get_module_from_name(name)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/unittest/loader.py", line 337, in _get_module_from_name
    __import__(name)
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/tests/test_backups.py", line 13, in <module>
    from panel import backups
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/panel/backups.py", line 36, in <module>
    import httpx
ModuleNotFoundError: No module named 'httpx'


======================================================================
ERROR: test_hysteria_hot_auth (unittest.loader._FailedTest.test_hysteria_hot_auth)
----------------------------------------------------------------------
ImportError: Failed to import test module: test_hysteria_hot_auth
Traceback (most recent call last):
  File "/usr/lib/python3.12/unittest/loader.py", line 394, in _find_test_path
    module = self._get_module_from_name(name)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/unittest/loader.py", line 337, in _get_module_from_name
    __import__(name)
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/tests/test_hysteria_hot_auth.py", line 9, in <module>
    from agent import agent
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/agent/agent.py", line 68, in <module>
    from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
ModuleNotFoundError: No module named 'fastapi'


======================================================================
ERROR: test_protocol_subscriptions (unittest.loader._FailedTest.test_protocol_subscriptions)
----------------------------------------------------------------------
ImportError: Failed to import test module: test_protocol_subscriptions
Traceback (most recent call last):
  File "/usr/lib/python3.12/unittest/loader.py", line 394, in _find_test_path
    module = self._get_module_from_name(name)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/unittest/loader.py", line 337, in _get_module_from_name
    __import__(name)
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/tests/test_protocol_subscriptions.py", line 8, in <module>
    from panel.app import (
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/panel/app.py", line 55, in <module>
    import pyotp
ModuleNotFoundError: No module named 'pyotp'


======================================================================
ERROR: test_session_security (unittest.loader._FailedTest.test_session_security)
----------------------------------------------------------------------
ImportError: Failed to import test module: test_session_security
Traceback (most recent call last):
  File "/usr/lib/python3.12/unittest/loader.py", line 394, in _find_test_path
    module = self._get_module_from_name(name)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/unittest/loader.py", line 337, in _get_module_from_name
    __import__(name)
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/tests/test_session_security.py", line 8, in <module>
    from agent import agent
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/agent/agent.py", line 68, in <module>
    from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
ModuleNotFoundError: No module named 'fastapi'


======================================================================
ERROR: test_upgrade_queue_rounds (unittest.loader._FailedTest.test_upgrade_queue_rounds)
----------------------------------------------------------------------
ImportError: Failed to import test module: test_upgrade_queue_rounds
Traceback (most recent call last):
  File "/usr/lib/python3.12/unittest/loader.py", line 394, in _find_test_path
    module = self._get_module_from_name(name)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/unittest/loader.py", line 337, in _get_module_from_name
    __import__(name)
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/tests/test_upgrade_queue_rounds.py", line 6, in <module>
    from panel import app as panel_app
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/panel/app.py", line 55, in <module>
    import pyotp
ModuleNotFoundError: No module named 'pyotp'


======================================================================
ERROR: test_upgrade_status (unittest.loader._FailedTest.test_upgrade_status)
----------------------------------------------------------------------
ImportError: Failed to import test module: test_upgrade_status
Traceback (most recent call last):
  File "/usr/lib/python3.12/unittest/loader.py", line 394, in _find_test_path
    module = self._get_module_from_name(name)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/unittest/loader.py", line 337, in _get_module_from_name
    __import__(name)
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/tests/test_upgrade_status.py", line 6, in <module>
    from agent import agent
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/agent/agent.py", line 68, in <module>
    from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
ModuleNotFoundError: No module named 'fastapi'


======================================================================
ERROR: test_uptime_history (unittest.loader._FailedTest.test_uptime_history)
----------------------------------------------------------------------
ImportError: Failed to import test module: test_uptime_history
Traceback (most recent call last):
  File "/usr/lib/python3.12/unittest/loader.py", line 394, in _find_test_path
    module = self._get_module_from_name(name)
             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/usr/lib/python3.12/unittest/loader.py", line 337, in _get_module_from_name
    __import__(name)
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/tests/test_uptime_history.py", line 7, in <module>
    from panel import app as panel_app
  File "/home/runner/work/xray-reality-installer/xray-reality-installer/panel/app.py", line 55, in <module>
    import pyotp
ModuleNotFoundError: No module named 'pyotp'


----------------------------------------------------------------------
Ran 14 tests in 0.001s

FAILED (errors=8)
```

## AI review

AI review failed (HTTPError); deterministic report retained.

> Credentials and raw API responses are never stored in this report.
