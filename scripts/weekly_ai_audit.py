"""Generate a week-over-week project audit with an optional free AI review."""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parents[1]
REPORT_DIR = ROOT / "reports" / "weekly"
MAX_CONTEXT = 120_000


def run(*args: str) -> tuple[int, str]:
    proc = subprocess.run(
        args,
        cwd=ROOT,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=180,
        check=False,
    )
    return proc.returncode, (proc.stdout or "").strip()


def ask_gemini(prompt: str, key: str) -> str:
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        "gemini-2.5-flash:generateContent?key=" + key
    )
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as response:
        data = json.load(response)
    return data["candidates"][0]["content"]["parts"][0]["text"].strip()


def ask_github_models(prompt: str, token: str) -> str:
    req = urllib.request.Request(
        "https://models.github.ai/inference/chat/completions",
        data=json.dumps({
            "model": "openai/gpt-4o",
            "messages": [
                {"role": "system", "content": "You are a careful senior code reviewer. Do not invent facts."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.1,
            "max_tokens": 3000,
        }).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer " + token,
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as response:
        data = json.load(response)
    return data["choices"][0]["message"]["content"].strip()


def build_context() -> tuple[str, str, str, str]:
    _, head = run("git", "rev-parse", "HEAD")
    _, baseline = run("git", "rev-list", "-n1", "--before=7 days ago", "HEAD")
    baseline = baseline or head
    _, log = run(
        "git", "log", "--since=7 days ago", "--date=short",
        "--pretty=format:%h %ad %s",
    )
    _, stat = run("git", "diff", "--stat", f"{baseline}..HEAD", "--", ":!reports/weekly")
    _, diff = run("git", "diff", f"{baseline}..HEAD", "--", ":!reports/weekly")
    _, files = run("git", "ls-files")
    if len(diff) > MAX_CONTEXT:
        diff = diff[:MAX_CONTEXT] + "\n\n[diff truncated for model context]"
    context = (
        f"Repository: {ROOT.name}\nHEAD: {head}\nBaseline (before 7 days): {baseline}\n\n"
        f"Tracked files:\n{files}\n\nCommits in the last week:\n{log or '(none)'}\n\n"
        f"Diff stat:\n{stat or '(no code changes)'}\n\nDiff:\n{diff or '(no diff)'}"
    )
    return head, baseline, stat, context


def main() -> int:
    now = datetime.now(timezone.utc)
    head, baseline, stat, context = build_context()
    test_code, tests = run(sys.executable, "-m", "unittest", "discover", "-s", "tests")
    prompt = (
        "Review the following VPN panel repository for a weekly engineering audit. "
        "Compare HEAD to the baseline, identify regressions, security or privacy "
        "risks, operational risks, missing tests, and three prioritized next actions. "
        "Be concise and evidence-based. Do not repeat secrets or tokens.\n\n"
        + context
        + f"\n\nAutomated test exit code: {test_code}\nAutomated test output:\n{tests[-20_000:]}"
    )
    ai_text = "AI review was unavailable; see the deterministic comparison below."
    provider = "deterministic-only"
    try:
        gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY_FALLBACK")
        if gemini_key:
            ai_text = ask_gemini(prompt, gemini_key)
            provider = "gemini-2.5-flash"
        elif os.environ.get("GITHUB_TOKEN"):
            ai_text = ask_github_models(prompt, os.environ["GITHUB_TOKEN"])
            provider = "github-models/openai-gpt-4o"
    except (OSError, KeyError, ValueError, urllib.error.URLError, json.JSONDecodeError) as exc:
        ai_text = f"AI review failed ({type(exc).__name__}); deterministic report retained."

    report = f"""# Weekly project audit — {now.strftime('%Y-%m-%d')}\n\n- **HEAD:** `{head}`\n- **Baseline:** `{baseline}`\n- **AI provider:** `{provider}`\n- **Tests exit code:** `{test_code}`\n\n## Week-over-week change summary\n\n```text\n{stat or '(no code changes)'}\n```\n\n## Automated tests\n\n```text\n{tests[-20_000:]}\n```\n\n## AI review\n\n{ai_text}\n\n> Credentials and raw API responses are never stored in this report.\n"""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    (REPORT_DIR / f"{now.strftime('%Y-%m-%d')}.md").write_text(report, encoding="utf-8")
    (REPORT_DIR / "latest.md").write_text(report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
