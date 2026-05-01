#!/usr/bin/env python3
"""White-label Hiddify-Next into a branded Android VPN client.

Reads a YAML config (``config.yaml`` by default) and turns a fresh clone of
``hiddify/hiddify-app`` into your branded fork in-place.

What it does
------------

1. Optionally clones ``hiddify/hiddify-app`` at a pinned commit / tag into
   ``--repo`` (default ``./hiddify-app``).
2. Renames the app:
   * ``Hiddify`` → ``brand_name`` (everywhere it's user-visible)
   * ``com.hiddify.hiddify`` → ``package_id`` (Kotlin namespace)
   * ``app.hiddify.com`` → ``application_id`` (Android applicationId)
   * Moves ``android/app/src/main/kotlin/com/hiddify/hiddify`` to the new
     package path.
3. Adds the custom deeplink scheme to ``AndroidManifest.xml``.
4. Writes ``lib/core/whitelabel/preset.dart`` with the hardcoded preset
   subscription URL + brand colours.
5. Applies ``patches/*.patch`` (in alphabetical order) for structural
   code changes — hide "add profile" UI, auto-import preset subscription
   on first launch, etc.
6. Replaces brand assets from ``branding/`` (icon, splash, banner) into
   the right Flutter asset paths.

This is *idempotent on a fresh clone* and *not* idempotent on an already
white-labelled tree — always run it on a clean checkout.

Usage
-----
    python3 whitelabel.py
    python3 whitelabel.py --config my.yaml --repo ./hiddify-app

Then build the APK with::

    cd hiddify-app
    flutter pub get
    dart run build_runner build --delete-conflicting-outputs
    flutter build apk --release --split-per-abi

See ``README.md`` for the full setup including Flutter / Android SDK and
signing the release APK.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import yaml
except ImportError:
    print(
        "PyYAML is required.  Install with: pip install pyyaml",
        file=sys.stderr,
    )
    sys.exit(1)


HERE = Path(__file__).resolve().parent


# ---------- config ----------


@dataclass
class WLConfig:
    brand_name: str
    package_id: str       # e.g. com.myvpn.app — used in Kotlin namespace
    application_id: str   # e.g. app.myvpn.com — used in Android applicationId
    deeplink_scheme: str
    preset_subscription_url: str
    primary_color: str    # hex, e.g. #1976D2
    accent_color: str     # hex
    support_url: str
    privacy_url: str
    terms_url: str
    telegram_url: str
    upstream_repo: str = "https://github.com/hiddify/hiddify-app.git"
    upstream_ref: str = "v4.1.2"

    @classmethod
    def load(cls, path: Path) -> "WLConfig":
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        # apply defaults
        return cls(**{f: data.get(f, getattr(cls, f, None)) for f in cls.__annotations__})


# ---------- helpers ----------


def run(cmd: list[str], cwd: Path | None = None, check: bool = True) -> subprocess.CompletedProcess:
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, cwd=cwd, check=check)


def ensure_repo(cfg: WLConfig, repo: Path) -> None:
    if repo.exists() and (repo / ".git").exists():
        print(f"[skip] {repo} already exists")
        return
    print(f"[clone] {cfg.upstream_repo} @ {cfg.upstream_ref}")
    run(["git", "clone", "--depth", "1", "--branch", cfg.upstream_ref, cfg.upstream_repo, str(repo)])


def replace_in_file(path: Path, replacements: list[tuple[str, str]]) -> bool:
    if not path.exists() or path.is_dir():
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return False
    new_text = text
    for old, new in replacements:
        new_text = new_text.replace(old, new)
    if new_text != text:
        path.write_text(new_text, encoding="utf-8")
        return True
    return False


def walk_replace(root: Path, replacements: list[tuple[str, str]], suffixes: tuple[str, ...]) -> int:
    n = 0
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if not any(str(p).endswith(s) for s in suffixes):
            continue
        if replace_in_file(p, replacements):
            n += 1
    return n


# ---------- steps ----------


def step_string_rename(repo: Path, cfg: WLConfig) -> None:
    """Rename Hiddify → brand_name + package id everywhere it matters.

    We're conservative: we don't touch every "hiddify" string (lots of
    those are internal class names like HiddifyCoreService).  We only
    rewrite the ones that are user-visible OR Android-package-related.
    """
    print("[rename] strings")

    common = [
        # User-visible app title (translations + Android <application label>).
        ('"appTitle": "Hiddify"', f'"appTitle": "{cfg.brand_name}"'),
        ('android:label="Hiddify"', f'android:label="{cfg.brand_name}"'),
        # Brand mentions in localized strings (hand-picked - the rest stay).
        (
            'Made with ❤ by Hiddify',
            f'Powered by {cfg.brand_name}',
        ),
    ]
    n = walk_replace(repo, common, (".json", ".xml", ".dart", ".plist"))
    print(f"  patched {n} files (user-visible strings)")

    # Constants.dart - the canonical place for app name + brand URLs.
    const = repo / "lib/core/model/constants.dart"
    replace_in_file(
        const,
        [
            ('static const appName = "Hiddify";', f'static const appName = "{cfg.brand_name}";'),
            (
                'static const githubUrl = "https://github.com/hiddify/hiddify-next";',
                f'static const githubUrl = "{cfg.support_url}";',
            ),
            (
                'static const licenseUrl = "https://github.com/hiddify/hiddify-next?tab=License-1-ov-file#readme";',
                f'static const licenseUrl = "{cfg.support_url}";',
            ),
            (
                'static const githubReleasesApiUrl = "https://api.github.com/repos/hiddify/hiddify-next/releases";',
                'static const githubReleasesApiUrl = "";',
            ),
            (
                'static const githubLatestReleaseUrl = "https://github.com/hiddify/hiddify-app/releases/latest";',
                'static const githubLatestReleaseUrl = "";',
            ),
            (
                'static const appCastUrl = "https://raw.githubusercontent.com/hiddify/hiddify-next/main/appcast.xml";',
                'static const appCastUrl = "";',
            ),
            (
                'static const telegramChannelUrl = "https://t.me/hiddify";',
                f'static const telegramChannelUrl = "{cfg.telegram_url}";',
            ),
            (
                'static const privacyPolicyUrl = "https://hiddify.com/privacy-policy/";',
                f'static const privacyPolicyUrl = "{cfg.privacy_url}";',
            ),
            (
                'static const termsAndConditionsUrl = "https://hiddify.com/terms/";',
                f'static const termsAndConditionsUrl = "{cfg.terms_url}";',
            ),
        ],
    )

    # Android applicationId.
    replace_in_file(
        repo / "android/app/build.gradle",
        [
            ('namespace \'com.hiddify.hiddify\'', f'namespace \'{cfg.package_id}\''),
            ('testNamespace "test.com.hiddify.hiddify"', f'testNamespace "test.{cfg.package_id}"'),
            ('applicationId "app.hiddify.com"', f'applicationId "{cfg.application_id}"'),
        ],
    )

    # pubspec name (Flutter project name) — keep as "hiddify" because changing
    # it would require regenerating freezed/riverpod codegen output for *every*
    # generated import.  The user never sees this.

    print("[rename] Constants.dart and android/app/build.gradle done")


def step_kotlin_rename(repo: Path, cfg: WLConfig) -> None:
    print("[kotlin] move package directory")
    src_kotlin = repo / "android/app/src/main/kotlin/com/hiddify/hiddify"
    if not src_kotlin.exists():
        print(f"  warn: {src_kotlin} doesn't exist (already moved?)")
        return
    pkg_path = cfg.package_id.replace(".", "/")
    dst_kotlin = repo / "android/app/src/main/kotlin" / pkg_path
    dst_kotlin.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src_kotlin), str(dst_kotlin))

    # Drop empty intermediate dirs (com/hiddify/).
    for parent in [repo / "android/app/src/main/kotlin/com/hiddify", repo / "android/app/src/main/kotlin/com"]:
        try:
            parent.rmdir()
        except OSError:
            pass

    # Rewrite `package` and `import` statements in all .kt files.
    n = walk_replace(
        repo,
        [
            ("com.hiddify.hiddify", cfg.package_id),
        ],
        (".kt", ".java", ".xml", ".gradle"),
    )
    print(f"  rewrote {n} files referencing com.hiddify.hiddify")


def step_deeplink_scheme(repo: Path, cfg: WLConfig) -> None:
    print(f"[deeplink] adding scheme {cfg.deeplink_scheme}://")
    manifest = repo / "android/app/src/main/AndroidManifest.xml"
    text = manifest.read_text(encoding="utf-8")
    needle = '<data android:scheme="hiddify" />'
    if needle in text and f'<data android:scheme="{cfg.deeplink_scheme}" />' not in text:
        text = text.replace(
            needle,
            f'<data android:scheme="{cfg.deeplink_scheme}" />\n                <data android:scheme="hiddify" />',
        )
        manifest.write_text(text, encoding="utf-8")
        print(f"  added <data android:scheme=\"{cfg.deeplink_scheme}\" />")
    else:
        print("  skip (already present)")


def step_preset_subscription(repo: Path, cfg: WLConfig) -> None:
    print("[preset] writing whitelabel/preset.dart")
    out = repo / "lib/core/whitelabel/preset.dart"
    out.parent.mkdir(parents=True, exist_ok=True)
    json_url = json.dumps(cfg.preset_subscription_url)
    json_brand = json.dumps(cfg.brand_name)
    json_primary = json.dumps(cfg.primary_color)
    json_accent = json.dumps(cfg.accent_color)
    json_deeplink = json.dumps(cfg.deeplink_scheme)
    out.write_text(
        f"""// AUTO-GENERATED by clients/android/whitelabel.py — do not edit by hand.
// Regenerate with: python3 whitelabel.py

import 'package:flutter/material.dart';

abstract class WhitelabelConfig {{
  /// Hard-coded subscription URL the app imports automatically on first launch.
  /// Users never see or edit it.  Change this by re-running whitelabel.py.
  static const String presetSubscriptionUrl = {json_url};

  /// User-visible brand name (also used as the imported profile's name).
  static const String brandName = {json_brand};

  /// Custom URL scheme — registered as an Android intent filter, used by
  /// deeplinks like {cfg.deeplink_scheme}://import?url=...
  static const String deeplinkScheme = {json_deeplink};

  /// Brand primary colour.
  static Color get primary => _hex({json_primary});

  /// Brand accent colour.
  static Color get accent => _hex({json_accent});

  /// True when the app is white-labelled and should hide
  /// "add profile / manage subscriptions" UI.
  static const bool hideProfileManagement = true;

  static Color _hex(String s) {{
    final cleaned = s.replaceFirst('#', '');
    final value = int.parse(cleaned, radix: 16);
    return Color(0xFF000000 | value);
  }}
}}
""",
        encoding="utf-8",
    )
    print(f"  wrote {out.relative_to(repo)}")


def step_apply_patches(repo: Path) -> None:
    patch_dir = HERE / "patches"
    if not patch_dir.exists():
        print("[patches] (no patches/ directory, skipping)")
        return
    patches = sorted(patch_dir.glob("*.patch"))
    if not patches:
        print("[patches] (none)")
        return
    print(f"[patches] applying {len(patches)} patch(es)")
    for p in patches:
        print(f"  applying {p.name}")
        # `git apply --3way` lets us tolerate small drift if upstream moved a few lines.
        run(["git", "apply", "--3way", "--whitespace=nowarn", str(p)], cwd=repo)


def step_branding(repo: Path) -> None:
    """Copy assets from branding/ into the right Flutter places.

    Drop your icon at ``branding/icon-1024.png`` (1024×1024 PNG) and
    splash assets at ``branding/splash-light.png`` /
    ``branding/splash-dark.png`` — see README.
    """
    brand = HERE / "branding"
    if not brand.exists():
        print("[branding] (no branding/ directory, skipping)")
        return
    # Adaptive icon foreground (Android).
    icon = brand / "icon-1024.png"
    if icon.exists():
        for size, mip in [
            ("48", "mdpi"),
            ("72", "hdpi"),
            ("96", "xhdpi"),
            ("144", "xxhdpi"),
            ("192", "xxxhdpi"),
        ]:
            for variant in ("ic_launcher.png", "ic_launcher_round.png"):
                dst = repo / f"android/app/src/main/res/mipmap-{mip}/{variant}"
                if dst.exists():
                    shutil.copyfile(icon, dst)
        # iOS / play store
        play = repo / "android/app/src/main/ic_launcher-playstore.png"
        if play.exists():
            shutil.copyfile(icon, play)
        print("  replaced launcher icons (placeholder — re-export per density for production)")
    else:
        print("  no branding/icon-1024.png — keeping default Hiddify icon")


def step_print_summary(cfg: WLConfig, repo: Path) -> None:
    print()
    print("=" * 60)
    print("White-label complete.  Next steps:")
    print("=" * 60)
    print(f"  Brand:           {cfg.brand_name}")
    print(f"  Package ID:      {cfg.package_id}")
    print(f"  applicationId:   {cfg.application_id}")
    print(f"  Deeplink:        {cfg.deeplink_scheme}://")
    print(f"  Preset sub URL:  {cfg.preset_subscription_url}")
    print()
    print(f"  Repo:            {repo}")
    print()
    print("Build:")
    print(f"  cd {repo}")
    print("  flutter pub get")
    print("  dart run build_runner build --delete-conflicting-outputs")
    print("  flutter build apk --release --split-per-abi")
    print()
    print("Output APKs land in build/app/outputs/flutter-apk/.")
    print()


# ---------- main ----------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--config", default=str(HERE / "config.yaml"), help="path to YAML config")
    ap.add_argument("--repo", default=str(HERE / "hiddify-app"), help="path to hiddify-app checkout")
    ap.add_argument("--skip-clone", action="store_true", help="don't clone, expect repo to already exist")
    ap.add_argument("--skip-rename", action="store_true")
    ap.add_argument("--skip-kotlin", action="store_true")
    ap.add_argument("--skip-deeplink", action="store_true")
    ap.add_argument("--skip-preset", action="store_true")
    ap.add_argument("--skip-patches", action="store_true")
    ap.add_argument("--skip-branding", action="store_true")
    args = ap.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.exists():
        print(f"config not found: {cfg_path}", file=sys.stderr)
        print(f"copy {HERE / 'config.example.yaml'} → {cfg_path} and fill it in", file=sys.stderr)
        return 1
    cfg = WLConfig.load(cfg_path)

    repo = Path(args.repo)
    if not args.skip_clone:
        ensure_repo(cfg, repo)

    if not args.skip_rename:
        step_string_rename(repo, cfg)
    if not args.skip_kotlin:
        step_kotlin_rename(repo, cfg)
    if not args.skip_deeplink:
        step_deeplink_scheme(repo, cfg)
    if not args.skip_preset:
        step_preset_subscription(repo, cfg)
    if not args.skip_patches:
        step_apply_patches(repo)
    if not args.skip_branding:
        step_branding(repo)

    step_print_summary(cfg, repo)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
