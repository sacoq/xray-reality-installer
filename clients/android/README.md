# Branded Android client (white-labelled Hiddify-Next)

This directory turns [`hiddify-app`](https://github.com/hiddify/hiddify-app)
(the cross-platform Flutter app behind Hiddify-Next, which already speaks
VLESS+Reality, sing-box, urltest, etc.) into **your own branded Android VPN
client**, with:

- **Hidden servers.** The app ships with your panel's subscription URL
  hard-coded. Users never see hostnames, IPs, or "add subscription" UI.
  All the "add profile / paste URL" buttons are removed; the app
  auto-imports the preset on first launch.
- **Custom branding.** App name, package ID, deeplink scheme, primary /
  accent colours, support links, launcher icon — all driven from a single
  YAML config.
- **Auto vs Manual modes for free.** Hiddify already renders sing-box
  `urltest` selectors as "auto-pick fastest" and any other `selector`
  outbound as "pick a location manually" out of the box. Your panel
  builds these in `_render_singbox()` (see
  `panel/sub_page.py`), so as long as your subscription contains a
  `urltest` outbound + a list of named locations, the app picks them up
  automatically and the user gets one toggle per group.
- **Custom deeplinks.** `myvpn://import?url=...`,
  `myvpn://activate?token=...`, etc. — registered as Android intent
  filters; usable from your Telegram bot, your `/page/<token>` landing,
  or anywhere else.

> ⚠️ **License**: Hiddify-Next is **GPL-3.0**. Forking it means
> *your fork must also be GPL-3.0* and you have to make the source
> available *to anyone who installs your APK and asks for it*. You don't
> have to publish the source proactively — just hand it over on request.
> If you need a fully closed-source app, you have to write one from
> scratch (a few months of work). Most boutique VPN brands run with
> GPL-3.0 forks; this is fine and not a meaningful business risk.

---

## What's in this directory

| Path                         | What                                                             |
| ---------------------------- | ---------------------------------------------------------------- |
| `whitelabel.py`              | Driver script — clones hiddify-app, applies branding + patches   |
| `config.example.yaml`        | Template config with every available knob commented              |
| `patches/*.patch`            | Code patches: hide "add profile" UI, auto-import preset on boot  |
| `branding/`                  | Drop your icon / splash / banner here (PNG, see below)           |

The script generates `lib/core/whitelabel/preset.dart` inside the
hiddify-app checkout — that file is the single source of truth for the
preset subscription URL and brand constants at runtime.

---

## End-to-end build

### 0. One-time host setup (Linux / macOS)

The build needs Flutter 3.38.x, Dart 3.10.x, Android SDK 36, NDK
28.2.13676358, JDK 17. The exact versions are pinned in
`hiddify-app/pubspec.yaml` — don't substitute newer ones blindly.

```bash
# Java 17
sudo apt-get install -y openjdk-17-jdk
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# Flutter (use the pinned version)
git clone --depth 1 --branch 3.38.5 https://github.com/flutter/flutter.git ~/flutter
export PATH="$HOME/flutter/bin:$PATH"
flutter --version

# Android SDK (cmdline-tools)
mkdir -p ~/Android/Sdk/cmdline-tools
cd ~/Android/Sdk/cmdline-tools
wget -O cmdline.zip https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip
unzip cmdline.zip && mv cmdline-tools latest && rm cmdline.zip
export ANDROID_HOME=~/Android/Sdk
export PATH="$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$PATH"

# Accept licences + install required packages
yes | sdkmanager --licenses
sdkmanager "platform-tools" "platforms;android-36" "build-tools;36.0.0" \
           "ndk;28.2.13676358" "cmake;3.22.1"
flutter doctor --android-licenses
flutter doctor          # everything should be green for Android
```

> **Windows users**: install Flutter via [`winget install Flutter.Flutter`](https://flutter.dev/docs/get-started/install/windows)
> and Android Studio (it bundles SDK + NDK). The rest of the script is
> Python and works the same.

### 1. Configure your brand

```bash
cd clients/android
cp config.example.yaml config.yaml
$EDITOR config.yaml   # set brand_name, package_id, preset_subscription_url, etc.
```

The most important field is `preset_subscription_url`: point it at your
panel's subscription endpoint, e.g.
`https://panel.example.com/sub/abc123def456`.

### 2. (Optional) Drop your brand assets

Put a 1024×1024 PNG launcher icon at `branding/icon-1024.png`. The
script copies it into all five mipmap density directories. For
production-quality icons, render per-density yourself and replace
`android/app/src/main/res/mipmap-*/ic_launcher.png` after running the
script.

If you skip this step, the app keeps the upstream Hiddify icon — easy
to recognise during testing, *do not ship like this.*

### 3. Run the white-labeller

```bash
pip install pyyaml
python3 whitelabel.py
```

This:

1. Clones `hiddify-app` at the pinned tag into `./hiddify-app/`.
2. Renames `Hiddify` → your `brand_name` everywhere user-visible.
3. Renames `com.hiddify.hiddify` → your `package_id` (Kotlin namespace +
   directory layout) and `app.hiddify.com` → your `application_id`.
4. Adds your custom deeplink scheme to `AndroidManifest.xml`.
5. Writes `lib/core/whitelabel/preset.dart` with the preset URL +
   brand constants.
6. Applies patches from `patches/` to hide "add profile" UI.
7. Copies launcher icons from `branding/` if present.

It's idempotent on a *fresh clone* — to rerun it, delete the
`hiddify-app/` directory first.

### 4. Build the APK

```bash
cd hiddify-app
flutter pub get
dart run build_runner build --delete-conflicting-outputs
flutter build apk --release --split-per-abi
```

The split-per-abi build produces three APKs in
`build/app/outputs/flutter-apk/`:

- `app-armeabi-v7a-release.apk` (~old phones)
- `app-arm64-v8a-release.apk` (~most modern Android phones, ship this)
- `app-x86_64-release.apk` (emulators / Chromebooks)

For Play Store / RuStore upload, use App Bundle:

```bash
flutter build appbundle --release
# -> build/app/outputs/bundle/release/app-release.aab
```

### 5. Sign the release APK

For testing it's fine to install the unsigned debug APK with
`flutter install`. For distribution, generate a release keystore once
and reuse it forever:

```bash
keytool -genkey -v -keystore ~/myvpn-release.jks \
  -keyalg RSA -keysize 2048 -validity 10000 -alias myvpn

# put the credentials in hiddify-app/android/key.properties (mode 600):
cat > hiddify-app/android/key.properties <<EOF
storePassword=...
keyPassword=...
keyAlias=myvpn
storeFile=/home/you/myvpn-release.jks
EOF
chmod 600 hiddify-app/android/key.properties
```

The `android/app/build.gradle` already picks this up automatically when
the file exists.

> **Back up the keystore** somewhere durable. Lose it and you cannot
> publish updates to the same RuStore / Play Store listing — you'll
> have to publish a new app from scratch.

---

## Distribution

### Sideloading

Easiest path while you're iterating: send the signed APK to users
directly (Telegram bot, website, QR code). Android requires "install
from unknown sources" toggle — deeplink the user straight to the
permission page if they haven't granted it.

### RuStore

[https://www.rustore.ru/help/developers/](https://www.rustore.ru/help/developers/)

You need:

- ИП / самозанятый аккаунт + ФЗ-152 согласие
- App icon 512×512 PNG, screenshots 320–3840 px wide
- Privacy policy URL (the `privacy_url` in `config.yaml`) — must be a
  real, publicly-reachable page

VPN apps need extra moderation but are not rejected by default.

### Galaxy Store / 1Mobile

Galaxy Store is a fast alternative for Russian users
([https://seller.samsungapps.com/](https://seller.samsungapps.com/));
1Mobile and APKPure also accept VPN apps if you sign up.

### Google Play

Play Store has been hostile to direct VLESS/Reality clients lately, but
white-labelled Hiddify-Next forks still slip through if you (a) keep
the binary clean and (b) market it as a "secure proxy client", not "a
way to bypass censorship". Use App Bundle (`flutter build appbundle`)
for Play.

### TestFlight (iOS)

Out of scope for this directory. Hiddify-Next supports iOS but iOS
distribution requires a Mac, an Apple Developer Program seat (\$99/year),
and TestFlight invites — none of which this script automates.

---

## How "Auto" / "Manual" mode works in this build

You don't need to write any UI code for this — Hiddify-Next already
honours sing-box `urltest` and `selector` outbounds. The trick is to
build the right subscription on the panel side.

In `panel/sub_page.py` (or `panel/app.py:_render_singbox`), shape the
sing-box config like this:

```jsonc
{
  "outbounds": [
    {
      "type": "selector",
      "tag": "Auto / Manual",
      "outbounds": ["⚡ Auto", "🇩🇪 Germany", "🇫🇮 Finland", "🇷🇺 Moscow front"],
      "default": "⚡ Auto"
    },
    {
      "type": "urltest",
      "tag": "⚡ Auto",
      "outbounds": ["🇩🇪 Germany", "🇫🇮 Finland", "🇷🇺 Moscow front"],
      "url": "https://www.gstatic.com/generate_204",
      "interval": "30s"
    },
    { "type": "vless", "tag": "🇩🇪 Germany", /* ... */ },
    { "type": "vless", "tag": "🇫🇮 Finland", /* ... */ },
    { "type": "vless", "tag": "🇷🇺 Moscow front", /* ... */ }
  ]
}
```

The Hiddify UI then shows:

- A `Auto / Manual` group → tap it to choose the active outbound
- An `⚡ Auto` urltest item → when selected, sing-box auto-picks the
  fastest server every 30 s
- Three named locations → manual override

The user toggles between auto and manual just by tapping a different
entry in the group — no extra UI to write. Hostnames / IPs are *not*
shown by the app for VLESS outbounds, only the friendly tag.

> The current panel code in `panel/app.py:_render_singbox` already
> emits `urltest` for balancer pools and `selector` for whitelist
> fronts. If your subscription is plain (single-server), the app shows
> a single "direct" entry with no Auto/Manual UI — that's expected.
> Group your servers into a balancer pool from the panel UI to get the
> dual-mode UX.

---

## Troubleshooting

### `flutter pub get` fails on `hiddify-core`

`hiddify-app/hiddify-core` is a git submodule pointing at a private
mirror over SSH. The script doesn't touch it, but you may need to:

```bash
cd hiddify-app
git submodule update --init --recursive
# or, if the SSH URL is unreachable:
git config submodule.hiddify-core.url https://github.com/hiddify/hiddify-core.git
git submodule sync
git submodule update --init
```

### `dart run build_runner build` fails

Usually this means generated code is out of sync. Always run with
`--delete-conflicting-outputs`. If a specific generator complains
about missing imports, double-check that `lib/core/whitelabel/preset.dart`
exists — it's the single new source file the app depends on.

### Patches fail to apply

The `patches/*.patch` files are pinned against `upstream_ref` in
config. If you bumped `upstream_ref` and a patch fails:

```bash
cd hiddify-app
git apply --3way --reject ../patches/03-hide-home-add-button.patch
# fix the .rej hunks by hand, then re-export:
git diff lib/features/home/widget/home_page.dart > ../patches/03-hide-home-add-button.patch
```

### App crashes on launch with "no profile imported"

Check that `preset_subscription_url` in your config:

1. Resolves from the device (curl it from a phone on cellular).
2. Returns a base64-encoded subscription (your panel's `/sub/<token>`
   does this by default — verify with `curl -s URL | base64 -d`).
3. Is reachable over HTTPS — Android refuses cleartext HTTP by default.

The bootstrap step logs every step to logcat:

```bash
adb logcat -s flutter:V | grep -iE "preset|profile"
```

You should see `preset: importing https://...` followed by either
`preset: imported successfully` or a specific error.

---

## Updating to a newer Hiddify-Next

```bash
# 1. bump the version in config.yaml
upstream_ref: "v4.1.3"

# 2. wipe the old checkout and re-run
rm -rf hiddify-app
python3 whitelabel.py

# 3. if a patch fails, re-export it (see Troubleshooting above) and
#    commit the updated .patch back to this directory.
```

The Constants.dart, build.gradle, AndroidManifest.xml, and Kotlin
package rename are *string-replacements*, not patches, so they're
robust against upstream churn. Patches only target the four
`hide-add-profile` / `auto-import-preset` files.
