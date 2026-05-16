# Branding assets

Drop your brand assets in this directory — `whitelabel.py` picks them
up automatically.

## Expected files

| File                    | Format          | Used for                                                                  |
| ----------------------- | --------------- | ------------------------------------------------------------------------- |
| `icon-1024.png`         | 1024×1024 PNG   | Android launcher icon (copied into all five mipmap-* density directories) |
| `splash-light.png`      | 512×512+ PNG    | Light-mode splash centre image (configure with flutter_native_splash)     |
| `splash-dark.png`       | 512×512+ PNG    | Dark-mode splash                                                          |
| `banner.png`            | 320×180 PNG     | Android TV / leanback launcher banner                                     |

## Quality notes

The 1024×1024 PNG → mipmap copy is a *placeholder* for early testing.
For production:

1. Render the icon **per density** (mdpi 48px, hdpi 72px, xhdpi 96px,
   xxhdpi 144px, xxxhdpi 192px) using a vector source.
2. Run `flutter_launcher_icons` against your config — that handles
   adaptive icons, monochrome icons (Android 13+), and round variants.
3. Replace the round variant separately at
   `android/app/src/main/res/mipmap-*/ic_launcher_round.png`.

## Splash configuration

The Hiddify-Next codebase already includes `flutter_native_splash` as a
dependency. To regenerate splashes after adding `splash-light.png` /
`splash-dark.png`, edit the `flutter_native_splash:` block in
`hiddify-app/pubspec.yaml` to point at your assets, then run:

```bash
cd hiddify-app
dart run flutter_native_splash:create
```

(Doing this from the white-labeller is on the roadmap — for now, a
manual one-liner is the simplest path.)
