# Android Build Guide

CipherLine Android is built using Tauri Mobile, producing a native APK with the same Rust cryptographic backend as the desktop client.

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Rust | stable (latest) | With `aarch64-linux-android` target |
| Tauri CLI | 2.x | `cargo install tauri-cli --version "^2" --locked` |
| Android SDK | API 24+ | Via Android Studio or `sdkmanager` |
| Android NDK | r25+ | Required for Rust cross-compilation |
| Java JDK | 17 | Required by Gradle |
| OpenSSL | 3.x (host) | For `bundled-sqlcipher` compilation |

### Environment Variables

Ensure these are set:

```sh
export ANDROID_HOME=/path/to/android/sdk
export NDK_HOME=$ANDROID_HOME/ndk/<version>
```

### Rust Target

```sh
rustup target add aarch64-linux-android
```

---

## Building

### Debug APK

```sh
cargo tauri android dev
```

### Release APK

```sh
cargo tauri android build --apk
```

The APK is written to `src-tauri/gen/android/app/build/outputs/apk/`.

> **Note:** The CI pipeline builds only the `aarch64-linux-android` target to avoid OpenSSL cross-compilation issues with multiple architectures.

---

## Signing

### Keystore

A release keystore is required for signed APKs. Generate one with:

```sh
keytool -genkey -v \
  -keystore cipherline-release.keystore \
  -alias cipherline \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -storepass <password> \
  -keypass <password>
```

### CI/CD Signing

The GitHub Actions release workflow uses these secrets:

| Secret | Description |
|--------|-------------|
| `ANDROID_KEYSTORE_PASSWORD` | Keystore password |
| `ANDROID_KEY_PASSWORD` | Key alias password |

The keystore file should be base64-encoded and stored as a secret, or committed in an encrypted form.

### Security

- **Never** commit an unencrypted keystore to version control
- Store keystore passwords only in GitHub Secrets or a secure vault
- The `.gitignore` already excludes `*.keystore` files

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| NDK not found | Set `NDK_HOME` or install via `sdkmanager --install "ndk;25.2.9519653"` |
| OpenSSL errors during cross-compile | The `bundled-sqlcipher` feature compiles OpenSSL from source. Ensure your host has a C compiler and `perl` (for OpenSSL's configure script). |
| Gradle build fails | Verify Java 17 is installed: `java --version`. Set `JAVA_HOME` if needed. |
| APK installs but crashes | Check `adb logcat` for panics. Common cause: missing native library for the device's ABI. |
| Multiple ABI build fails | Build only for `aarch64`: the CI pipeline restricts to this target for OpenSSL compatibility. |
| `cargo clean` needed | If incremental builds fail after target changes, run `cargo clean` and rebuild. |

---

## Release Checklist

- [ ] Build release APK: `cargo tauri android build --apk`
- [ ] Sign APK with release keystore
- [ ] Test on physical device (ARM64)
- [ ] Verify end-to-end encryption works (send/receive messages)
- [ ] Verify relay connectivity
- [ ] Check SQLCipher database encryption
- [ ] Update version in `Cargo.toml` and `tauri.conf.json`
- [ ] Tag release and push to trigger CI/CD
