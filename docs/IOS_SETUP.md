# CipherLine — iOS Build Setup

iOS builds require **macOS with Xcode** installed. The `cargo tauri ios init`
command is only available on macOS.

## Prerequisites

- macOS 13+ (Ventura or later)
- Xcode 15+ with iOS SDK
- Rust iOS targets (already installed via `rustup target add`):
  - `aarch64-apple-ios`
  - `x86_64-apple-ios`
  - `aarch64-apple-ios-sim`
- CocoaPods: `sudo gem install cocoapods`

## One-time Setup (on macOS)

```bash
# Clone the repo and navigate to it
cd cipherline

# Initialize the iOS project
cargo tauri ios init

# The generated project will appear in src-tauri/gen/apple/
```

## Building

```bash
# Development build (simulator)
cargo tauri ios dev

# Release build
cargo tauri ios build
```

## Keychain Access

The iOS build uses the `keyring` crate with `apple-native` feature, which
delegates to the iOS Keychain. This provides hardware-backed key storage
via the Secure Enclave on compatible devices.

## Push Notifications (APNs)

1. Enable Push Notifications capability in Xcode
2. Create an APNs key in Apple Developer Portal
3. Configure the push server endpoint in the relay
4. The app uses `tauri-plugin-notification` which handles APNs registration

## Notes

- SQLCipher builds natively on iOS via the `bundled-sqlcipher` feature
- The `cdylib` and `staticlib` crate types are configured in Cargo.toml
- All Rust cross-compilation targets are pre-installed
