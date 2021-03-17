# @digitalbazaar/zcapld ChangeLog

### Changed
- **BREAKING**: Changed package name from `ocapld` to `@digitalbazaar/zcapld`.
- Resetting version to `1.0.0`.
- **BREAKING**: Only support Node.js >=12.
- Update dependencies.
- Use new `@digitalbazaar/ed25519-signature-2018` and
  `@digitalbazaar/ed25519-verification-key-2018` dependencies for testing.
- Modernize bundle building.

### Added
- Ship bundled ESM version.

### Removed
- **BREAKING**: Remove `bitcore-message` dependency. It's for a specialized use
  case.

### Previous ocapld ChangeLog
- This package was renamed from `ocapld`.
  See the [`ocapld` changelog](./CHANGELOG-ocapld.md) for earlier changes.
