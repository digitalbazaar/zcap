# ocapld ChangeLog

## 1.3.1 - 2019-08-xx

### Fixed
- Handle case where a capability lists list multiple
  controllers/invokers/delegators.

## 1.3.0 - 2019-07-17

### Added
- Add `expectedRootCapability` to allow a root capability to
  specify an `invocationTarget` different from its `id`. This
  allows zcaps to be used to manage authority for resources
  that cannot express their own zcap authority information
  such as binary files or resources that use JSON or JSON-LD
  but, for whatever reason, cannot express `controller`,
  `invoker`, `delegator`, or key information.

## 1.2.1 - 2019-06-29

### Fixed
- Check `allowedAction` against expected `capabilityAction`.
- Fix expected action check.
- Fix capability chain check.
- Ensure root caps are dereferenced and have a valid target.
- Handle case where `invocationTarget` is an object.

## 1.2.0 - 2019-05-17

### Added
- Support `controller` on capabilities as `delegator` and `invoker`.

### Changed
- Update webpack and babel.
- Switch to eslint.

## 1.1.0 - 2019-03-27

### Changed
- Upgrade jsonld-signatures to version 4.

## 1.0.2 - 2019-01-03

### Fixed
- Change jsonld-signatures to a regular dependency.

## 1.0.1 - 2019-01-03

### Fixed
- Distribute webpack built dist files.

## 1.0.0 - 2019-01-03

### Changed
- Use webpack 'externals' for jsonld and jsonld-signatures.

## 0.1.0 - 2019-01-02
- Initial release.
- See git history for changes.
