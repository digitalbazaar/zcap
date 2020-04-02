# ocapld ChangeLog

## 2.0.0 - 2020-04-02

### Changed
- **BREAKING**: An `invocationTarget` must be specified in all delegations.
- Improve test coverage.

### Fixed
- Properly validate `allowedAction` in capabilities.

### Added
- Add verification of `expires` as a core feature.
- Add the ability to specificy a `maxChainLength` when verifying capability
  delegations.
- Add an optional `allowTargetAttenuation` flag which allows the
  `invocationTarget` of a delegation chain to be increasingly restrictive
  based on a hierarchical RESTful URL structure.

## 1.8.0 - 2020-02-14

### Changed

- Use jsonld-signatures@5.

## 1.7.0 - 2020-02-07

### Added
- Implement validation for embedded capabilities in `capabilityChain`.

## 1.6.1 - 2020-01-30

### Fixed
- Adjust the parameters to `inspectCapabilityChain` to support more general
  use cases. See in-line documentation for parameter details.

## 1.6.0 - 2020-01-29

### Added
- Add an optional `inspectCapabilityChain` parameter to `CapabilityDelegation`
  and `CapabilityInvocation`. `inspectCapabilityChain` must be an async
  function used to check the capability chain. It can, for instance,  be used
  to find revocations related to any of the capabilities in the chain.

## 1.5.1 - 2020-01-29

### Fixed
- Address issues in `verifyCapabilityChain` helper that resulted in some
  proofs not being properly verified.

## 1.5.0 - 2020-01-09

### Added
- Support multiple values for `expectedTarget` and `expectedRootCapability`
  for use cases such as where capabilities are given for reading/writing
  any item in a collection instead of only individual items.

## 1.4.0 - 2019-10-08

### Changed
- Use jsonld-signatures@4.4.0 Use with support for Node 12 native Ed25519
  crypto.

## 1.3.1 - 2019-08-11

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
