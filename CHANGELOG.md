# @digitalbazaar/zcap ChangeLog

## 7.2.1 - 2022-02-22

### Fixed
- Ensure `maxClockSkew` is considered when checking `maxDelegationTtl`
  against current time.
- Use `karma@6.3.16` to address reported vulnerability with dev
  dependency `karma`.

## 7.2.0 - 2022-01-20

### Added
- Include `capability` and `verificationMethod` as details when a zcap
  invocation/delegation fails verification because the capability
  controller does not match the verification method (or its controller). If
  this information causes undesirable correlation, i.e., the controller
  of a root zcap is private in some way, do not include it when transmitting
  errors to a client. This information can be omitted by deleting `details`
  from the error or constructing a new error that omits `details`.

## 7.1.0 - 2022-01-14

### Added
- Include `dereferencedChain` in purpose result when verifying a
  capability invocation or delegation proof.

## 7.0.1 - 2022-01-11

### Changed
- Update dependencies.

## 7.0.0 - 2022-01-11

### Changed
- **BREAKING**: Rename package to `@digitalbazaar/zcap`.

## 6.0.0 - 2022-01-11

### Added
- Add `createRootCapability` helper function to construct root zcaps from
  a root invocation target and a root controller.
- Add local validation during delegation to prevent accidental delegation of
  zcaps that violate delegation rules that a verifier would always reject.
- Add `maxClockSkew` param that defaults to `300` seconds. This parameter
  defines the maximum clock skew that will be accepted when comparing
  capability expiration date-times against the current date (or other
  specified date) and when comparing a capability invocation proof against
  the capability's delegation proof.

### Changed
- **BREAKING**: Root zcaps MUST specify an `invocationTarget`. This eliminates
  optionality, simplifying implementations.
- **BREAKING**: Root zcaps MUST be passed by reference to their ID when invoking
  and they will be expressed by reference (just their ID) in a capability
  invocation proof. Delegated zcaps MUST be fully embedded (pass full object)
  when invoking and they will be fully embedded in a capability invocation proof.
- **BREAKING**: When creating a capability delegation proof, a new parameter
  `parentCapability` MUST be passed so that the chain can be auto-computed.
  Passing `capabilityChain` is no longer permitted.
- **BREAKING**: Require `capabilityAction` when creating capability invocation
  proofs and `expectedAction` when verifying proofs; removing previous
  optionality simplifies implementations.
- **BREAKING**: Changed default to check for chain date monotonicity and
  removed the option to do otherwise. This was an expected change for the
  next major breaking release.
- **BREAKING**: `expires` is not permitted on root capabilities and is
  required on delegated capabilities. Removing optionality here simplifies
  implementations and improves security by reducing surface and providing
  an "out" for zcaps that can not be easily revoked by causing them to
  always expire eventually.
- **BREAKING**: Combine `currentDate` and `date` parameters that were serving
  the same purpose. These params are only used for verification and the `date`
  parameter is used by the base class provided by jsonld-signatures, so the
  `currentDate` parameter has been removed; use `date` instead, it is only
  used for verification of proofs, not creation of proofs.
- **BREAKING**: `invocationTarget` MUST be specified in capability invocation
  proofs, it will not default to the `invocationTarget` specified in the
  capability. Removing this optionality removes complexity in implementations.
- **BREAKING**: `capabilityChain` and `capabilityChainMeta` that are passed
  to `inspectCapabilityChain` include entries for the root capability. The
  `verifyResult` is `null` for the root zcap.
- **BREAKING**: `allowTargetAttenuation=true` allows both path- or query-based
  invocation target attenuation. Turning this on means a verifier will allow
  accept delegations (and invocations) where a suffix has been added to the
  parent zcap's invocation target (invoked zcap's invocation target). The
  suffix must starts with `/` or `?` if the invocation target prefix has no `?`
  and `&` otherwise.

### Removed
- **BREAKING**: Removed support for using `invoker` and `delegator` properties.
  Only `controller` is now permitted and it is `required`, i.e., a ZCAP MUST
  have a `controller` property, the value of the ZCAP's `id` property is not
  considered a default controller value for the ZCAP. This change simplifies
  ZCAP implementations and better reflects the fact that a delegation cannot
  actually be restricted -- a system can only force users to use data model
  and protocol-external mechanisms to delegate. This change keeps all
  delegation within the data model/protocol for improved auditability.
- **BREAKING**: Removed support for vocab-modeled custom caveats. Custom
  caveats should instead be modeled a combination of capability actions
  and path- or query-based attenuation of invocation targets. This approach
  provides the flexibility required to model custom caveats without the
  overhead of building and maintaining custom contexts and vocabularies. The
  common case is that custom caveats are specific to particular APIs rather
  than shared commonly across many different standardized APIs -- so it is
  unnecessarily burdensome to require the creation ofLinked Data vocabularies
  and contexts to represent them when using localized API-specific capability
  actions and invocation target paths will suffice. Common caveats such as
  expiration dates are provided as a part of the core model -- and should any
  other common caveats become evident, they can be added to the core model over
  time.
- **BREAKING**: Removed support for allowing the last delegated zcap in a
  capability chain to be expressed by reference. Instead, if the last zcap in
  the chain is delegated, it MUST be fully embedded. All other zcaps MUST be
  expressed via reference to their ID. Therefore, a capability chain MUST
  always consist of: the root zcap ID, any non-last delegated zcap IDs, and,
  for chains longer than 1 (excluding the final zcap or 2 if inclusive), the
  fully embedded last delegated zcap. This simplifies implementations, removes
  any concerns around mutability in dereferenced zcaps, and guarantees that all
  zcaps in a chain are available in an invocation. It does require that the
  invoker send the entire chain, however, this considered the best trade off.
- **BREAKING**: Removed ability to expire a root capability. There is no
  use case for this, so the complexity has been removed.
- **BREAKING**: Removed support for zcaps expressed using contexts other than
  the zcap-ld v1 context. The zcap spec will be updated to describe zcaps as
  JSON in a way that JSON-LD compatible, eliminating the need for supporting
  and JSON-LD context transformations beyond those used to create and verify
  proofs. This approach will not prohibit the future use of CBOR-LD to
  represent zcaps over the wire to greatly reduce size.

## 5.2.0 - 2021-12-20

### Added
- Add optional `maxDelegationTtl` to enable checking that all zcaps in a
  delegation chain have a time-to-live that is not greater than a certain
  value. This check will have a default value shorter than `Infinity` in
  a future breaking version.
- Add optional `requireChainDateMonotonicity` to enable checking that all
  zcaps in a delegation chain have delegation proofs that were created using
  dates that monotonically increase (i.e., no delegated zcap was delegated
  any later than its parent). This check will be required in a future breaking
  version.

## 5.1.3 - 2021-11-15

### Fixed
- Ensure `invocationTarget` from an invocation proof is checked against the
  capability used and the `expectedTarget`. The `invocationTarget` from the
  proof must both be in the `expectedTarget` list (or a direct match if a
  string value is used for `expectedTarget` vs. an array) and it must also
  match the `invocationTarget` in the capability used (if
  `allowTargetAttenuation=true` then the capability's `invocationTarget` may
  be a path prefix for the `invocationTarget` from the proof).

## 5.1.2 - 2021-07-21

### Fixed
- Enable zcap context to appear anywhere in a context array when
  checking proof context because it is a protected context.

## 5.1.1 - 2021-07-21

### Fixed
- Ensure `proof` uses an expected context during proof validation.

## 5.1.0 - 2021-07-11

### Changed
- Updated jsonld-signatures to 9.3.x. This brings in an optimization for
  controller documents that are JSON-LD DID documents.

## 5.0.0 - 2021-07-02

### Added
- Expose `ZCAP_CONTEXT` in `constants` as a convenience.
- Add `documentLoader` to expose a convenience document loader that will load
  `ZCAP_CONTEXT`.
- Add `extendDocumentLoader` for adding a custom document loader that extend
  `documentLoader` to load other documents.

### Changed
- **BREAKING**: LD capability invocation proofs now require `invocationTarget`
  to be set in order for `match()` to find proofs based on `expectedTarget`.
  This helps ensure that the proof creator's intended `invocationTarget` is
  declared (important for systems that support RESTful attenuation) and it
  enables more efficient proof verification when documents include multiple
  capability invocation proofs that may have different invocation targets.

### Fixed
- Ensure `expectedAction` is checked when looking for a matching proof,
  not `capabilityAction`.

## 4.0.0 - 2021-04-26

### Fixed
- **BREAKING**: Use [`zcap-context@1.1.0`](https://github.com/digitalbazaar/zcap-context/blob/main/CHANGELOG.md)
  and refactor `fetchInSecurityContext` API.
- Use [`@digitalbazaar/security-context@1.0.0`](https://github.com/digitalbazaar/security-context/blob/main/CHANGELOG.md).

## 3.1.1 - 2021-04-15

### Fixed
- Use `jsonld-signatures@9`.
- Update test dependencies and fix tests.

## 3.1.0 - 2021-04-08

### Added
- Skip `jsonld.compact` step when a JSON-LD document has specific contexts.
  This is a temporary measure until a zcap context is created.

## 3.0.0 - 2021-03-19

### Changed
- **BREAKING**: Changed package name from `ocapld` to `@digitalbazaar/zcapld`.
- **BREAKING**: Only support Node.js >=12.
- Update dependencies.
- Use new `@digitalbazaar/ed25519-signature-2018` and
  `@digitalbazaar/ed25519-verification-key-2018` dependencies for testing.

### Removed
- **BREAKING**: Remove `bitcore-message` dependency. It's for a specialized use
  case.
- **BREAKING**: Remove browser bundles.

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
