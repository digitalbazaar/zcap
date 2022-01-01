/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const jsigs = require('jsonld-signatures');
const utils = require('./utils');
const {ControllerProofPurpose} = jsigs.purposes;

/* Note: This class is just an abstract base class for the
`CapabilityInvocation` and `CapabilityDelegation` proof purposes. */

module.exports = class CapabilityProofPurpose extends ControllerProofPurpose {
  /**
   * @param {string|Date|number} [date] - The expected date for the creation of
   *   the proof.
   * @param {boolean} [allowTargetAttenuation=false] - Allow the
   *   invocationTarget of a delegation chain to be increasingly restrictive
   *   based on a hierarchical RESTful URL structure.
   * @param {object} [controller] - The description of the controller, if it
   *   is not to be dereferenced via a `documentLoader`.
   * @param {Date} [currentDate = new Date()] - The date used for comparison
   *   when determining if a capability has expired.
   * @param {string|array} [expectedRootCapability] - The expected root
   *   capability for the delegation chain (this can be a single root
   *   capability ID expressed as a string or, if there is more than one
   *   acceptable root capability, several root capability IDs in an array.
   * @param {InspectCapabilityChain} [inspectCapabilityChain] - An async
   *   function that can be used to check for revocations related to any of
   *   verified capabilities.
   * @param {number} [maxChainLength=10] - The maximum length of the capability
   *   delegation chain.
   * @param {number} [maxDelegationTtl=Infinity] - The maximum time to live
   *   for a delegated zcap (as measured by the time difference between
   *   `expires`, which MUST be present if `maxDelegationTtl !== Infinity`, and
   *   `created` on the delegation proof.
   * @param {number} [maxTimestampDelta] - A maximum number of seconds that
   *   the date on the signature can deviate from, defaults to `Infinity`.
   * @param {boolean} [requireChainDateMonotonicity=false] - Require the
   *   created dates on delegation proofs to be monotonically increasing
   *   forward in time.
   * @param {object|array} suite - the jsonld-signature suites to use to
   *   verify the capability chain.
   * @param {string} term - The term `capabilityInvocation` or
   *   `capabilityDelegation` to look for in an LD proof.
   */
  constructor({
    // proof creation params (and common to all derived classes)
    date,
    // proof verification params (and common to all derived classes)
    allowTargetAttenuation = false, controller, currentDate,
    expectedRootCapability,
    inspectCapabilityChain,
    maxChainLength,
    maxDelegationTtl = Infinity,
    maxTimestampDelta = Infinity,
    requireChainDateMonotonicity = false,
    suite,
    term
  } = {}) {
    super({term, controller, date, maxTimestampDelta});

    // params used to verify a proof
    const hasVerifyProofParams = controller || currentDate ||
      expectedRootCapability || inspectCapabilityChain || suite;
    if(hasVerifyProofParams) {
      if(currentDate !== undefined && !(currentDate instanceof Date)) {
        throw new TypeError('"currentDate" must be a Date object.');
      }
      // FIXME: require `expectedRootCapability` but provide a helper to
      // auto-generate it? -- it may also be the case that when verifying
      // delegation chains only, the expected root isn't known ahead of time
      // ... in which case we may need to allow the check to be skipped?
      /*if(expectedRootCapability === undefined) {
        expectedRootCapability =
          `${ZCAP_ROOT_PREFIX}${encodeURIComponent(expectedTarget)}`;
      }*/
      if(!(typeof expectedRootCapability === 'string' ||
        Array.isArray(expectedRootCapability))) {
        throw new TypeError(
          '"expectedRootCapability" must be a string or array.');
      }

      // expected root capability values must be absolute URIs
      const expectedRootCapabilities = Array.isArray(expectedRootCapability) ?
        expectedRootCapability : [expectedRootCapability];
      for(const erc of expectedRootCapabilities) {
        if(!(typeof erc === 'string' && erc.includes(':'))) {
          throw new Error(
            '"expectedRootCapability" values must be absolute URI strings.');
        }
      }

      this.allowTargetAttenuation = allowTargetAttenuation;
      this.currentDate = currentDate || new Date();
      this.expectedRootCapability = expectedRootCapability;
      this.inspectCapabilityChain = inspectCapabilityChain;
      this.maxChainLength = maxChainLength;
      this.maxDelegationTtl = maxDelegationTtl;
      // FIXME: remove this option; always require chain date monotonicity
      this.requireChainDateMonotonicity = requireChainDateMonotonicity;
      this.suite = suite;
    }
  }

  async validate(proof, validateOptions) {
    // FIXME: double check these docs

    /* Note: Trust begins at the root zcap, so we start chain validation at
    the root and move forward from there. This also helps prevent time from
    being wasted by attackers that submit long zcap chains that are valid
    beyond the root (but not at the root because the attacker hasn't actually
    been delegated authority).

    This means that each parent zcap must be verified before a child is. This
    also means that we can't simply recursively unwind the chain in reverse;
    so the code is a bit more complex.

    This means that the verification process is:

    1. Verify the tail proof (which has already occurred before this function
      (`validate`) is called.
    2. Verify the chain from root => tail by calling `verifyCapabilityChain`
      just once -- when validating the tail. To ensure we don't call it more
      than once, we use `verifiedParentCapability` as a guard; if the parent
      capability has been verified, we don't call it, presuming that we are
      presently inside of a call to `verifyCapabilityChain` initiated by
      validating the tail as mentioned. If we are not inside such a call,
      then it will also be the case that the capability delegation proof
      will already have been verified, so we send a signal when we call
      `verifyCapabilityChain` not to reverify it -- by passing in the
      `capabilityChainMeta` array that captures verify results such that it
      already contains a result. */

    try {
      // ensure proof has expected context (even though this is called in
      // `match`, it is possible to call `validate` separately without calling
      // `match`, so check here too)
      utils.checkProofContext({proof});

      const {
        allowTargetAttenuation,
        currentDate,
        expectedRootCapability,
        inspectCapabilityChain,
        maxDelegationTtl,
        requireChainDateMonotonicity,
        suite
      } = this;

      const {
        document, documentLoader, expansionMap
      } = validateOptions;

      // run any proof-purpose-specific short-circuit check
      const shortcircuit = await this._shortCircuitValidate({
        proof, validateOptions
      });
      if(shortcircuit) {
        return shortcircuit;
      }

      /* 1. Dereference the capability chain. This involves finding all
      embedded delegated zcaps, using a verifier-trusted hook to dereference
      the root zcap, and putting the full zcaps in order (root => tail) in an
      array. The `tail` is the zcap that was invoked. */
      const {dereferencedChain} = await this._dereferenceChain({
        document, documentLoader, proof
      });

      /* 2. Run any proof-purpose-specific early checks prior to chain
      verification. */
      await this._runChecksBeforeChainVerification({
        dereferencedChain, proof, validateOptions
      });

      /* 3. Verify the capability delegation chain. This will make sure that
      the root zcap in the chain is as expected (for the endpoint where the
      invocation occurred) and that every other zcap in the chain (including
      the invoked one), has been properly delegated. */
      const {
        verified, error, capabilityChainMeta
      } = await utils.verifyCapabilityChain({
        // required to avoid circular dependencies
        CapabilityDelegation: this._getCapabilityDelegationClass(),
        allowTargetAttenuation,
        currentDate,
        dereferencedChain,
        // FIXME: pass all validate options as `validateOptions`?
        documentLoader,
        expectedRootCapability,
        expansionMap,
        inspectCapabilityChain,
        maxDelegationTtl,
        requireChainDateMonotonicity,
        suite
      });
      if(!verified) {
        throw error;
      }

      /* 4. Run any proof-purpose-specific checks after chain verification. */
      const validateResult = await this._runChecksAfterChainVerification({
        capabilityChainMeta, dereferencedChain, proof, validateOptions
      });

      // run `inspectCapabilityChain` hook
      if(inspectCapabilityChain) {
        const {valid, error} = await inspectCapabilityChain({
          // FIXME: why not include root zcap too?
          capabilityChain: dereferencedChain.slice(1),
          capabilityChainMeta
        });
        if(!valid) {
          throw error;
        }
      }

      // check verification method controller
      return validateResult;
    } catch(error) {
      return {valid: false, error};
    }
  }

  async _dereferenceChain({document, documentLoader, proof}) {
    const {maxChainLength} = this;
    const {capability} = this._getTailCapability({document, proof});
    const {dereferencedChain} = await utils.dereferenceCapabilityChain({
      capability,
      // FIXME: allow custom `getRootCapability`
      async getRootCapability({id}) {
        const {document} = await documentLoader(id);
        return {rootCapability: document};
      },
      maxChainLength
    });
    return {dereferencedChain};
  }

  _getCapabilityDelegationClass() {
    throw new Error('Not implemented.');
  }

  async _getTailCapability(/*{document, proof}*/) {
    throw new Error('Not implemented.');
  }

  // no-op by default
  async _runChecksBeforeChainVerification() {}

  // no-op by default
  async _runChecksAfterChainVerification() {}

  async _runBaseProofValidation({proof, validateOptions}) {
    // run super class's validation checks
    const result = await super.validate(proof, validateOptions);
    if(!result.valid) {
      throw result.error;
    }
    return result;
  }

  // no-op by default
  async _shortCircuitValidate() {}
};
