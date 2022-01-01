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
   * @param {boolean} [allowTargetAttenuation=false] - Allow the
   *   invocationTarget of a delegation chain to be increasingly restrictive
   *   based on a hierarchical RESTful URL structure.
   * @param {object} [controller] - The description of the controller, if it
   *   is not to be dereferenced via a `documentLoader`.
   * @param {string|Date|number} [date] - Used during proof verification as the
   *   expected date for the creation of the proof (within a maximum timestamp
   *   delta) and for checking to see if a capability has expired; if not
   *   passed the current date will be used.
   * @param {string|array} [expectedRootCapability] - The expected root
   *   capability for the delegation chain (this can be a single root
   *   capability ID expressed as a string or, if there is more than one
   *   acceptable root capability, several root capability IDs in an array.
   * @param {InspectCapabilityChain} [inspectCapabilityChain] - An async
   *   function that can be used to check for revocations related to any of
   *   verified capabilities.
   * @param {number} [maxChainLength=10] - The maximum length of the capability
   *   delegation chain.
   * @param {number} [maxDelegationTtl=Infinity] - The maximum milliseconds to
   *   live for a delegated zcap as measured by the time difference between
   *   `expires` and `created` on the delegation proof.
   * @param {number} [maxTimestampDelta=Infinity] - A maximum number of seconds
   *   that the date on the signature can deviate from, defaults to `Infinity`.
   * @param {object|array} suite - the jsonld-signature suites to use to
   *   verify the capability chain.
   * @param {string} term - The term `capabilityInvocation` or
   *   `capabilityDelegation` to look for in an LD proof.
   */
  constructor({
    // proof verification params (and common to all derived classes)
    allowTargetAttenuation = false, controller, date,
    expectedRootCapability,
    inspectCapabilityChain,
    maxChainLength,
    maxDelegationTtl = Infinity,
    maxTimestampDelta = Infinity,
    suite,
    term
  } = {}) {
    super({term, controller, date, maxTimestampDelta});

    // params used to verify a proof
    const hasVerifyProofParams = controller || date ||
      expectedRootCapability || inspectCapabilityChain || suite;
    if(hasVerifyProofParams) {
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
      this.expectedRootCapability = expectedRootCapability;
      this.inspectCapabilityChain = inspectCapabilityChain;
      this.maxChainLength = maxChainLength;
      this.maxDelegationTtl = maxDelegationTtl;
      this.suite = suite;
    }
  }

  async validate(proof, validateOptions) {
    /* Note: Trust begins at the root zcap, so we start chain validation at
    the root and move forward toward the tail from there. This also helps
    prevent an attacker from wasting time when they submit long zcap chains
    that are extensions of otherwise valid chains.

    So, each parent zcap must be verified before its child is. This also means
    that we can't simply recursively unwind the chain in reverse; therefore,
    the code is a bit more complex.

    Note that if a chain is being checked without an invocation, i.e., without
    invoking the tail capability, then the tail's capability delegation *proof*
    will have been cryptographically verified prior to this call. Otherwise,
    it will need to be cryptographically verified. There is a signal described
    below to indicate whether this verification needs to occur. Regardless, the
    tail has not yet been validated as a tail for the chain and won't be until
    the rest of the chain, starting at the root, is validated.

    The validation process is:

    0. Run a short-circuit check to ensure that we only verify the capability
      chain once; that is, we only start checking the chain when we haven't
      verified any parent zcaps yet. Whether we've started checking the chain
      yet or not is handled by a derived class that implements
      `_shortCircuitValidate`, returning the short-circuit validation result
      if the chain check has already started and `undefined` if it hasn't.
    1. If we haven't been short-circuited, then dereference the capability
      chain referenced in the tail proof to get all zcaps in the chain.
    2. Run any proof-purpose specific checks prior to checking the rest of
      the chain. This allows shortcuts when checking a capability invocation
      proof, e.g., if an invocation is immediately invalid for some reason,
      there is no need to check that the delegation rules were followed along
      the entire chain. This method also returns the `capabilityChainMeta`
      array to use to hold the capability delegation proof verify results. If
      a capability delegation proof for the tail has already been verified,
      this array will have a placeholder for its full proof validation result
      as a signal to avoid duplicating this work later.
    3. Verify the chain from root => tail by calling `verifyCapabilityChain`
      just once -- when validating the tail. The short-circuit check above
      ensures we don't call this more than once. Additionally, the
      `capabilityChainMeta` array signals whether we need to cryptographically
      verify the capability delegation proof on the tail or if we must skip
      this to avoid duplicating that work.
    4. Run any purpose-specific checks after chain verification. This allows
      capability delegation proof checks to be run on the tail against the now
      verified parent, allowing its proof validation result to be fully
      constructed and updated in the `capabilityChainMeta` array (as well
      as the return value for this function).
    5. Run the `inspectCapabilityChain` hook, if given, to allow for custom
      implementations to check for revoked zcaps in databases or whatever other
      behavior is desired. */

    try {
      // ensure proof has expected context (even though this is called in
      // `match`, it is possible to call `validate` separately without calling
      // `match`, so check here too)
      utils.checkProofContext({proof});

      const {
        allowTargetAttenuation,
        date,
        expectedRootCapability,
        inspectCapabilityChain,
        maxDelegationTtl,
        suite
      } = this;

      const {
        document, documentLoader, expansionMap
      } = validateOptions;

      // 0. Run any proof-purpose-specific short-circuit check.
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
      const {
        capabilityChainMeta
      } = await this._runChecksBeforeChainVerification({
        dereferencedChain, proof, validateOptions
      });

      /* 3. Verify the capability delegation chain. This will make sure that
      the root zcap in the chain is as expected (for the endpoint where the
      invocation occurred) and that every other zcap in the chain (including
      the invoked one), has been properly delegated. */
      const {
        verified, error
      } = await this._verifyCapabilityChain({
        // required to avoid circular dependencies
        CapabilityDelegation: this._getCapabilityDelegationClass(),
        allowTargetAttenuation,
        capabilityChainMeta,
        date,
        dereferencedChain,
        documentLoader,
        expectedRootCapability,
        expansionMap,
        inspectCapabilityChain,
        maxDelegationTtl,
        suite
      });
      if(!verified) {
        throw error;
      }

      /* 4. Run any proof-purpose-specific checks after chain verification
        to get the proof validation result. */
      const validateResult = await this._runChecksAfterChainVerification({
        capabilityChainMeta, dereferencedChain, proof, validateOptions
      });

      // 5. Run `inspectCapabilityChain` hook.
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

  /**
   * Verifies the given dereferenced capability chain. This involves ensuring
   * that the root zcap in the chain is as expected (for the endpoint where an
   * invocation or a simple chain chain is occurring) and that every other zcap
   * in the chain (including any invoked one), has been properly delegated.
   *
   * @param {class} CapabilityDelegation - The CapabilityDelegation class; this
   *   must be passed to avoid circular references in this module.
   * @param {InspectChainResult[]} capabilityChainMeta - The array of results
   *   for inspecting the capability chain; if this has a value when passed,
   *   then it is presumed to be the verify result for the tail capability and
   *   that tail capability will not be verified internally by this function
   *   to avoid duplicating work; all verification results (including the
   *   tail's -- either computed locally or reused from what was passed) will
   *   be added to this array in order from root => tail.
   * @param {array} dereferencedChain - The dereferenced capability chain for
   *   `capability`, starting at the root capability and ending at `capability`.
   * @param {function} documentLoader - A configured jsonld documentLoader.
   * @param {object} expansionMap - A configured jsonld expansionMap.
   *
   * @return {object} {verified, error, verifiedParentCapability}.
   */
  async _verifyCapabilityChain({
    CapabilityDelegation,
    capabilityChainMeta,
    dereferencedChain,
    documentLoader,
    expansionMap
  }) {
    /* Note: We start verifying a capability chain at its root of trust (the
    root capability) and then move toward the tail. To prevent recursively
    repeating checks, we pass a `verifiedParentCapability` each time we start
    verifying another capability delegation proof in the capability chain.

    Verification process is:

    1. Verify the root capability ID matches an expected one.
    2. For each capability `zcap` in the chain, verify the capability delegation
      proof on `zcap` (if `capabilityChainMeta` has no precomputed result) and
      that all of the delegation rules have been followed. */

    /* Note: `verifiedParentCapability` will prevent repetitive checking of
    the same segments of the chain (once a parent is verified, its chain is
    not checked again when checking its children). */
    let verifiedParentCapability = null;

    try {
      // 1. Verify the root capability ID matches an expected one.
      const [root] = dereferencedChain;
      const {expectedRootCapability} = this;
      if(!((Array.isArray(expectedRootCapability) &&
        expectedRootCapability.includes(root.id)) ||
        (typeof expectedRootCapability === 'string' &&
          root.id === expectedRootCapability))) {
        throw new Error(
          `Expected root capability (${expectedRootCapability}) does not ` +
          `match actual root capability (${root.id}).`);
      }

      // if the chain only has the root, exit early
      if(dereferencedChain.length === 1) {
        return {
          verified: true,
          verifiedParentCapability,
          capabilityChainMeta
        };
      }

      // 2. For each capability `zcap` in the chain, verify the capability
      //   delegation proof on `zcap` and that the delegation rules have been
      //   followed.
      let parentAllowedAction;
      let parentDelegationDate;
      let parentExpirationDate;
      let {invocationTarget: parentInvocationTarget} = root;

      // track whether `capabilityChainMeta` needs its first result shifted to
      // the end (if a result was present, it is for the last or "tail" zcap,
      // so we set a flag to remember to move it to the end when we're done
      // checking zcaps below)
      const mustShift = capabilityChainMeta.length > 0;

      // get all delegated capabilities (no root zcap since it has no delegation
      // proof to check)
      const delegatedCapabilities = dereferencedChain.slice(1);
      const {
        allowTargetAttenuation,
        date,
        maxDelegationTtl,
        suite
      } = this;
      const currentDate = (date && new Date(date)) || new Date();
      for(let i = 0; i < delegatedCapabilities.length; ++i) {
        const zcap = delegatedCapabilities[i];
        verifiedParentCapability = delegatedCapabilities[i - 1] || root;

        // verify proof on zcap if no result has been computed yet (one
        // verify result will be present in `capabilityChainMeta` per
        // delegated capability)
        if(capabilityChainMeta.length < delegatedCapabilities.length) {
          const verifyResult = await jsigs.verify(zcap, {
            suite,
            purpose: new CapabilityDelegation({
              allowTargetAttenuation,
              date: currentDate,
              expectedRootCapability,
              verifiedParentCapability,
              maxDelegationTtl
            }),
            documentLoader,
            expansionMap
          });
          if(!verifyResult.verified) {
            throw verifyResult.error;
          }
          // delegation proof verified; save meta data for later inspection
          capabilityChainMeta.push({verifyResult});
        }

        // ensure `allowedAction` is valid (compared against parent)
        const {allowedAction} = zcap;
        if(!utils.hasValidAllowedAction({allowedAction, parentAllowedAction})) {
          throw new Error(
            'The "allowedAction" in a delegated capability ' +
            'must not be less restrictive than its parent.');
        }

        // ensure `invocationTarget` delegation is acceptable
        const invocationTarget = utils.getTarget({capability: zcap});
        if(!utils.isValidTarget({
          invocationTarget,
          baseInvocationTarget: parentInvocationTarget,
          allowTargetAttenuation
        })) {
          if(allowTargetAttenuation) {
            throw new Error(
              `The "invocationTarget" in a delegated capability must not be ` +
              'less restrictive than its parent.');
          } else {
            throw new Error(
              'The "invocationTarget" in a delegated capability ' +
              'must be equivalent to its parent.');
          }
        }

        // verify expiration dates
        // expires date has been previously validated, so just parse it
        const currentCapabilityExpirationDate = Date.parse(zcap.expires);

        // if the parent does not specify an expiration date, then any more
        // restrictive expiration date is acceptable
        if(parentExpirationDate !== undefined) {
          // handle case where `expires` is set in the parent, but the child
          // has an expiration date greater than the parent
          if(currentCapabilityExpirationDate > parentExpirationDate) {
            throw new Error('The `expires` property in a delegated ' +
              'capability must not be less restrictive than its ' +
              'parent.');
          }
          if(currentDate.getTime() > currentCapabilityExpirationDate) {
            throw new Error(
              'A capability in the delegation chain has expired.');
          }
        }

        // get delegated date
        let currentCapabilityDelegationDate;
        const proofs = utils.getDelegationProofs({capability: zcap});
        // get earliest date from delegation proofs
        for(const p of proofs) {
          const created = Date.parse(p.created);
          if(currentCapabilityDelegationDate === undefined) {
            currentCapabilityDelegationDate = created;
          } else if(currentCapabilityDelegationDate < created) {
            currentCapabilityDelegationDate = created;
          }
        }

        // verify parent capability was not delegated after child
        if(parentDelegationDate !== undefined &&
          parentDelegationDate > currentCapabilityDelegationDate) {
          throw new Error(
            'A capability in the delegation chain was delegated before ' +
            'its parent.');
        }

        // FIXME: disallow infinity as an option and set a reasonable default
        if(maxDelegationTtl < Infinity) {
          /* Note: Here we ensure zcap has a time-to-live (TTL) that is
          sufficiently short. This is to prevent the use of zcaps that, when
          revoked, will have to be stored for long periods of time. We have to
          ensure:

          1. The zcap's delegation date is not in the future (this also ensures
            that the zcap's expiration date is not before its delegation date as
            it would have triggered an expiration error in a previous check).
          2. The zcap's current TTL is <= `maxDelegationTtl`
          3. The zcap's TTL was never > `maxDelegationTtl`. */
          if(currentCapabilityDelegationDate > currentDate) {
            throw new Error(
              'A delegated capability in the delegation chain was delegated ' +
              'in the future.');
          }
          const currentTtl = currentCapabilityExpirationDate - currentDate;
          const maxTtl = currentCapabilityExpirationDate -
            currentCapabilityDelegationDate;
          if(currentTtl > maxDelegationTtl || maxTtl > maxDelegationTtl) {
            throw new Error(
              'A delegated capability in the delegation chain has a time to ' +
              'live that is too long.');
          }
        }

        parentAllowedAction = allowedAction;
        parentExpirationDate = currentCapabilityExpirationDate;
        parentDelegationDate = currentCapabilityDelegationDate;
        parentInvocationTarget = invocationTarget;
      }

      // shift zcap verify result for last zcap to the end of meta array if
      // necessary
      if(mustShift) {
        capabilityChainMeta.push(capabilityChainMeta.shift());
      }

      return {verified: true, verifiedParentCapability, capabilityChainMeta};
    } catch(error) {
      return {verified: false, error};
    }
  }
};
