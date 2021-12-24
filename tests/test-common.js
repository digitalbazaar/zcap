/*!
 * Copyright (c) 2018-2021 Digital Bazaar, Inc. All rights reserved.
 */

/* eslint-disable indent */
module.exports = async function(options) {

'use strict';

const should = require('chai').should();
const {expect, helpers, jsigs, mock, zcapld} = options;

const {
  CapabilityInvocation,
  CapabilityDelegation,
  constants: {ZCAP_CONTEXT_URL, ZCAP_ROOT_PREFIX}
} = zcapld;

const {Ed25519Signature2020} =
  require('@digitalbazaar/ed25519-signature-2020');

const {Ed25519VerificationKey2020} =
  require('@digitalbazaar/ed25519-verification-key-2020');

const {
  controllers,
  privateDidDocs,
  capabilities,
  addToLoader,
  testLoader
} = mock;
const {Controller, uuid} = helpers;

// helper:
function clone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

const alice = new Controller(controllers.alice);
const bob = new Controller(controllers.bob);
const carol = new Controller(controllers.carol);
const diana = new Controller(controllers.diana);
const alpha = new Controller(privateDidDocs.alpha);
// const beta = new Controller(privateDidDocs.beta);
// const gamma = new Controller(privateDidDocs.gamma);
// const delta = new Controller(privateDidDocs.delta);

const CONSTANT_DATE = '2018-02-13T21:26:08Z';

// run tests
describe('zcapld', () => {
  describe('Sign with capabilityInvocation proof purpose', () => {
    it('should succeed w/key invoker', async () => {
      const doc = clone(mock.exampleDoc);
      const signed = await _invoke({
        doc, invoker: alice, date: CONSTANT_DATE,
        capability: capabilities.root.alpha,
        capabilityAction: 'read'
      });
      expect(signed).to.deep.equal(mock.exampleDocWithInvocation.alpha);
    });

    it('should succeed w/controller invoker', async () => {
      const doc = clone(mock.exampleDoc);
      const signed = await _invoke({
        doc, invoker: alice, date: CONSTANT_DATE,
        capability: capabilities.root.beta,
        capabilityAction: 'read'
      });
      expect(signed).to.deep.equal(mock.exampleDocWithInvocation.beta);
    });

    it('should fail when missing "capability"', async () => {
      let err;
      try {
        const doc = clone(mock.exampleDoc);
        await _invoke({
          doc, invoker: alice,
          purposeOptions: {}
        });
      } catch(e) {
        err = e;
      }
      expect(err).to.exist;
      expect(err.message).to.equal('"capability" must be a string or object.');
    });

    it('should fail when missing "capabilityAction"', async () => {
      let err;
      try {
        const doc = clone(mock.exampleDoc);
        await _invoke({
          doc, invoker: alice,
          purposeOptions: {
            capability: 'urn:foo'
          }
        });
      } catch(e) {
        err = e;
      }
      expect(err).to.exist;
      expect(err.message).to.equal('"capabilityAction" must be a string.');
    });

    it('should fail when missing "invocationTarget"', async () => {
      let err;
      try {
        const doc = clone(mock.exampleDoc);
        await _invoke({
          doc, invoker: alice,
          purposeOptions: {
            capability: 'urn:foo',
            capabilityAction: 'read'
          }
        });
      } catch(e) {
        err = e;
      }
      expect(err).to.exist;
      expect(err.message).to.equal('"invocationTarget" must be a string.');
    });
  });

  describe('Sign with capabilityDelegation proof purpose', () => {
    it('should succeed w/verification method as controller', async () => {
      // create a delegated capability for special case where controller is
      // a verification method itself (uncommon case)
      // 1. Parent capability points to the root capability
      // 2. The controller is Bob's invocation verification method (key)
      const newCapability = {
        '@context': ZCAP_CONTEXT_URL,
        id: 'urn:uuid:055f47a4-61d3-11ec-9144-10bf48838a41',
        parentCapability: capabilities.root.alpha.id,
        controller: bob.get('capabilityInvocation', 0).id,
        invocationTarget: capabilities.root.alpha.invocationTarget
      };
      // 3. Sign the delegated capability with Alice's delegation key
      // (this works because Alice is the root capability's controller)
      const delegatedCapability = await _delegate({
        newCapability, delegator: alice, date: CONSTANT_DATE,
        capabilityChain: [capabilities.root.alpha.id]
      });
      expect(delegatedCapability).to.deep.equal(capabilities.delegated.alpha);
    });

    it('should succeed', async () => {
      // create a delegated capability  where controller is an entity that uses
      // verification methods (common case)
      // 1. Parent capability points to the root capability
      // 2. The controller is Bob
      const newCapability = {
        '@context': ZCAP_CONTEXT_URL,
        id: 'urn:uuid:710910c8-61e4-11ec-8739-10bf48838a41',
        parentCapability: capabilities.root.beta.id,
        controller: bob.id(),
        invocationTarget: capabilities.root.beta.invocationTarget
      };
      // 3. Sign the delegated capability with Alice's delegation key
      // (this works because Alice is the root capability's controller)
      const delegatedCapability = await _delegate({
        newCapability, delegator: alice, date: CONSTANT_DATE,
        capabilityChain: [capabilities.root.beta.id]
      });
      expect(delegatedCapability).to.deep.equal(capabilities.delegated.beta);
    });

    it('should fail when missing "capabilityChain" and "parentCapability"',
      async () => {
      let err;
      try {
        const doc = clone(mock.exampleDoc);
        await _delegate({
          newCapability: doc, delegator: alice, purposeOptions: {}
        });
      } catch(e) {
        err = e;
      }
      expect(err).to.exist;
      expect(err.message).to.equal(
        'Either "capabilityChain" or "parentCapability" is required to ' +
        'create a capability delegation proof.');
    });

    it('should success when passing only "parentCapability"', async () => {
      // only pass `parentCapability` as a purpose option -- this will cause
      // the `capabilityChain` to be auto-generated
      const newCapability = {
        '@context': ZCAP_CONTEXT_URL,
        id: 'urn:uuid:710910c8-61e4-11ec-8739-10bf48838a41',
        parentCapability: capabilities.root.beta.id,
        controller: bob.id(),
        invocationTarget: capabilities.root.beta.invocationTarget
      };
      const delegatedCapability = await _delegate({
        newCapability, delegator: alice, date: CONSTANT_DATE,
        purposeOptions: {
          parentCapability: capabilities.root.beta
        }
      });
      expect(delegatedCapability).to.deep.equal(capabilities.delegated.beta);
    });
  });

  context('Capability controller is itself a verification method', () => {
    it('should verify an invoked root capability', async () => {
      const result = await _verifyInvocation({
        invocation: mock.exampleDocWithInvocation.alpha,
        rootCapability: capabilities.root.alpha,
        expectedAction: 'read'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should verify w/array expected target', async () => {
      const result = await _verifyInvocation({
        invocation: mock.exampleDocWithInvocation.alpha,
        purposeOptions: {
          expectedAction: 'read',
          expectedRootCapability: capabilities.root.alpha.id,
          expectedTarget: [capabilities.root.alpha.invocationTarget]
        }
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should verify a capability chain of depth 2', async () => {
      const delegatedCapability = await _delegate({
        parentCapability: capabilities.root.alpha,
        controller: bob.get('capabilityInvocation', 0).id,
        delegator: alice,
        capabilityChain: [capabilities.root.alpha.id]
      });
      const result = await _verifyDelegation({
        delegation: delegatedCapability
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should fail to verify a capability chain of depth 2 ' +
      'when the expectedRootCapability does not match', async () => {
      const delegatedCapability = await _delegate({
        parentCapability: capabilities.root.alpha,
        controller: bob.get('capabilityInvocation', 0).id,
        delegator: alice,
        capabilityChain: [capabilities.root.alpha.id]
      });
      const result = await _verifyDelegation({
        delegation: delegatedCapability, purposeOptions: {
          expectedRootCapability: 'urn:uuid:fake'
        }
      });
      expect(result).to.exist;
      expect(result.verified).to.be.false;
      result.error.name.should.equal('VerificationError');
      const [error] = result.error.errors;
      error.message.should.contain('does not match actual root capability');
    });

    it('should verify invoking a capability chain of depth 2', async () => {
      // delegate from alice to bob
      const delegatedCapability = await _delegate({
        parentCapability: capabilities.root.alpha,
        controller: bob.get('capabilityInvocation', 0).id,
        delegator: alice,
        capabilityChain: [capabilities.root.alpha.id]
      });

      // bob invokes the delegated zcap
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: delegatedCapability,
        capabilityAction: 'read'
      });
      const result = await _verifyInvocation({
        invocation, rootCapability: capabilities.root.alpha,
        expectedAction: 'read'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });
  });

  context('Capability controller uses verification method', () => {
    it('should verify an invoked root capability', async () => {
      const result = await _verifyInvocation({
        invocation: mock.exampleDocWithInvocation.beta,
        rootCapability: capabilities.root.beta,
        expectedAction: 'read'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should fail to verify a root capability as delegated', async () => {
      // root zcaps have no delegation proof to verify
      const root = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        controller: 'urn:some:root:id'
      };
      addToLoader({doc: root});
      const result = await _verifyDelegation({delegation: root});
      expect(result).to.exist;
      expect(result.verified).to.be.false;
    });

    it('should fail to invoke a root zcap with no controller', async () => {
      const root = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        invocationTarget: uuid()
      };
      addToLoader({doc: root});
      const doc = {
        '@context': ZCAP_CONTEXT_URL,
        'example:foo': uuid()
      };
      const invocation = await _invoke({
        doc, invoker: alpha, capability: root, capabilityAction: 'read'
      });
      const result = await _verifyInvocation({
        invocation, rootCapability: root, expectedAction: 'read'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.false;
      result.error.name.should.equal('VerificationError');
      const [error] = result.error.errors;
      error.message.should.contain('Capability controller not found');
    });

    it('should verify a invoking root capability w/ separate target when ' +
      'a matching `expectedRootCapability` is given', async () => {
      const root = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        invocationTarget: uuid(),
        controller: bob.id()
      };
      addToLoader({doc: root});
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: root, capabilityAction: 'read'
      });
      const result = await _verifyInvocation({
        invocation, rootCapability: root, expectedAction: 'read'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should verify a root capability w/ separate target when ' +
      'a matching `expectedRootCapability` array is given', async () => {
      const root = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        invocationTarget: uuid(),
        controller: bob.id()
      };
      addToLoader({doc: root});
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: root, capabilityAction: 'read'
      });
      const result = await _verifyInvocation({
        invocation, purposeOptions: {
          expectedAction: 'read',
          expectedRootCapability: [root.id],
          expectedTarget: root.invocationTarget
        }
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should fail to verify a root capability w/ separate target when ' +
      '`expectedRootCapability` is not a URI', async () => {
      const root = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        invocationTarget: uuid(),
        controller: bob.id()
      };
      addToLoader({doc: root});
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: root, capabilityAction: 'read'
      });
      // truncate the URN from the start of the root id
      // this will make it an invalid `expectedRootCapability` because
      // it is not an absolute URI
      const expectedRootCapability = [root.id.replace('urn:uuid:', '')];
      let result;
      let error;
      try {
        result = await _verifyInvocation({
          invocation, purposeOptions: {
            expectedAction: 'read',
            expectedRootCapability,
            expectedTarget: root.invocationTarget
          }
        });
      } catch(e) {
        error = e;
      }
      expect(result).to.not.exist;
      expect(error).to.exist;
      error.message.should.contain(
        '"expectedRootCapability" values must be absolute URI strings.');
    });

    it('should fail to verify a root capability w/ separate target when ' +
      'no `expectedRootCapability` is given', async () => {
      const root = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        invocationTarget: uuid(),
        controller: bob.id()
      };
      addToLoader({doc: root});
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: root, capabilityAction: 'read'
      });
      let error;
      let result;
      try {
        result = await _verifyInvocation({
          invocation, purposeOptions: {
            expectedAction: 'read',
            expectedTarget: root.invocationTarget
          }
        });
      } catch(e) {
        error = e;
      }
      expect(result).to.not.exist;
      expect(error).to.exist;
      error.name.should.equal('TypeError');
      error.message.should.contain(
        '"expectedRootCapability" must be a string or array.');
    });

    it('should verify two invocation proofs on the same doc', async () => {
      const doc = {
        '@context': ZCAP_CONTEXT_URL,
        'example:foo': uuid()
      };
      const target1 = 'https://zcap.example/target1';
      const target2 = 'https://zcap.example/target2';
      const invocation1 = await _invoke({
        doc, invoker: alice,
        purposeOptions: {
          capability: capabilities.root.restful.id,
          capabilityAction: 'read',
          invocationTarget: target1
        }
      });
      const invocation2 = await _invoke({
        doc: invocation1, invoker: alice,
        purposeOptions: {
          capability: capabilities.root.restful.id,
          capabilityAction: 'read',
          invocationTarget: target2
        }
      });
      // verify both invocation proofs for different targets
      const result = await jsigs.verify(invocation2, {
        suite: new Ed25519Signature2020(),
        purpose: [
          new CapabilityInvocation({
            allowTargetAttenuation: true,
            expectedAction: 'read',
            expectedRootCapability: capabilities.root.restful.id,
            expectedTarget: [
              capabilities.root.restful.invocationTarget,
              target1
            ]
          }),
          new CapabilityInvocation({
            allowTargetAttenuation: true,
            expectedAction: 'read',
            expectedRootCapability: capabilities.root.restful.id,
            expectedTarget: [
              capabilities.root.restful.invocationTarget,
              target2
            ]
          })
        ],
        documentLoader: testLoader
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should verify an invoked root capability w/ multiple controllers',
      async () => {
      const root = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        invocationTarget: uuid(),
        controller: ['urn:other', bob.id()],
      };
      addToLoader({doc: root});
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: root, capabilityAction: 'read'
      });
      const result = await _verifyInvocation({
        invocation, rootCapability: root, expectedAction: 'read'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should verify a root zcap w/ multiple controllers', async () => {
      const root = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        invocationTarget: uuid(),
        controller: ['urn:other', bob.id()],
      };
      addToLoader({doc: root});
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: root, capabilityAction: 'read'
      });
      const result = await _verifyInvocation({
        invocation, rootCapability: root, expectedAction: 'read'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should fail if expectedRootCapability does not match', async () => {
      // alice delegates to bob
      const delegatedCapability = await _delegate({
        parentCapability: capabilities.root.beta,
        controller: bob,
        delegator: alice,
        capabilityChain: [capabilities.root.beta.id]
      });

      // bob invokes
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: delegatedCapability,
        capabilityAction: 'read'
      });

      // should fail verification because of `expectedRootCapability`
      // does not match the root capability for bob's zcap
      const result = await _verifyInvocation({
        invocation, purposeOptions: {
          expectedAction: 'read',
          expectedRootCapability: 'urn:this-should-matter',
          expectedTarget: capabilities.root.beta.invocationTarget
        }
      });
      expect(result).to.exist;
      expect(result.verified).to.be.false;
      result.error.name.should.equal('VerificationError');
      const [error] = result.error.errors;
      error.message.should.contain('does not match actual root capability');
    });

    it('should verify a capability chain of depth 2', async () => {
      const delegatedCapability = await _delegate({
        parentCapability: capabilities.root.beta,
        controller: bob,
        delegator: alice,
        capabilityChain: [capabilities.root.beta.id]
      });
      const result = await _verifyDelegation({
        delegation: delegatedCapability
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should verify invoking a capability chain of depth 2 and a ' +
      '"read" expected action', async () => {
      // alice delegates to bob
      const delegatedCapability = await _delegate({
        parentCapability: capabilities.root.beta,
        controller: bob,
        delegator: alice,
        capabilityChain: [capabilities.root.beta.id]
      });

      // bob invokes
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: delegatedCapability,
        capabilityAction: 'read'
      });
      const result = await _verifyInvocation({
        invocation, rootCapability: capabilities.root.beta,
        expectedAction: 'read'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should verify invoking a capability chain of depth 2 and a ' +
      '"write" expected action', async () => {
      // alice delegates to bob w/o any action restriction
      const delegatedCapability = await _delegate({
        parentCapability: capabilities.root.beta,
        controller: bob,
        delegator: alice,
        capabilityChain: [capabilities.root.beta.id]
      });

      // bob invokes using `capabilityAction` of 'write' -- and since that
      // is an expected action by the verifier, it is allowed
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: delegatedCapability,
        capabilityAction: 'write'
      });
      const result = await _verifyInvocation({
        invocation, rootCapability: capabilities.root.beta,
        expectedAction: 'write'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should verify a capability chain of depth 2 and an ' +
      'allowed action on one capability', async () => {
      // alice delegates to bob and adds an allowed action restriction
      const newCapability = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        parentCapability: capabilities.root.beta.id,
        invocationTarget: capabilities.root.beta.invocationTarget,
        controller: bob.id(),
        allowedAction: 'write'
      };
      const delegatedCapability = await _delegate({
        newCapability, delegator: alice,
        capabilityChain: [capabilities.root.beta.id]
      });

      // bob invokes
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: delegatedCapability,
        capabilityAction: 'write'
      });

      // should verify because bob's specified capability action is one he
      // is allowed to use
      const result = await _verifyInvocation({
        invocation, rootCapability: capabilities.root.beta,
        expectedAction: 'write'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should fail to verify a capability chain of depth 2 when ' +
      'matching "capabilityAction" not found', async () => {
      // alice delegates to bob with `allowedAction: 'write'`
      const newCapability = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        parentCapability: capabilities.root.beta.id,
        invocationTarget: capabilities.root.beta.invocationTarget,
        controller: bob.id(),
        allowedAction: 'write'
      };
      const delegatedCapability = await _delegate({
        newCapability, delegator: alice,
        capabilityChain: [capabilities.root.beta.id]
      });

      // bob tries to invoke without setting any `capabilityAction`, so
      // an invocation proof that matches the expected action is not found
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: delegatedCapability,
        // this will be deleted below as the API does not allow
        // `capabilityAction` to be missing
        capabilityAction: ''
      });
      delete invocation.proof.capabilityAction;
      const result = await _verifyInvocation({
        invocation, purposeOptions: {
          expectedAction: 'write',
          expectedRootCapability: capabilities.root.beta.id,
          expectedTarget: capabilities.root.beta.invocationTarget
        }
      });
      expect(result).to.exist;
      expect(result.verified).to.be.false;
      result.error.name.should.equal('VerificationError');
      const [error] = result.error.errors;
      error.name.should.equal('NotFoundError');
    });

    it('should fail to verify a capability chain of depth 2 when a ' +
      '"capabilityAction" is not in "allowedAction"', async () => {
      // alice delegates to bob with `allowedAction: 'write'`
      const newCapability = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        parentCapability: capabilities.root.beta.id,
        invocationTarget: capabilities.root.beta.invocationTarget,
        controller: bob.id(),
        allowedAction: 'write'
      };
      const delegatedCapability = await _delegate({
        newCapability, delegator: alice,
        capabilityChain: [capabilities.root.beta.id]
      });

      // bob tries to invoke and sets `capabilityAction` to something other
      // an invocation proof that matches the expected action is not found
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: delegatedCapability,
        capabilityAction: 'invalid'
      });
      const result = await _verifyInvocation({
        invocation, rootCapability: capabilities.root.beta,
        expectedAction: 'write'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.false;
      result.error.name.should.equal('VerificationError');
      const [error] = result.error.errors;
      error.name.should.equal('NotFoundError');
    });

    it('should fail to verify a capability chain of depth 2 when ' +
      'required "capabilityAction" is missing', async () => {
      // alice delegates to bob w/o any action restrictions
      const newCapability = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        parentCapability: capabilities.root.beta.id,
        invocationTarget: capabilities.root.beta.invocationTarget,
        controller: bob.id()
      };
      const delegatedCapability = await _delegate({
        newCapability, delegator: alice,
        capabilityChain: [capabilities.root.beta.id]
      });

      // bob invokes using no specified capability action but the verifier
      // is expecting one, so no matching invocation proof should be found
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: delegatedCapability,
        // this will be deleted below as the API does not allow
        // `capabilityAction` to be missing
        capabilityAction: ''
      });
      delete invocation.proof.capabilityAction;
      const result = await _verifyInvocation({
        invocation, rootCapability: capabilities.root.beta,
        expectedAction: 'write'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.false;
      result.error.name.should.equal('VerificationError');
      const [error] = result.error.errors;
      error.name.should.equal('NotFoundError');
    });

    it('should fail to verify a capability chain of depth 2 when an ' +
      'expected "capabilityAction" does not match', async () => {
      // alice delegates to bob w/o any action restrictions
      const newCapability = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        parentCapability: capabilities.root.beta.id,
        invocationTarget: capabilities.root.beta.invocationTarget,
        controller: bob.id()
      };
      const delegatedCapability = await _delegate({
        newCapability, delegator: alice,
        capabilityChain: [capabilities.root.beta.id]
      });

      // bob tries to invoke using the 'write' capability action, but since
      // the verifier is expecting 'read', no matching invocation proof is
      // found
      const doc = clone(mock.exampleDoc);
      const invocation = await _invoke({
        doc, invoker: bob, capability: delegatedCapability,
        capabilityAction: 'write'
      });
      const result = await _verifyInvocation({
        invocation, rootCapability: capabilities.root.beta,
        expectedAction: 'read'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.false;
      result.error.name.should.equal('VerificationError');
      const [error] = result.error.errors;
      error.name.should.equal('NotFoundError');
    });

    describe('Chain depth of 3', () => {
      it('should verify chain', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        const result = await _verifyDelegation({delegation: carolDelCap});
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify chain with non-embedded last ' +
        'delegated zcap', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability

        // first check to ensure that delegation fails "client side"
        let carolDelCap;
        let localError;
        try {
          carolDelCap = await _delegate({
            newCapability: carolCap, delegator: bob,
            capabilityChain: [capabilities.root.beta.id, bobDelCap.id]
          });
        } catch(e) {
          localError = e;
        }
        expect(localError).to.exist;
        localError.name.should.equal('TypeError');
        localError.message.should.contain(
          'consist of strings of capability IDs');

        // now skip client-side validation
        carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          purposeOptions: {
            _skipLocalValidationForTesting: true,
            capabilityChain: [capabilities.root.beta.id, bobDelCap.id]
          }
        });

        const result = await _verifyDelegation({delegation: carolDelCap});
        should.exist(result);
        result.verified.should.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain('it must consist of strings');
      });

      it('should fail to verify chain with misreferenced parent ' +
        'zcap', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          // intentionally reference `alpha` instead of `beta` to trigger error
          capabilityChain: [capabilities.root.alpha.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        const result = await _verifyDelegation({delegation: carolDelCap});
        should.exist(result);
        result.verified.should.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain('does not match the parent');
      });

      it('should fail to verify a chain ' +
        'w/invalid allowedAction strings', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          allowedAction: 'read',
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          allowedAction: 'write',
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        const result = await _verifyDelegation({delegation: carolDelCap});
        should.exist(result);
        result.verified.should.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'delegated capability must be equivalent or more restrictive');
      });

      it('should fail to verify chain w/invalid allowedAction string ' +
        'vs array', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          allowedAction: 'read',
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          allowedAction: ['read', 'write'],
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        const result = await _verifyDelegation({delegation: carolDelCap});
        should.exist(result);
        result.verified.should.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'delegated capability must be equivalent or more restrictive');
      });

      it('should fail to verify chain ' +
        'w/invalid allowedAction arrays', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          allowedAction: ['read', 'write'],
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          allowedAction: ['foo', 'bar'],
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        const result = await _verifyDelegation({delegation: carolDelCap});
        should.exist(result);
        result.verified.should.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'delegated capability must be equivalent or more restrictive');
      });

      it('should verify chain when child allowedAction is ' +
        'a valid subset of the parent allowedAction array', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          allowedAction: ['read', 'write'],
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          allowedAction: ['read'],
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        const result = await _verifyDelegation({delegation: carolDelCap});
        should.exist(result);
        result.verified.should.be.true;
      });

      it('should verify chain when child allowedAction is ' +
        'a valid subset of the undefined parent allowedAction', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          allowedAction: 'read',
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        const result = await _verifyDelegation({delegation: carolDelCap});
        should.exist(result);
        result.verified.should.be.true;
      });

      it('should fail to verify chain w/bad middle capability', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        ///    capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });
        // change ID to something else (breaking signature)
        bobDelCap.id = uuid();

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        const result = await _verifyDelegation({delegation: carolDelCap});
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.name.should.equal('VerificationError');
      });

      it('should fail to verify chain w/bad last capability', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        ///    capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });
        // change ID to something else (breaking signature)
        carolDelCap.id = uuid();

        const result = await _verifyDelegation({delegation: carolDelCap});
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.equal('Invalid signature.');
      });

      it('should verify chain w/inspectCapabilityChain', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        let checkedChain = false;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain = true;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(2);
          capabilityChainMeta.should.be.an('array');
          capabilityChainMeta.should.have.length(2);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {valid: true};
        };
        const result = await _verifyDelegation({
          delegation: carolDelCap, inspectCapabilityChain
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
        checkedChain.should.be.true;
      });

      it('should fail to verify w/inspectCapabilityChain w/revoked capability',
        async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        let checkedChain = false;
        const inspectCapabilityChain = async ({
          capabilityChain
        }) => {
          checkedChain = true;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(2);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {
            error: new Error(`The capability "${capabilityChain[0].id}" ` +
              'has been revoked.'),
            valid: false,
          };
        };
        const result = await _verifyDelegation({
          delegation: carolDelCap, inspectCapabilityChain
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        expect(result.error.errors[0]).to.exist;
        result.error.errors[0].message.should.contain('revoked');
        checkedChain.should.be.true;
      });

      it('should fail to verify w/delegated zcap created before ' +
        'parent', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          // force proof creation date to be in the past
          date: new Date(0),
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        const result = await _verifyDelegation({
          delegation: carolDelCap, purposeOptions: {
            requireChainDateMonotonicity: true
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        expect(result.error.errors[0]).to.exist;
        result.error.errors[0].message.should.contain(
          'delegated before its parent');
      });

      it('should fail to verify w/delegated zcap with no expiration ' +
        'date', async () => {
        // TTL of 1 day
        const ttl = 1000 * 60 * 60 * 24;

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        const result = await _verifyDelegation({
          delegation: carolDelCap, purposeOptions: {
            // max TTL of 1 day
            maxDelegationTtl: ttl
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        expect(result.error.errors[0]).to.exist;
        result.error.errors[0].message.should.contain(
          'does not have an expiration date');
      });

      it('should fail to verify chain w/delegated zcap in the ' +
        'future', async () => {
        // TTL of 1 day
        const ttl = 1000 * 60 * 60 * 24;

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        // force delegation into the future
        const delegated = new Date(Date.now() + ttl);
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id(),
          expires: new Date(delegated.getTime() + ttl / 2).toISOString()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice, date: delegated,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id(),
          expires: bobDelCap.expires
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        const result = await _verifyDelegation({
          delegation: carolDelCap, purposeOptions: {
            maxDelegationTtl: ttl
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        expect(result.error.errors[0]).to.exist;
        result.error.errors[0].message.should.contain(
          'delegated in the future');
      });

      it('should fail to verify chain ' +
        'w/delegated zcap with a TTL that is too long', async () => {
        // TTL of 1 day
        const ttl = 1000 * 60 * 60 * 24;

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const delegated = new Date();
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id(),
          expires: new Date(delegated.getTime() + ttl + 1).toISOString()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice, date: delegated,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id(),
          expires: bobDelCap.expires
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        const result = await _verifyDelegation({
          delegation: carolDelCap, purposeOptions: {
            maxDelegationTtl: ttl
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        expect(result.error.errors[0]).to.exist;
        result.error.errors[0].message.should.contain(
          'time to live that is too long');
      });

      it('should verify invocation', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap,
          capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability: capabilities.root.beta,
          expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify chain w/ multiple delegators', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: ['urn:other', bob.id()]
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap,
          capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability: capabilities.root.beta,
          expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify invoking w/inspectCapabilityChain', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        let checkedChain = false;
        const inspectCapabilityChain = async ({
          capabilityChain
        }) => {
          checkedChain = true;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(2);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {valid: true};
        };
        const result = await _verifyInvocation({
          invocation, rootCapability: capabilities.root.beta,
          expectedAction: 'read',
          inspectCapabilityChain
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
        checkedChain.should.be.true;
      });

      it('should verify invoking ' +
        'w/TTL and delegation date monotonicity checks', async () => {
        // 24 hour TTL
        const ttl = 1000 * 60 * 60 * 24;

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id(),
          expires: new Date(Date.now() + ttl / 2).toISOString()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id(),
          expires: bobDelCap.expires
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        let checkedChain = false;
        const inspectCapabilityChain = async ({
          capabilityChain
        }) => {
          checkedChain = true;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(2);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {valid: true};
        };
        const result = await _verifyInvocation({
          invocation,
          purposeOptions: {
            expectedAction: 'read',
            expectedRootCapability: capabilities.root.beta.id,
            expectedTarget: capabilities.root.beta.invocationTarget,
            inspectCapabilityChain,
            maxDelegationTtl: ttl,
            requireChainDateMonotonicity: true
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
        checkedChain.should.be.true;
      });

      it('should fail invoking ' +
        'w/inspectCapabilityChain and a revoked capability', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        let checkedChain = false;
        const inspectCapabilityChain = async ({
          capabilityChain
        }) => {
          checkedChain = true;
          should.exist(capabilityChain);
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(2);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {
            error: new Error(
              `The capability "${capabilityChain[0].id}" has been revoked.`),
            valid: false,
          };
        };
        const result = await _verifyInvocation({
          invocation, rootCapability: capabilities.root.beta,
          expectedAction: 'read',
          inspectCapabilityChain
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        expect(result.error.errors[0]).to.exist;
        result.error.errors[0].message.should.contain('has been revoked');
        checkedChain.should.be.true;
      });
    }); // end Chain depth of 3

    describe('Expiration date', () => {
      it('CapabilityInvocation throws TypeError on currentDate = null',
        async () => {
        let result;
        let err;
        try {
          result = new CapabilityInvocation({
            expectedTarget:
              'urn:uuid:1aaec12f-bcf2-40d8-8192-cc4dde9bca96',
            suite: new Ed25519Signature2020(),
            currentDate: null,
          });
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.should.be.instanceof(TypeError);
        err.message.should.contain('must be a Date');
      });

      it('CapabilityDelegation throws TypeError on currentDate = null',
        async () => {
        let result;
        let err;
        try {
          result = new CapabilityDelegation({
            // `expectedRootCapability` must be present to signal this purpose
            // instance is for verifying a proof; otherwise different missing
            // param errors will be raised for creating a proof
            expectedRootCapability: 'urn:foo',
            currentDate: null
          });
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.should.be.instanceof(TypeError);
        err.message.should.contain('must be a Date');
      });

      it('should fail to verify root capability with `expires`',
        async () => {
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:d3e905ba-6430-11ec-beae-10bf48838a41';
        rootCapability.expires = (new Date()).toISOString();
        addToLoader({doc: rootCapability});

        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: alice, capability: rootCapability,
          capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability, expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'Root capability must not have an "expires" field.');
      });

      it('should verify invoking a capability with `expires`',
        async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:9ff561b8-0b3f-4bbc-af00-03ba785a7fc6';
        addToLoader({doc: rootCapability});

        let expires = new Date();
        expires.setHours(expires.getHours() + 1);
        expires = expires.toISOString();
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id(),
          expires
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id(),
          expires
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability, expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a capability with bad `expires` field',
        async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:0aee1dd6-646b-11ec-b975-10bf48838a41';
        addToLoader({doc: rootCapability});

        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id(),
          expires: 'not a valid date'
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: bob, capability: bobDelCap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability, expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.equal(
          'Delegated capability must have a valid expires date.');
      });

      it('should verify invoking a capability with `expires` ' +
        'and `currentDate` parameter in the past', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:1c919b19-baab-45ee-b0ef-24309dfb355d';
        addToLoader({doc: rootCapability});

        // the capability is presently expired
        let expires = new Date();
        expires.setHours(expires.getHours() - 10);
        expires = expires.toISOString();
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id(),
          expires
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id(),
          expires
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        // the capability was still valid 20 hours ago
        const currentDate = new Date();
        currentDate.setHours(currentDate.getHours() - 20);
        const result = await _verifyInvocation({
          invocation, purposeOptions: {
            expectedAction: 'read',
            expectedRootCapability: rootCapability.id,
            expectedTarget: rootCapability.invocationTarget,
            currentDate
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail invoking a capability with `expires` ' +
        'and `currentDate` parameter in the past', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:142b0b4a-c664-4288-84e6-be0a59b6efa4';
        addToLoader({doc: rootCapability});

        // the capability is presently expired
        let expires = new Date();
        expires.setHours(expires.getHours() - 50);
        expires = expires.toISOString();
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id(),
          expires
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id(),
          expires
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        // the capability was also expired 20 hours ago
        const currentDate = new Date();
        currentDate.setHours(currentDate.getHours() - 20);
        const result = await _verifyInvocation({
          invocation, purposeOptions: {
            expectedAction: 'read',
            expectedRootCapability: rootCapability.id,
            expectedTarget: rootCapability.invocationTarget,
            currentDate
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.equal(
          'A capability in the delegation chain has expired.');
      });

      it('should fail invoking a capability with `expires` ' +
        'and `currentDate` parameter in the future', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:bcbcde5e-d64a-4f46-a76e-daf52f63f702';
        addToLoader({doc: rootCapability});

        // the capability is presently valid
        let expires = new Date();
        expires.setHours(expires.getHours() + 50);
        expires = expires.toISOString();
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id(),
          expires
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id(),
          expires
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        // the capability will have expired in 100 hours
        const currentDate = new Date();
        currentDate.setHours(currentDate.getHours() + 100);
        const result = await _verifyInvocation({
          invocation, purposeOptions: {
            expectedAction: 'read',
            expectedRootCapability: rootCapability.id,
            expectedTarget: rootCapability.invocationTarget,
            suite: new Ed25519Signature2020(),
            currentDate,
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.equal(
          'A capability in the delegation chain has expired.');
      });

      it('should fail invoking a capability with missing `expires` in ' +
        'the second capability delegation', async () => {
        // the capability from alice to bob has proper expires, but the
        // capability from bob to carol does not

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:ae96f88e-6b8a-4445-9b4f-03f45c3d1685';
        addToLoader({doc: rootCapability});

        let expires = new Date();
        expires.setHours(expires.getHours() + 1);
        expires = expires.toISOString();
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id(),
          expires
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability, expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.include(
          'delegated capability must be equivalent or more restrictive');
      });

      it('should fail invoking a capability with ' +
        'capability that expires on the Unix epoch', async () => {
        // the delegated chain has expiration date in the past

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:cbddee5a-09fb-44db-a921-70c36436c253';
        addToLoader({doc: rootCapability});

        // set the expires to the Unix epoch
        let expires = new Date(0);
        expires = expires.toISOString();
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id(),
          expires
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id(),
          expires
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability, expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        should.exist(result.error);
        result.error.errors.should.have.length(1);
        const [error] = result.error.errors;
        error.message.should.equal(
          'A capability in the delegation chain has expired.');
      });

      it('should fail invoking a capability with expired ' +
        'second delegated capability', async () => {
        // bob's capability specifies a date in the future, but
        // the delegation from bob to carol specifies a date that is in the
        // past

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:3c034da3-8b5e-4fdc-b75d-8c37d73cd21e';
        addToLoader({doc: rootCapability});

        let expires = new Date();
        expires.setHours(expires.getHours() + 10);
        expires = expires.toISOString();
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id(),
          expires
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID

        // set expires for this delegation well in the past
        expires = new Date();
        expires.setHours(expires.getHours() - 10);
        expires = expires.toISOString();
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id(),
          expires
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability, expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'A capability in the delegation chain has expired.');
      });

      it('should fail invoking a capability with second delegated ' +
        'capability that expires on the Unix epoch', async () => {
        // bob's capability specifies a date in the future, but
        // the delegation from bob to carol specifies unix epoch date

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:6286a906-619b-4f5b-a8ae-af9fb774b070';
        addToLoader({doc: rootCapability});

        let expires = new Date();
        expires.setHours(expires.getHours() + 10);
        expires = expires.toISOString();
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id(),
          expires
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID

        // set expires for this delegation to the Unix epoch
        expires = new Date(0);
        expires = expires.toISOString();
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id(),
          expires
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability, expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        should.exist(result.error);
        result.error.errors.should.have.length(1);
        const [error] = result.error.errors;
        error.message.should.contain(
          'capability in the delegation chain has expired');
      });

      it('should fail invoking a capability with ' +
        'second delegated capability that expires after first', async () => {
        // bob's capability specifies a date in the future, but
        // the delegation from bob to carol specifies a date that is even
        // further into the future

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:1e7dfae9-85a3-40d7-97ea-20105f0b9d99';
        addToLoader({doc: rootCapability});

        let expires = new Date();
        expires.setHours(expires.getHours() + 10);
        expires = expires.toISOString();
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id(),
          expires
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID

        // set expires for this delegation beyond the expiration of the
        // parent capability, which is not allowed
        expires = new Date();
        expires.setHours(expires.getHours() + 100);
        expires = expires.toISOString();
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id(),
          expires
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability, expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'delegated capability must be equivalent or more restrictive');
      });

      it('should verify invoking a capability with only expires on ' +
        'second delegated capability', async () => {
        // only the second delegation has a valid future expiration

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:a0d0360b-7e93-4c9c-8804-69ca426c60c3';
        addToLoader({doc: rootCapability});

        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID

        // set expires for this delegation well in the past
        let expires = new Date();
        expires.setHours(expires.getHours() + 10);
        expires = expires.toISOString();
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id(),
          expires
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability, expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail invoking a capability with only an expired ' +
        'second delegated capability', async () => {
        // only the second delegation has an expiration in the past

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:2c41869c-95bb-4e23-9bcd-2fbb320bb440';
        addToLoader({doc: rootCapability});

        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID

        // set expires for this delegation well in the past
        let expires = new Date();
        expires.setHours(expires.getHours() - 10);
        expires = expires.toISOString();
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id(),
          expires
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability, expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.equal(
          'A capability in the delegation chain has expired.');
      });
    }); // end Expiration date

    describe('Chain depth of 4', () => {
      it('should verify chain w/inspectCapabilityChain', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        // Create a delegated capability for Diana
        //   4. Parent capability should point to Carol's capability
        //   5. The controller should be Diana's ID
        const dianaCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          invocationTarget: carolCap.invocationTarget,
          controller: diana.id()
        };
        //  6. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability
        const dianaDelCap = await _delegate({
          newCapability: dianaCap, delegator: carol,
          capabilityChain: [
            capabilities.root.beta.id, bobDelCap.id, carolDelCap
          ]
        });

        let checkedChain = false;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain = true;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(3);
          capabilityChainMeta.should.be.an('array');
          capabilityChainMeta.should.have.length(3);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {valid: true};
        };

        const result = await _verifyDelegation({
          delegation: dianaDelCap, inspectCapabilityChain
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
        checkedChain.should.be.true;
      });

      it('should fail to verify w/embedded middle zcap', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        // Create a delegated capability for Diana
        //   4. Parent capability should point to Carol's capability
        //   5. The controller should be Diana's ID
        const dianaCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          invocationTarget: carolCap.invocationTarget,
          controller: diana.id()
        };
        //  6. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability

        // first check to ensure that delegation fails "client side"
        let dianaDelCap;
        let localError;
        try {
          dianaDelCap = await _delegate({
            newCapability: dianaCap, delegator: carol,
            capabilityChain: [capabilities.root.beta.id, bobDelCap, carolDelCap]
          });
        } catch(e) {
          localError = e;
        }
        expect(localError).to.exist;
        localError.name.should.equal('TypeError');
        localError.message.should.contain(
          'consist of strings of capability IDs');

        // now skip client-side validation
        dianaDelCap = await _delegate({
          newCapability: dianaCap, delegator: carol,
          purposeOptions: {
            _skipLocalValidationForTesting: true,
            capabilityChain: [capabilities.root.beta.id, bobDelCap, carolDelCap]
          }
        });

        const result = await _verifyDelegation({
          delegation: dianaDelCap
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        should.exist(result.error.errors);
        const [error] = result.error.errors;
        error.message.should.contain(
          'consist of strings of capability IDs');
      });

      it('should fail to verify chain exceeding maxChainLength', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        // Create a delegated capability for Diana
        //   4. Parent capability should point to Carol's capability
        //   5. The controller should be Diana's ID
        const dianaCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          invocationTarget: carolCap.invocationTarget,
          controller: diana.id()
        };
        //  6. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability
        const dianaDelCap = await _delegate({
          newCapability: dianaCap, delegator: carol,
          capabilityChain: [
            capabilities.root.beta.id, bobDelCap.id, carolDelCap
          ]
        });

        let checkedChain = false;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain = true;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(3);
          capabilityChainMeta.should.be.an('array');
          capabilityChainMeta.should.have.length(3);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {valid: true};
        };

        const result = await _verifyDelegation({
          delegation: dianaDelCap, purposeOptions: {
            inspectCapabilityChain,
            maxChainLength: 2
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        should.exist(result.error);
        should.exist(result.error.errors);
        result.error.errors.should.have.length(1);
        result.error.errors[0].message.should.equal(
          'The capability chain exceeds the maximum allowed length of 2.');
        // should not get to check chain because of invalid chain length
        checkedChain.should.be.false;
      });

      it('should verify chain ' +
        'w/inspectCapabilityChain using embedded capabilities from ' +
        'capabilityChain', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [capabilities.root.beta.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [capabilities.root.beta.id, bobDelCap]
        });

        // Create a delegated capability for Diana
        //   4. Parent capability should point to Carol's capability
        //   5. The controller should be Diana's ID
        const dianaCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          invocationTarget: carolCap.invocationTarget,
          controller: diana.id()
        };
        //  6. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability
        const dianaDelCap = await _delegate({
          newCapability: dianaCap, delegator: carol,
          capabilityChain: [
            capabilities.root.beta.id, bobDelCap.id, carolDelCap
          ]
        });

        let checkedChain = false;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain = true;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(3);
          capabilityChainMeta.should.be.an('array');
          capabilityChainMeta.should.have.length(3);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {valid: true};
        };

        const result = await _verifyDelegation({
          delegation: dianaDelCap, inspectCapabilityChain
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
        checkedChain.should.be.true;
      });
    }); // end Chain depth of 4

    describe('Path-based hierarchical attenuation', () => {
      it('should verify chain', async () => {
        const rootTarget =
          'https://example.com/edvs/cc8b09fd-76e2-4fae-9bdd-2522b83a2971';
        const rootCapability = {
          // FIXME: add zcapld helper for creating root zcaps from a target
          '@context': ZCAP_CONTEXT_URL,
          id: `${ZCAP_ROOT_PREFIX}${encodeURIComponent(rootTarget)}`,
          controller: alice.id(),
          invocationTarget: rootTarget
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        // Create a delegated capability for Diana
        //   7. Parent capability should point to Carol's capability
        //   8. The controller should be Diana's ID

        // delegate access to a specific document under carol's capability
        const invocationTarget =
          `${carolCap.invocationTarget}/a-specific-document`;
        const dianaCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          invocationTarget,
          controller: diana.id()
        };

        //  9. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability
        const dianaDelCap = await _delegate({
          newCapability: dianaCap, delegator: carol,
          capabilityChain: [rootCapability.id, bobDelCap.id, carolDelCap]
        });

        const result = await _verifyDelegation({
          delegation: dianaDelCap, purposeOptions: {
            allowTargetAttenuation: true
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify chain with attenuation that is more ' +
        'permissive than the parent capability', async () => {
        const rootTarget =
          'https://example.com/edvs/357570f6-8df2-4e78-97dc-42260d64e78e';
        const rootCapability = {
          // FIXME: add zcapld helper for creating root zcaps from a target
          '@context': ZCAP_CONTEXT_URL,
          id: `${ZCAP_ROOT_PREFIX}${encodeURIComponent(rootTarget)}`,
          controller: alice.id(),
          invocationTarget: rootTarget
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID

        // delegate access to a specific document under bob's capability
        const invocationTarget =
          `${bobCap.invocationTarget}/a-specific-document`;
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        // Create a delegated capability for Diana
        //   7. Parent capability should point to Carol's capability
        //   8. The controller should be Diana's ID

        const dianaCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          // NOTE: this is an invalid attempt to degate a capability to the
          // root of the EDV when carol's zcap has an invocationTarget that
          // is a specific EDV document
          invocationTarget: bobCap.invocationTarget,
          controller: diana.id()
        };

        //  9. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability
        const dianaDelCap = await _delegate({
          newCapability: dianaCap, delegator: carol,
          capabilityChain: [rootCapability.id, bobDelCap.id, carolDelCap]
        });

        const result = await _verifyDelegation({
          delegation: dianaDelCap, purposeOptions: {
            allowTargetAttenuation: true
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.errors.should.have.length(1);
        const [error] = result.error.errors[0].errors;
        error.message.should.include(
          'delegated capability must be equivalent or more restrictive');
      });

      it('should verify when invoking at an exact-match target', async () => {
        const rootTarget = `https://example.com/edvs/${uuid()}`;
        const rootCapability = {
          // FIXME: add zcapld helper for creating root zcaps from a target
          '@context': ZCAP_CONTEXT_URL,
          id: `${ZCAP_ROOT_PREFIX}${encodeURIComponent(rootTarget)}`,
          invocationTarget: rootTarget,
          controller: alice.id()
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID

        // delegate access to a specific document under bob's capability
        const invocationTarget =
          `${bobCap.invocationTarget}/a-specific-document`;
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolDelCap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, purposeOptions: {
            allowTargetAttenuation: true,
            expectedAction: 'read',
            expectedTarget: [rootTarget, invocationTarget],
            expectedRootCapability: rootCapability.id
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify when invoking at an unexpected ' +
        'target', async () => {
        const rootTarget = `https://example.com/edvs/${uuid()}`;
        const rootCapability = {
          // FIXME: add zcapld helper for creating root zcaps from a target
          '@context': ZCAP_CONTEXT_URL,
          id: `${ZCAP_ROOT_PREFIX}${encodeURIComponent(rootTarget)}`,
          invocationTarget: rootTarget,
          controller: alice.id()
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID

        // delegate access to a specific document under bob's capability
        const invocationTarget =
          `${bobCap.invocationTarget}/a-specific-document`;
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        // Note: This is intentionally an invalid target (a doc that
        // carol should not have access to)
        const invalidTarget = `${rootTarget}/a-different-specific-document`;
        const invocation = await _invoke({
          doc, invoker: carol,
          purposeOptions: {
            capability: carolDelCap,
            capabilityAction: 'read',
            invocationTarget: invalidTarget
          }
        });
        const expectedTarget = [rootTarget, invocationTarget];
        const purpose = new CapabilityInvocation({
          allowTargetAttenuation: true,
          expectedAction: 'read',
          expectedTarget,
          expectedRootCapability: rootCapability.id,
          suite: new Ed25519Signature2020()
        });
        // force match to true to test expected target code path
        purpose.match = () => true;
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2020(),
          purpose,
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.errors.should.have.length(1);
        const [error] = result.error.errors;
        error.message.should.include(
          `Expected target (${expectedTarget}) does not match ` +
          `invocation target (${invalidTarget})`);
      });

      it('should verify when invoking at a valid sub target', async () => {
        const rootTarget = `https://example.com/edvs/${uuid()}`;
        const rootCapability = {
          // FIXME: add zcapld helper for creating root zcaps from a target
          '@context': ZCAP_CONTEXT_URL,
          id: `${ZCAP_ROOT_PREFIX}${encodeURIComponent(rootTarget)}`,
          invocationTarget: rootTarget,
          controller: alice.id()
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID

        // delegate access to a specific document under bob's capability
        const invocationTarget =
          `${bobCap.invocationTarget}/a-specific-document`;
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        // Note: This is an attenuated path off of carol's zcap's target
        const validSubTarget = `${carolDelCap.invocationTarget}/sub-path`;
        const invocation = await _invoke({
          doc, invoker: carol,
          purposeOptions: {
            capability: carolCap,
            capabilityAction: 'read',
            invocationTarget: validSubTarget
          }
        });
        const result = await _verifyInvocation({
          invocation, purposeOptions: {
            allowTargetAttenuation: true,
            expectedAction: 'read',
            expectedTarget: [rootTarget, validSubTarget],
            expectedRootCapability: rootCapability.id
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify when invoking at an invalid ' +
        'target', async () => {
        const rootTarget = `https://example.com/edvs/${uuid()}`;
        const rootCapability = {
          // FIXME: add zcapld helper for creating root zcaps from a target
          '@context': ZCAP_CONTEXT_URL,
          id: `${ZCAP_ROOT_PREFIX}${encodeURIComponent(rootTarget)}`,
          invocationTarget: rootTarget,
          controller: alice.id()
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID

        // delegate access to a specific document under bob's capability
        const invocationTarget =
          `${bobCap.invocationTarget}/a-specific-document`;
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        //   7. Use Carol's invocation key that can be found in Carol's
        //      controller document of keys
        //   8. The controller should be Carol's ID
        const doc = clone(mock.exampleDoc);
        // Note: This is intentionally an invalid target (a doc that
        // carol should not have access to)
        const invalidTarget = `${rootTarget}/a-different-specific-document`;
        const invocation = await _invoke({
          doc, invoker: carol,
          purposeOptions: {
            capability: carolCap,
            capabilityAction: 'read',
            invocationTarget: invalidTarget
          }
        });
        const result = await _verifyInvocation({
          invocation, purposeOptions: {
            allowTargetAttenuation: true,
            expectedAction: 'read',
            // Note: Here we are simulating an endpoint that is expecting
            // the `invalidTarget` -- it's just that the zcap being used
            // is not authorized for that target.
            expectedTarget: [rootTarget, invalidTarget],
            expectedRootCapability: rootCapability.id
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.errors.should.have.length(1);
        const [error] = result.error.errors;
        error.message.should.include(
          `Invocation target (${invalidTarget}) does not match capability ` +
          `target (${carolDelCap.invocationTarget})`);
      });

      it('should fail to verify when allowTargetAttenuation is not ' +
        'explicitly allowed', async () => {
        const rootTarget =
          'https://example.com/edvs/2c2fe4ab-ff54-4a82-b103-f806f50d364e';
        const rootCapability = {
          // FIXME: add zcapld helper for creating root zcaps from a target
          '@context': ZCAP_CONTEXT_URL,
          id: `${ZCAP_ROOT_PREFIX}${encodeURIComponent(rootTarget)}`,
          controller: alice.id(),
          invocationTarget: rootTarget
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        // Create a delegated capability for Diana
        //   4. Parent capability should point to Carol's capability
        //   5. The controller should be Diana's ID

        // delegate access to a specific document under carol's capability
        const invocationTarget =
          `${carolCap.invocationTarget}/a-specific-document`;
        const dianaCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          invocationTarget,
          controller: diana.id()
        };

        //  6. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability
        const dianaDelCap = await _delegate({
          newCapability: dianaCap, delegator: carol,
          capabilityChain: [rootCapability.id, bobDelCap.id, carolDelCap]
        });

        // NOTE: allowTargetAttenuation is intentionally not set
        // here, the default is false
        const result = await _verifyDelegation({delegation: dianaDelCap});
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.errors.should.have.length(1);
        const [error] = result.error.errors[0].errors;
        error.message.should.contain('must be equivalent to its parent');
      });

      it('should verify chain w/inspectCapabilityChain', async () => {
        const rootTarget =
          'https://example.com/edvs/83d7e997-d742-4b1a-9033-968f222b9144';
        const rootCapability = {
          // FIXME: add zcapld helper for creating root zcaps from a target
          '@context': ZCAP_CONTEXT_URL,
          id: `${ZCAP_ROOT_PREFIX}${encodeURIComponent(rootTarget)}`,
          controller: alice.id(),
          invocationTarget: rootTarget
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        // Create a delegated capability for Diana
        //   4. Parent capability should point to Carol's capability
        //   5. The controller should be Diana's ID

        // delegate access to a specific document under carol's capability
        const invocationTarget =
          `${carolCap.invocationTarget}/a-specific-document`;
        const dianaCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          invocationTarget,
          controller: diana.id()
        };

        //  6. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability
        const dianaDelCap = await _delegate({
          newCapability: dianaCap, delegator: carol,
          capabilityChain: [rootCapability.id, bobDelCap.id, carolDelCap]
        });

        let checkedChain = false;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain = true;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(3);
          capabilityChainMeta.should.be.an('array');
          capabilityChainMeta.should.have.length(3);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {valid: true};
        };

        const result = await _verifyDelegation({
          delegation: dianaDelCap, purposeOptions: {
            allowTargetAttenuation: true,
            inspectCapabilityChain
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
        checkedChain.should.be.true;
      });

      it('should fail to verify an increasingly permissive chain ' +
        'w/inspectCapabilityChain', async () => {
        const rootTarget =
          'https://example.com/edvs/d9dd2093-0908-47ba-8db7-954ff1cd81ee';
        const rootCapability = {
          // FIXME: add zcapld helper for creating root zcaps from a target
          '@context': ZCAP_CONTEXT_URL,
          id: `${ZCAP_ROOT_PREFIX}${encodeURIComponent(rootTarget)}`,
          controller: alice.id(),
          invocationTarget: rootTarget
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The controller should be Bob's ID
        const bobCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.invocationTarget,
          controller: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await _delegate({
          newCapability: bobCap, delegator: alice,
          capabilityChain: [rootCapability.id]
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The controller should be Carol's ID

        // delegate access to a specific document under bob's capability
        const invocationTarget =
          `${bobCap.invocationTarget}/a-specific-document`;
        const carolCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget,
          controller: carol.id()
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await _delegate({
          newCapability: carolCap, delegator: bob,
          capabilityChain: [rootCapability.id, bobDelCap]
        });

        // Create a delegated capability for Diana
        //   4. Parent capability should point to Carol's capability
        //   5. The controller should be Diana's ID
        const dianaCap = {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          // NOTE: this is an invalid attempt to degate a capability to the
          // root of the EDV when carol's zcap has an invocationTarget that
          // is a specific EDV document
          invocationTarget: bobCap.invocationTarget,
          controller: diana.id()
        };

        //  6. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability
        const dianaDelCap = await _delegate({
          newCapability: dianaCap, delegator: carol,
          capabilityChain: [rootCapability.id, bobDelCap.id, carolDelCap]
        });

        let checkedChain = false;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain = true;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(3);
          capabilityChainMeta.should.be.an('array');
          capabilityChainMeta.should.have.length(3);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {valid: true};
        };

        const result = await _verifyDelegation({
          delegation: dianaDelCap, purposeOptions: {
            allowTargetAttenuation: true,
            inspectCapabilityChain
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.errors.should.have.length(1);
        result.error.errors[0].errors.should.have.length(1);
        const [error] = result.error.errors[0].errors;
        error.message.should.include(
          'delegated capability must be equivalent or more restrictive');
        // should not get to check chain because of invalid zcap
        checkedChain.should.be.false;
      });
    }); // end Path-based hierarchical attenuation
  });
});

function _checkCapabilityChain({capabilityChain}) {
  for(const c of capabilityChain) {
    c.should.be.an('object');
    c.should.have.property('id');
    c.should.have.property('controller');
  }
}

// helper for creating invocations
// pass `key` OR `controller` (not both)
// pass `capability` OR `purposeOptions` (not both)
async function _invoke({
  doc, key, invoker, date, capability, capabilityAction, purposeOptions
}) {
  if(invoker) {
    key = invoker.get('capabilityInvocation', 0);
  }
  let purpose;
  if(capability) {
    // common case
    purpose = new CapabilityInvocation({
      // MUST pass root zcap as a string, delegated zcap as an object
      capability: capability.parentCapability ? capability : capability.id,
      capabilityAction,
      invocationTarget: capability.invocationTarget
    });
  } else {
    // custom case
    purpose = new CapabilityInvocation(purposeOptions);
  }
  return jsigs.sign(doc, {
    documentLoader: testLoader,
    suite: new Ed25519Signature2020({
      key: new Ed25519VerificationKey2020(key),
      date
    }),
    purpose
  });
}

async function _verifyInvocation({
  invocation, rootCapability, expectedAction, inspectCapabilityChain,
  purposeOptions
}) {
  let purpose;
  if(rootCapability) {
    // common case
    purpose = new CapabilityInvocation({
      expectedTarget: rootCapability.invocationTarget,
      expectedRootCapability: rootCapability.id,
      expectedAction,
      inspectCapabilityChain,
      suite: new Ed25519Signature2020()
    });
  } else {
    // custom case
    purpose = new CapabilityInvocation({
      suite: new Ed25519Signature2020(),
      ...purposeOptions
    });
  }
  return jsigs.verify(invocation, {
    documentLoader: testLoader,
    suite: new Ed25519Signature2020(),
    purpose
  });
}

async function _delegate({
  newCapability, parentCapability, controller, key, delegator, date,
  capabilityChain, purposeOptions
}) {
  if(delegator) {
    key = delegator.get('capabilityDelegation', 0);
  }
  let purpose;
  if(capabilityChain) {
    // common case
    purpose = new CapabilityDelegation({capabilityChain});
  } else {
    // custom case
    purpose = new CapabilityDelegation(purposeOptions);
  }
  if(!newCapability) {
    // use parent capability
    newCapability = {
      '@context': ZCAP_CONTEXT_URL,
      id: uuid(),
      controller: typeof controller === 'string' ? controller : controller.id(),
      parentCapability: parentCapability.id,
      invocationTarget: parentCapability.invocationTarget
    };
  }
  return jsigs.sign(newCapability, {
    documentLoader: testLoader,
    suite: new Ed25519Signature2020({
      key: new Ed25519VerificationKey2020(key),
      date
    }),
    purpose
  });
}

async function _verifyDelegation({
  delegation, inspectCapabilityChain, purposeOptions = {}
}) {
  return jsigs.verify(delegation, {
    documentLoader: testLoader,
    suite: new Ed25519Signature2020(),
    purpose: new CapabilityDelegation({
      suite: new Ed25519Signature2020(),
      inspectCapabilityChain,
      ...purposeOptions
    })
  });
}

};
