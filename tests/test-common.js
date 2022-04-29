/*!
 * Copyright (c) 2018-2022 Digital Bazaar, Inc. All rights reserved.
 */

import chai from 'chai';

import {
  Ed25519Signature2020
} from '@digitalbazaar/ed25519-signature-2020';
import {
  Ed25519VerificationKey2020
} from '@digitalbazaar/ed25519-verification-key-2020';

const should = chai.should();

/* eslint-disable indent */
export default async function(options) {

const {expect, helpers, jsigs, mock, zcap} = options;

const {
  CapabilityInvocation,
  CapabilityDelegation,
  createRootCapability,
  constants: {ZCAP_CONTEXT_URL}
} = zcap;

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
const EXPIRES_3000_DATE = '3000-01-01T00:01Z';

// run tests
describe('zcap', () => {
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
      expect(err.message).to.equal(
        '"invocationTarget" must be a string that expresses an absolute URI.');
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
        controller: bob.get('capabilityInvocation', 0).id,
        parentCapability: capabilities.root.alpha.id,
        invocationTarget: capabilities.root.alpha.invocationTarget,
        expires: EXPIRES_3000_DATE
      };
      // 3. Sign the delegated capability with Alice's delegation key
      // (this works because Alice is the root capability's controller)
      const delegatedCapability = await _delegate({
        newCapability,
        parentCapability: capabilities.root.alpha,
        delegator: alice,
        date: CONSTANT_DATE
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
        controller: bob.id(),
        parentCapability: capabilities.root.beta.id,
        invocationTarget: capabilities.root.beta.invocationTarget,
        expires: EXPIRES_3000_DATE
      };
      // 3. Sign the delegated capability with Alice's delegation key
      // (this works because Alice is the root capability's controller)
      const delegatedCapability = await _delegate({
        newCapability,
        parentCapability: capabilities.root.beta,
        delegator: alice,
        date: CONSTANT_DATE
      });
      expect(delegatedCapability).to.deep.equal(capabilities.delegated.beta);
    });

    it('should fail when missing "parentCapability"',
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
        '"parentCapability" must be a string expressing the ID of a root ' +
        'capability or an object expressing the full parent capability.');
    });

    it('should succeed when passing only "parentCapability"', async () => {
      // only pass `parentCapability` as a purpose option -- this will cause
      // the `capabilityChain` to be auto-generated
      const newCapability = {
        '@context': ZCAP_CONTEXT_URL,
        id: 'urn:uuid:710910c8-61e4-11ec-8739-10bf48838a41',
        controller: bob.id(),
        parentCapability: capabilities.root.beta.id,
        invocationTarget: capabilities.root.beta.invocationTarget,
        expires: EXPIRES_3000_DATE
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
        delegator: alice
      });
      const result = await _verifyDelegation({
        delegation: delegatedCapability,
        expectedRootCapability: capabilities.root.alpha.id
      });
      expect(result).to.exist;
      expect(result.verified).to.be.true;
    });

    it('should fail to verify a capability chain of depth 2 ' +
      'when the expectedRootCapability does not match', async () => {
      const delegatedCapability = await _delegate({
        parentCapability: capabilities.root.alpha,
        controller: bob.get('capabilityInvocation', 0).id,
        delegator: alice
      });
      const result = await _verifyDelegation({
        delegation: delegatedCapability,
        expectedRootCapability: 'urn:uuid:fake'
      });
      expect(result).to.exist;
      expect(result.verified).to.be.false;
      result.error.name.should.equal('VerificationError');
      const [error] = result.error.errors;
      error.message.should.contain('does not match expected root capability');
    });

    it('should verify invoking a capability chain of depth 2', async () => {
      // delegate from alice to bob
      const delegatedCapability = await _delegate({
        parentCapability: capabilities.root.alpha,
        controller: bob.get('capabilityInvocation', 0).id,
        delegator: alice
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
        controller: 'urn:some:root:id',
        invocationTarget: 'urn:some:invocation:target'
      };
      addToLoader({doc: root});
      const result = await _verifyDelegation({
        delegation: root,
        expectedRootCapability: root.id
      });
      expect(result).to.exist;
      expect(result.verified).to.be.false;
    });

    it('should fail to invoke a root zcap with no controller', async () => {
      const root = {
        '@context': ZCAP_CONTEXT_URL,
        id: uuid(),
        // `controller` intentionally missing
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
        controller: bob.id(),
        invocationTarget: uuid()
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
        controller: bob.id(),
        invocationTarget: uuid()
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
        controller: bob.id(),
        invocationTarget: uuid()
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
        controller: ['urn:other', bob.id()],
        invocationTarget: uuid()
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
        controller: ['urn:other', bob.id()],
        invocationTarget: uuid()
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
        delegator: alice
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
      error.message.should.contain('does not match expected root capability');
    });

    it('should verify a capability chain of depth 2', async () => {
      const delegatedCapability = await _delegate({
        parentCapability: capabilities.root.beta,
        controller: bob,
        delegator: alice
      });
      const result = await _verifyDelegation({
        delegation: delegatedCapability,
        expectedRootCapability: capabilities.root.beta.id
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
        delegator: alice
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
        delegator: alice
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
      const delegatedCapability = await _delegate({
        newCapability: {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          controller: bob.id(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          expires: EXPIRES_3000_DATE,
          allowedAction: 'write'
        },
        parentCapability: capabilities.root.beta,
        delegator: alice
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
      const delegatedCapability = await _delegate({
        newCapability: {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          controller: bob.id(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          expires: EXPIRES_3000_DATE,
          allowedAction: 'write'
        },
        parentCapability: capabilities.root.beta,
        delegator: alice
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
      const delegatedCapability = await _delegate({
        newCapability: {
          '@context': ZCAP_CONTEXT_URL,
          id: uuid(),
          controller: bob.id(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.invocationTarget,
          expires: EXPIRES_3000_DATE,
          allowedAction: 'write'
        },
        parentCapability: capabilities.root.beta,
        delegator: alice
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
      const delegatedCapability = await _delegate({
        parentCapability: capabilities.root.beta,
        controller: bob,
        delegator: alice
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
      const delegatedCapability = await _delegate({
        parentCapability: capabilities.root.beta,
        controller: bob,
        delegator: alice
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
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify chain with embedded root ' +
        'zcap in chain', async () => {
        // alice attempts to delegate to bob w/bad chain
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice,
          // override chain
          // bad last entry of an embedded root zcap instead of an ID string
          _capabilityChain: [capabilities.root.beta]
        });

        // bob delegates to carol...
        // first check to ensure that delegation fails "client side"
        let carolZcap;
        let localError;
        try {
          // bob attempts to delegate to carol
          carolZcap = await _delegate({
            parentCapability: bobZcap,
            controller: carol,
            delegator: bob
          });
        } catch(e) {
          localError = e;
        }
        expect(localError).to.exist;
        localError.name.should.equal('TypeError');
        localError.message.should.contain(
          'consist of strings of capability IDs');

        // now skip client-side validation
        // bob delegates to carol (erroneously and the API allows it because
        // of the special `_skipLocalValidationForTesting` flag)
        carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob,
          purposeOptions: {
            // do not throw on bad last chain entry to test catching it
            // when verifying
            _skipLocalValidationForTesting: true
          }
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id
        });
        should.exist(result);
        result.verified.should.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain('it must consist of strings');
      });

      it('should fail to verify chain with non-embedded last ' +
        'delegated zcap', async () => {
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // now skip client-side validation
        // bob delegates to carol (erroneously and the API allows it because
        // of the special `_skipLocalValidationForTesting` flag)
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob,
          purposeOptions: {
            // do not throw on bad last chain entry to test catching it
            // when verifying
            _skipLocalValidationForTesting: true,
            // override chain
            // bad last chain entry
            _capabilityChain: [capabilities.root.beta.id, bobZcap.id]
          }
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id
        });
        should.exist(result);
        result.verified.should.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain('it must consist of strings');
      });

      it('should fail to verify chain with misreferenced parent ' +
        'zcap in middle of chain', async () => {
        // alice delegates to bob but with bad root reference in chain
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice,
          // override chain
          // intentionally reference `alpha` instead of `beta` to trigger error
          _capabilityChain: [capabilities.root.alpha.id]
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob,
          // override chain
          // proper capability chain
          _capabilityChain: [capabilities.root.beta.id, bobZcap]
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id
        });
        should.exist(result);
        result.verified.should.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain('does not match the parent');
      });

      it('should fail to verify chain with misreferenced parent ' +
        'zcap at end of chain', async () => {
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // alice delegates to diana (this zcap will be misreferenced as
        // the parent zcap of carol's below)
        const dianaZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: diana,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob,
          // override chain
          // intentionally reference diana's zcap instead of bob's
          _capabilityChain: [capabilities.root.alpha.id, dianaZcap]
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id
        });
        should.exist(result);
        result.verified.should.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain('does not match the parent');
      });

      it('should fail to verify a chain ' +
        'w/invalid allowedAction strings', async () => {
        // alice delegates to bob w/ allowed action restriction
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.invocationTarget,
            expires: EXPIRES_3000_DATE,
            allowedAction: 'read'
          },
          parentCapability: capabilities.root.beta,
          delegator: alice
        });

        // bob delegates to carol...
        // first check to ensure that delegation fails "client side"
        let carolZcap;
        let localError;
        try {
          // bob attempts to delegate to carol
          carolZcap = await _delegate({
            newCapability: {
              '@context': ZCAP_CONTEXT_URL,
              id: uuid(),
              controller: carol.id(),
              parentCapability: bobZcap.id,
              invocationTarget: bobZcap.invocationTarget,
              expires: EXPIRES_3000_DATE,
              allowedAction: 'write'
            },
            parentCapability: bobZcap,
            delegator: bob
          });
        } catch(e) {
          localError = e;
        }
        expect(localError).to.exist;
        localError.name.should.equal('Error');
        localError.message.should.equal(
          'The "allowedAction" in a delegated capability ' +
          'must not be less restrictive than its parent.');

        // bob tries to delegate to carol with an allowed action restriction
        // that bob is not allowed to set (bob can't let carol "write")
        carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires: EXPIRES_3000_DATE,
            allowedAction: 'write'
          },
          purposeOptions: {
            // skip local validation to allow the zcap to be delegated so it
            // can be checked by the verifier
            _skipLocalValidationForTesting: true
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id
        });
        should.exist(result);
        result.verified.should.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'delegated capability must not be less restrictive');
      });

      it('should fail to verify chain w/invalid allowedAction string ' +
        'vs array', async () => {
        // alice delegates to bob w/ allow action restriction
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.invocationTarget,
            expires: EXPIRES_3000_DATE,
            allowedAction: 'read'
          },
          parentCapability: capabilities.root.beta,
          delegator: alice
        });

        // bob delegates to carol...
        // first check to ensure that delegation fails "client side"
        let carolZcap;
        let localError;
        try {
          // bob attempts to delegate to carol
          carolZcap = await _delegate({
            newCapability: {
              '@context': ZCAP_CONTEXT_URL,
              id: uuid(),
              controller: carol.id(),
              parentCapability: bobZcap.id,
              invocationTarget: bobZcap.invocationTarget,
              expires: EXPIRES_3000_DATE,
              allowedAction: ['read', 'write']
            },
            parentCapability: bobZcap,
            delegator: bob
          });
        } catch(e) {
          localError = e;
        }
        expect(localError).to.exist;
        localError.name.should.equal('Error');
        localError.message.should.equal(
          'The "allowedAction" in a delegated capability ' +
          'must not be less restrictive than its parent.');

        // bob delegates to carol with less restrictive allowed action rule
        // that he is not allowed to make
        carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires: EXPIRES_3000_DATE,
            allowedAction: ['read', 'write']
          },
          purposeOptions: {
            // skip local validation to allow the zcap to be delegated so it
            // can be checked by the verifier
            _skipLocalValidationForTesting: true
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id
        });
        should.exist(result);
        result.verified.should.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'delegated capability must not be less restrictive');
      });

      it('should fail to verify chain ' +
        'w/invalid allowedAction arrays', async () => {
        // alice delegates to bob w/ allowed action restriction array
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.invocationTarget,
            expires: EXPIRES_3000_DATE,
            allowedAction: ['read', 'write']
          },
          parentCapability: capabilities.root.beta,
          delegator: alice
        });

        // bob delegates to carol...
        // first check to ensure that delegation fails "client side"
        let carolZcap;
        let localError;
        try {
          // bob attempts to delegate to carol
          carolZcap = await _delegate({
            newCapability: {
              '@context': ZCAP_CONTEXT_URL,
              id: uuid(),
              controller: carol.id(),
              parentCapability: bobZcap.id,
              invocationTarget: bobZcap.invocationTarget,
              expires: EXPIRES_3000_DATE,
              allowedAction: ['foo', 'bar']
            },
            parentCapability: bobZcap,
            delegator: bob
          });
        } catch(e) {
          localError = e;
        }
        expect(localError).to.exist;
        localError.name.should.equal('Error');
        localError.message.should.equal(
          'The "allowedAction" in a delegated capability ' +
          'must not be less restrictive than its parent.');

        // bob delegates to carol with a different allowed action restriction
        // array that he is not allowed to use
        carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires: EXPIRES_3000_DATE,
            allowedAction: ['foo', 'bar']
          },
          purposeOptions: {
            // skip local validation to allow the zcap to be delegated so it
            // can be checked by the verifier
            _skipLocalValidationForTesting: true
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id
        });
        should.exist(result);
        result.verified.should.be.false;
        should.exist(result.error);
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'delegated capability must not be less restrictive');
      });

      it('should verify chain when child allowedAction is ' +
        'a valid subset of the parent allowedAction array', async () => {
        // alice delegates to bob w/ allowed action restriction array
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.invocationTarget,
            expires: EXPIRES_3000_DATE,
            allowedAction: ['read', 'write']
          },
          parentCapability: capabilities.root.beta,
          delegator: alice
        });

        // bob delegates to carol and further restricts which actions she is
        // allowed to take
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires: EXPIRES_3000_DATE,
            allowedAction: ['read']
          },
          delegator: bob,
          parentCapability: bobZcap
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id
        });
        should.exist(result);
        result.verified.should.be.true;
      });

      it('should verify chain when child allowedAction is ' +
        'a valid subset of the undefined parent allowedAction', async () => {
        // alice delegates to bob w/ no special action restrictions
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol and adds an allowed action restriction
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires: EXPIRES_3000_DATE,
            allowedAction: 'read'
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id
        });
        should.exist(result);
        result.verified.should.be.true;
      });

      it('should fail to verify chain w/bad middle capability', async () => {
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });
        // change ID to something else (breaking signature)
        bobZcap.id = uuid();

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.name.should.equal('VerificationError');
      });

      it('should fail to verify chain w/bad last capability', async () => {
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });
        // change ID to something else (breaking signature)
        carolZcap.id = uuid();

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.equal('Invalid signature.');
      });

      it('should verify chain w/inspectCapabilityChain', async () => {
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        let checkedChain = 0;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain++;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(3);
          capabilityChainMeta.should.be.an('array');
          capabilityChainMeta.should.have.length(3);
          _checkCapabilityChain({capabilityChain});
          _checkCapabilityChainMeta({capabilityChainMeta});
          // a real implementation would look for revocations here
          return {valid: true};
        };
        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id,
          inspectCapabilityChain
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
        checkedChain.should.equal(1);
      });

      it('should fail to verify w/inspectCapabilityChain ' +
        'w/revoked capability', async () => {
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        let checkedChain = 0;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain++;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(3);
          _checkCapabilityChain({capabilityChain});
          _checkCapabilityChainMeta({capabilityChainMeta});
          // a real implementation would look for revocations here
          return {
            error: new Error(`The capability "${capabilityChain[0].id}" ` +
              'has been revoked.'),
            valid: false,
          };
        };
        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id,
          inspectCapabilityChain
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        expect(result.error.errors[0]).to.exist;
        result.error.errors[0].message.should.contain('revoked');
        checkedChain.should.equal(1);
      });

      it('should fail to verify w/delegated zcap created before ' +
        'parent', async () => {
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob,
          // force proof creation date to be in the past
          date: new Date(0),
          purposeOptions: {
            // required to allow a zcap w/o expires to be created; goal is to
            // only check via the verifier, not locally
            _skipLocalValidationForTesting: true
          }
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id
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

        // expires within TTL
        const expires = new Date(Date.now() + ttl);

        // alice delegates to bob
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.invocationTarget,
            expires: expires.toISOString()
          },
          parentCapability: capabilities.root.beta,
          delegator: alice
        });

        // bob delegates to carol, erroneously without an expiration date
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget
            // intentionally missing `expires` field
          },
          purposeOptions: {
            // required to allow a zcap w/o expires to be created; goal is to
            // only check via the verifier, not locally
            _skipLocalValidationForTesting: true
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id,
          purposeOptions: {
            // max TTL of 1 day
            maxDelegationTtl: ttl
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        expect(result.error.errors[0]).to.exist;
        result.error.errors[0].message.should.contain(
          'Delegated capability must have a valid expires date');
      });

      it('should fail to verify chain w/delegated zcap in the ' +
        'future', async () => {
        // TTL of 1 day
        const ttl = 1000 * 60 * 60 * 24;

        // force delegation into the future
        const delegated = new Date(Date.now() + ttl);
        // alice delegates to bob
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.invocationTarget,
            expires: new Date(delegated.getTime() + ttl / 2).toISOString()
          },
          parentCapability: capabilities.root.beta,
          delegator: alice,
          date: delegated
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires: bobZcap.expires
          },
          parentCapability: bobZcap,
          delegator: bob,
          purposeOptions: {
            // required to allow a zcap w/o expires to be created; goal is to
            // only check via the verifier, not locally
            _skipLocalValidationForTesting: true
          }
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id,
          purposeOptions: {
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

        const now = new Date();
        // alice delegates to bob with an expiration date that's too far
        // into the future (TTL too long for bob's zcap)
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.invocationTarget,
            expires: new Date(now.getTime() + ttl + 1).toISOString()
          },
          parentCapability: capabilities.root.beta,
          delegator: alice, date: now
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires: bobZcap.expires
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        const result = await _verifyDelegation({
          delegation: carolZcap,
          expectedRootCapability: capabilities.root.beta.id,
          purposeOptions: {
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
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap,
          capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability: capabilities.root.beta,
          expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify chain w/ multiple controllers', async () => {
        // alice delegates the same zcap to both bob and another party
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.invocationTarget,
            expires: EXPIRES_3000_DATE,
            controller: ['urn:other', bob.id()]
          },
          parentCapability: capabilities.root.beta,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap,
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
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
        });
        let checkedChain = 0;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain++;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(3);
          _checkCapabilityChain({capabilityChain});
          _checkCapabilityChainMeta({capabilityChainMeta});
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
        checkedChain.should.equal(1);
      });

      it('should verify invoking ' +
        'w/TTL and delegation date monotonicity checks', async () => {
        // 24 hour TTL
        const ttl = 1000 * 60 * 60 * 24;

        // alice delegates to bob
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.invocationTarget,
            expires: new Date(Date.now() + ttl / 2).toISOString()
          },
          parentCapability: capabilities.root.beta,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires: bobZcap.expires
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
        });
        let checkedChain = 0;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain++;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(3);
          _checkCapabilityChain({capabilityChain});
          _checkCapabilityChainMeta({capabilityChainMeta});
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
            maxDelegationTtl: ttl
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
        checkedChain.should.equal(1);
      });

      it('should fail invoking ' +
        'w/inspectCapabilityChain and a revoked capability', async () => {
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
        });
        let checkedChain = 0;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain++;
          should.exist(capabilityChain);
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(3);
          _checkCapabilityChain({capabilityChain});
          _checkCapabilityChainMeta({capabilityChainMeta});
          // a real implementation would look for revocations here (perhaps by
          // querying a database)
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
        checkedChain.should.equal(1);
      });
    }); // end Chain depth of 3

    describe('Expiration date', () => {
      it('CapabilityInvocation throws TypeError on invalid date',
        async () => {
        let result;
        let err;
        try {
          result = new CapabilityInvocation({
            expectedTarget:
              'urn:uuid:1aaec12f-bcf2-40d8-8192-cc4dde9bca96',
            suite: new Ed25519Signature2020(),
            date: 'invalid date',
          });
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.should.be.instanceof(TypeError);
        err.message.should.contain('is not a valid date.');
      });

      it('CapabilityDelegation throws TypeError on invalid date',
        async () => {
        let result;
        let err;
        try {
          result = new CapabilityDelegation({
            // `expectedRootCapability` must be present to signal this purpose
            // instance is for verifying a proof; otherwise different missing
            // param errors will be raised for creating a proof
            expectedRootCapability: 'urn:foo',
            date: 'invalid date'
          });
        } catch(e) {
          err = e;
        }
        should.exist(err);
        should.not.exist(result);
        err.should.be.instanceof(TypeError);
        err.message.should.contain('is not a valid date.');
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
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:9ff561b8-0b3f-4bbc-af00-03ba785a7fc6';
        addToLoader({doc: rootCapability});

        // alice delegates to bob w/1 hour expires
        let expires = new Date();
        expires.setHours(expires.getHours() + 1);
        expires = expires.toISOString();
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: rootCapability.id,
            invocationTarget: rootCapability.invocationTarget,
            expires
          },
          parentCapability: rootCapability,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability, expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to delegate a capability with bad `expires` field',
        async () => {
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:e843f3c4-6b2b-11ec-b87f-10bf48838a41';
        addToLoader({doc: rootCapability});

        // alice delegates to bob with an invalid `expires` date
        let bobZcap;
        let localError;
        try {
          bobZcap = await _delegate({
            newCapability: {
              '@context': ZCAP_CONTEXT_URL,
              id: uuid(),
              controller: bob.id(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.invocationTarget,
              expires: 'not a valid date'
            },
            parentCapability: rootCapability,
            delegator: alice
          });
        } catch(e) {
          localError = e;
        }
        expect(bobZcap).to.not.exist;
        expect(localError).to.exist;
        localError.message.should.contain(
          'Delegated capability must have a valid expires date.');
      });

      it('should fail to verify a capability with bad `expires` field',
        async () => {
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:0aee1dd6-646b-11ec-b975-10bf48838a41';
        addToLoader({doc: rootCapability});

        // alice delegates to bob with an invalid `expires` date
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: rootCapability.id,
            invocationTarget: rootCapability.invocationTarget,
            expires: 'not a valid date'
          },
          purposeOptions: {
            parentCapability: rootCapability,
            // skip checking zcap for bad `expires` date so it will only be
            // checked by the verifier
            _skipLocalValidationForTesting: true
          },
          delegator: alice
        });

        // bob invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: bob, capability: bobZcap, capabilityAction: 'read'
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
        'and `date` parameter in the past', async () => {
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:1c919b19-baab-45ee-b0ef-24309dfb355d';
        addToLoader({doc: rootCapability});

        // alice delegates to bob a capability that is already expired
        // using the current machine clock ... but we will pass a modified
        // verification time via `date` below
        // the capability was still valid 20 hours ago, use that as the
        // verification date
        const date = new Date();
        date.setHours(date.getHours() - 20);
        let expires = new Date();
        expires.setHours(expires.getHours() - 10);
        expires = expires.toISOString();
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: rootCapability.id,
            invocationTarget: rootCapability.invocationTarget,
            expires
          },
          date,
          parentCapability: rootCapability,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires
          },
          date,
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, purposeOptions: {
            expectedAction: 'read',
            expectedRootCapability: rootCapability.id,
            expectedTarget: rootCapability.invocationTarget,
            date
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail invoking a capability with `expires` ' +
        'and `date` parameter in the past', async () => {
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:142b0b4a-c664-4288-84e6-be0a59b6efa4';
        addToLoader({doc: rootCapability});

        // alice delegates to bob a capability is already expired
        let expires = new Date();
        expires.setHours(expires.getHours() - 50);
        expires = expires.toISOString();
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: rootCapability.id,
            invocationTarget: rootCapability.invocationTarget,
            expires
          },
          purposeOptions: {
            // do not validate locally to allow expired zcap to be delegated
            _skipLocalValidationForTesting: true
          },
          parentCapability: rootCapability,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires
          },
          purposeOptions: {
            // do not validate locally to allow expired zcap to be delegated
            _skipLocalValidationForTesting: true
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
        });
        // the capability was also expired 20 hours ago
        const date = new Date();
        date.setHours(date.getHours() - 20);
        const result = await _verifyInvocation({
          invocation, purposeOptions: {
            expectedAction: 'read',
            expectedRootCapability: rootCapability.id,
            expectedTarget: rootCapability.invocationTarget,
            date
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
        'and `date` parameter in the future', async () => {
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:bcbcde5e-d64a-4f46-a76e-daf52f63f702';
        addToLoader({doc: rootCapability});

        // alice delegates to bob a capability that is presently valid
        let expires = new Date();
        expires.setHours(expires.getHours() + 50);
        expires = expires.toISOString();
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: rootCapability.id,
            invocationTarget: rootCapability.invocationTarget,
            expires
          },
          parentCapability: rootCapability,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
        });
        // the capability will have expired in 100 hours, so pass that future
        // time in as the verification date to trigger an error
        const date = new Date();
        date.setHours(date.getHours() + 100);
        const result = await _verifyInvocation({
          invocation, purposeOptions: {
            expectedAction: 'read',
            expectedRootCapability: rootCapability.id,
            expectedTarget: rootCapability.invocationTarget,
            suite: new Ed25519Signature2020(),
            date,
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
        // capability from bob to carol does not...
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:ae96f88e-6b8a-4445-9b4f-03f45c3d1685';
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        let expires = new Date();
        expires.setHours(expires.getHours() + 1);
        expires = expires.toISOString();
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: rootCapability.id,
            invocationTarget: rootCapability.invocationTarget,
            expires
          },
          parentCapability: rootCapability,
          delegator: alice
        });

        // first check to ensure that delegation fails "client side"
        let carolZcap;
        let localError;
        try {
          // bob delegates to carol
          carolZcap = await _delegate({
            newCapability: {
              '@context': ZCAP_CONTEXT_URL,
              id: uuid(),
              controller: carol.id(),
              parentCapability: bobZcap.id,
              invocationTarget: bobZcap.invocationTarget
            },
            parentCapability: bobZcap,
            delegator: bob
          });
        } catch(e) {
          localError = e;
        }
        expect(localError).to.exist;
        localError.name.should.equal('Error');
        localError.message.should.contain(
          'Delegated capability must have a valid expires date');

        // now skip client-side validation...
        // bob delegates to carol (but it is missing `expires`)
        carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget
            // intentionally missing `expires`
          },
          purposeOptions: {
            // must skip local validation to allow zcap w/o `expires`
            _skipLocalValidationForTesting: true
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
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
          'Delegated capability must have a valid expires date');
      });

      it('should fail invoking a delegated capability before its ' +
        'delegation proof "created" date', async () => {
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:b4840a74-6cc0-11ec-819f-10bf48838a41';
        addToLoader({doc: rootCapability});

        // alice delegates to bob using a specific date to trigger an error
        // below
        const date = new Date();
        let expires = new Date();
        expires.setHours(expires.getHours() + 1);
        expires = expires.toISOString();
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: rootCapability.id,
            invocationTarget: rootCapability.invocationTarget,
            expires
          },
          date,
          parentCapability: rootCapability,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires
          },
          date,
          purposeOptions: {
            // must skip local validation to allow zcap w/o `expires`
            _skipLocalValidationForTesting: true
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes before her delegation (but not more than 300 seconds
        // so it does not trigger an error)
        {
          const beforeDelegation = new Date(date.getTime() - 1000);
          const doc = clone(mock.exampleDoc);
          const invocation = await _invoke({
            doc, date: beforeDelegation,
            invoker: carol, capability: carolZcap, capabilityAction: 'read'
          });
          const result = await _verifyInvocation({
            invocation, rootCapability, expectedAction: 'read'
          });
          expect(result).to.exist;
          expect(result.verified).to.be.true;
        }

        // carol invokes before her delegation (by more than 300 second
        // clock skew so it does trigger an error)
        const beforeDelegation = new Date(date.getTime() - (301 * 1000));
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, date: beforeDelegation,
          invoker: carol, capability: carolZcap, capabilityAction: 'read'
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
          'A delegated capability must not be invoked before the "created" ' +
          'date in its delegation proof.');
      });

      it('should fail delegating an expired capability', async () => {
        // the capability from alice to bob has proper expires, but the
        // capability from bob to carol does not...
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:ef98a880-6b36-11ec-940f-10bf48838a41';
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        let expires = new Date();
        expires.setHours(expires.getHours() + 1);
        expires = expires.toISOString();
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: rootCapability.id,
            invocationTarget: rootCapability.invocationTarget,
            expires
          },
          parentCapability: rootCapability,
          delegator: alice
        });

        // first check to ensure that delegation fails "client side"
        // note `afterExpired` has to be more than a clock skew of 300 seconds
        const afterExpired = new Date(Date.parse(expires) + (301 * 1000));
        let carolZcap;
        let localError;
        try {
          // bob delegates to carol *after* his zcap has expired
          carolZcap = await _delegate({
            newCapability: {
              '@context': ZCAP_CONTEXT_URL,
              id: uuid(),
              controller: carol.id(),
              parentCapability: bobZcap.id,
              invocationTarget: bobZcap.invocationTarget,
              expires
            },
            date: afterExpired,
            parentCapability: bobZcap,
            delegator: bob
          });
        } catch(e) {
          localError = e;
        }
        expect(localError).to.exist;
        localError.name.should.equal('Error');
        localError.message.should.contain(
          'Cannot delegate an expired capability.');

        // now skip client-side validation...
        // bob delegates to carol (but it has expired)
        carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires
          },
          date: afterExpired,
          purposeOptions: {
            // must skip local validation to allow zcap w/o `expires`
            _skipLocalValidationForTesting: true
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes an expired zcap
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc,
          // invocation date must not be before delegation date or a different
          // error will be triggered
          date: afterExpired,
          invoker: carol, capability: carolZcap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability, expectedAction: 'read',
          purposeOptions: {
            date: afterExpired
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

      it('should fail invoking a capability with ' +
        'capability that expires on the Unix epoch', async () => {
        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:cbddee5a-09fb-44db-a921-70c36436c253';
        addToLoader({doc: rootCapability});

        // alice delegates to bob a capability with expires to the Unix epoch
        // (which is in the past)
        let expires = new Date(0);
        expires = expires.toISOString();
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: rootCapability.id,
            invocationTarget: rootCapability.invocationTarget,
            expires
          },
          purposeOptions: {
            // do not validate locally to allow expired zcap to be delegated
            _skipLocalValidationForTesting: true
          },
          parentCapability: rootCapability,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires
          },
          purposeOptions: {
            // do not validate locally to allow expired zcap to be delegated
            _skipLocalValidationForTesting: true
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
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
        // past...

        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:3c034da3-8b5e-4fdc-b75d-8c37d73cd21e';
        addToLoader({doc: rootCapability});

        // alice delegates to bob a capability that hasn't expired yet
        let expires = new Date();
        expires.setHours(expires.getHours() + 10);
        expires = expires.toISOString();
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: rootCapability.id,
            invocationTarget: rootCapability.invocationTarget,
            expires
          },
          parentCapability: rootCapability,
          delegator: alice
        });

        // bob delegates to carol a capability that has alread expired
        // set expires for this delegation well in the past
        expires = new Date();
        expires.setHours(expires.getHours() - 10);
        expires = expires.toISOString();
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires
          },
          purposeOptions: {
            // do not validate locally to allow expired zcap to be delegated
            _skipLocalValidationForTesting: true
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
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

      it('should fail invoking a capability with second delegated ' +
        'capability that expires on the Unix epoch', async () => {
        // bob's capability expires on a date in the future, but
        // the delegation from bob to carol specifies unix epoch date...

        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:6286a906-619b-4f5b-a8ae-af9fb774b070';
        addToLoader({doc: rootCapability});

        // alice delegates to bob a capability that expires in the future
        let expires = new Date();
        expires.setHours(expires.getHours() + 10);
        expires = expires.toISOString();
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: rootCapability.id,
            invocationTarget: rootCapability.invocationTarget,
            expires
          },
          parentCapability: rootCapability,
          delegator: alice
        });

        // bob delegates to carol a capability that expired at the Unix epoch
        // set expires for this delegation to the Unix epoch
        expires = new Date(0);
        expires = expires.toISOString();
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires
          },
          purposeOptions: {
            // do not validate locally to allow expired zcap to be delegated
            _skipLocalValidationForTesting: true
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
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
        // further into the future...

        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:1e7dfae9-85a3-40d7-97ea-20105f0b9d99';
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        let expires = new Date();
        expires.setHours(expires.getHours() + 10);
        expires = expires.toISOString();
        const bobZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: bob.id(),
            parentCapability: rootCapability.id,
            invocationTarget: rootCapability.invocationTarget,
            expires
          },
          parentCapability: rootCapability,
          delegator: alice
        });

        // bob delegates to carol but erroneously tries to give her a zcap
        // that expires after his own...
        // set expires for this delegation beyond the expiration of the
        // parent capability, which is not allowed
        expires = new Date();
        expires.setHours(expires.getHours() + 100);
        expires = expires.toISOString();
        // first check to ensure that delegation fails "client side"
        let carolZcap;
        let localError;
        try {
          // bob attempts to delegate to carol
          carolZcap = await _delegate({
            newCapability: {
              '@context': ZCAP_CONTEXT_URL,
              id: uuid(),
              controller: carol.id(),
              parentCapability: bobZcap.id,
              invocationTarget: bobZcap.invocationTarget,
              expires
            },
            parentCapability: bobZcap,
            delegator: bob
          });
        } catch(e) {
          localError = e;
        }
        expect(localError).to.exist;
        localError.name.should.equal('Error');
        localError.message.should.equal(
          'The `expires` property in a delegated ' +
          'capability must not be less restrictive than its ' +
          'parent.');

        // bob delegates to carol
        carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires
          },
          purposeOptions: {
            // do not validate locally to allow expired zcap to be delegated
            _skipLocalValidationForTesting: true
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
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
          'delegated capability must not be less restrictive');
      });

      it('should verify invoking a capability with only expires on ' +
        'second delegated capability', async () => {
        // only the second delegation has a valid future expiration...

        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:a0d0360b-7e93-4c9c-8804-69ca426c60c3';
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to alice
        // set expires for this delegation well in the past
        let expires = new Date();
        expires.setHours(expires.getHours() + 10);
        expires = expires.toISOString();
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
        });
        const result = await _verifyInvocation({
          invocation, rootCapability, expectedAction: 'read'
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail invoking a capability with only an expired ' +
        'second delegated capability', async () => {
        // only the second delegation has an expiration in the past...

        const rootCapability = {...capabilities.root.beta};
        rootCapability.id = 'urn:zcap:2c41869c-95bb-4e23-9bcd-2fbb320bb440';
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        // set expires for this delegation well in the past
        let expires = new Date();
        expires.setHours(expires.getHours() - 10);
        expires = expires.toISOString();
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget: bobZcap.invocationTarget,
            expires
          },
          purposeOptions: {
            // do not validate locally to allow expired zcap to be delegated
            _skipLocalValidationForTesting: true
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
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
      it('should verify chain', async () => {
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        // carol delegates to diana
        const dianaZcap = await _delegate({
          parentCapability: carolZcap,
          controller: diana,
          delegator: carol
        });

        const result = await _verifyDelegation({
          delegation: dianaZcap,
          expectedRootCapability: capabilities.root.beta.id
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify chain w/inspectCapabilityChain', async () => {
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        // carol delegates to diana
        const dianaZcap = await _delegate({
          parentCapability: carolZcap,
          controller: diana,
          delegator: carol
        });

        let checkedChain = 0;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain++;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(4);
          capabilityChainMeta.should.be.an('array');
          capabilityChainMeta.should.have.length(4);
          _checkCapabilityChain({capabilityChain});
          _checkCapabilityChainMeta({capabilityChainMeta});
          // a real implementation would look for revocations here
          return {valid: true};
        };

        const result = await _verifyDelegation({
          delegation: dianaZcap,
          expectedRootCapability: capabilities.root.beta.id,
          inspectCapabilityChain
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
        checkedChain.should.equal(1);
      });

      it('should fail to verify w/embedded middle zcap', async () => {
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        // carol delegates to diana
        const dianaZcap = await _delegate({
          parentCapability: carolZcap,
          controller: diana,
          delegator: carol,
          purposeOptions: {
            _skipLocalValidationForTesting: true,
            // override chain
            // bad capability chain entry w/ bob's zcap embedded when it should
            // just have its ID here
            _capabilityChain: [capabilities.root.beta.id, bobZcap, carolZcap]
          }
        });

        const result = await _verifyDelegation({
          delegation: dianaZcap,
          expectedRootCapability: capabilities.root.beta.id
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
        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: capabilities.root.beta,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        // carol delegates to diana
        const dianaZcap = await _delegate({
          parentCapability: carolZcap,
          controller: diana,
          delegator: carol
        });

        let checkedChain = 0;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain++;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(4);
          capabilityChainMeta.should.be.an('array');
          capabilityChainMeta.should.have.length(4);
          _checkCapabilityChain({capabilityChain});
          _checkCapabilityChainMeta({capabilityChainMeta});
          // a real implementation would look for revocations here
          return {valid: true};
        };

        const result = await _verifyDelegation({
          delegation: dianaZcap,
          expectedRootCapability: capabilities.root.beta.id,
          purposeOptions: {
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
        checkedChain.should.equal(0);
      });
    }); // end Chain depth of 4

    describe('invocationTarget attenuation', () => {
      it('should verify chain w/path attenuation', async () => {
        const rootTarget =
          'https://example.com/edvs/cc8b09fd-76e2-4fae-9bdd-2522b83a2971';
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        // carol delegates to diana w/ restriction to access to a specific
        // document under carol's capability
        const invocationTarget =
          `${carolZcap.invocationTarget}/a-specific-document`;
        const dianaZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: diana.id(),
            parentCapability: carolZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: carolZcap,
          delegator: carol
        });

        const result = await _verifyDelegation({
          delegation: dianaZcap,
          expectedRootCapability: rootCapability.id,
          purposeOptions: {
            allowTargetAttenuation: true
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify chain w/query attenuation', async () => {
        const rootTarget =
          'https://example.com/edvs/0d3bd43c-719c-11ec-acdd-10bf48838a41';
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        // carol delegates to diana w/ restriction to access to a specific
        // query under carol's capability
        const invocationTarget =
          `${carolZcap.invocationTarget}?foo=bar`;
        const dianaZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: diana.id(),
            parentCapability: carolZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: carolZcap,
          delegator: carol
        });

        const result = await _verifyDelegation({
          delegation: dianaZcap,
          expectedRootCapability: rootCapability.id,
          purposeOptions: {
            allowTargetAttenuation: true
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify chain w/path and query attenuation', async () => {
        const rootTarget =
          'https://example.com/edvs/1d7ab048-719c-11ec-b07a-10bf48838a41';
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        // carol delegates to diana w/ restriction to access to a specific
        // document and query under carol's capability
        const invocationTarget =
          `${carolZcap.invocationTarget}/a-specific-document?foo=bar`;
        const dianaZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: diana.id(),
            parentCapability: carolZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: carolZcap,
          delegator: carol
        });

        const result = await _verifyDelegation({
          delegation: dianaZcap,
          expectedRootCapability: rootCapability.id,
          purposeOptions: {
            allowTargetAttenuation: true
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify chain with attenuation that is more ' +
        'permissive than the parent capability w/path', async () => {
        const rootTarget =
          'https://example.com/edvs/357570f6-8df2-4e78-97dc-42260d64e78e';
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol w/ restriction to access to a specific
        // document under bob's capability
        const invocationTarget =
          `${bobZcap.invocationTarget}/a-specific-document`;
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol delegates to diana erroneously expanding her access beyond
        // what bob restricted carol's to
        const dianaZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: diana.id(),
            parentCapability: carolZcap.id,
            // NOTE: this is an invalid attempt to degate a capability to the
            // root of the EDV when carol's zcap has an invocationTarget that
            // is a specific EDV document
            invocationTarget: bobZcap.invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: carolZcap,
          delegator: carol
        });

        const result = await _verifyDelegation({
          delegation: dianaZcap,
          expectedRootCapability: rootCapability.id,
          purposeOptions: {
            allowTargetAttenuation: true
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.errors.should.have.length(1);
        const [error] = result.error.errors;
        error.message.should.include(
          'delegated capability must not be less restrictive');
      });

      it('should fail to verify chain with attenuation that is more ' +
        'permissive than the parent capability w/query', async () => {
        const rootTarget =
          'https://example.com/edvs/3e209556-719c-11ec-9a7b-10bf48838a41';
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol w/ restriction to access to a specific
        // query under bob's capability
        const invocationTarget =
          `${bobZcap.invocationTarget}?foo=bar`;
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol delegates to diana erroneously expanding her access beyond
        // what bob restricted carol's to
        const dianaZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: diana.id(),
            parentCapability: carolZcap.id,
            // NOTE: this is an invalid attempt to degate a capability to the
            // root of the EDV when carol's zcap has an invocationTarget that
            // is a specific EDV document
            invocationTarget: bobZcap.invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: carolZcap,
          delegator: carol
        });

        const result = await _verifyDelegation({
          delegation: dianaZcap,
          expectedRootCapability: rootCapability.id,
          purposeOptions: {
            allowTargetAttenuation: true
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.errors.should.have.length(1);
        const [error] = result.error.errors;
        error.message.should.include(
          'delegated capability must not be less restrictive');
      });

      it('should verify when invoking at an exact-match target ' +
        'w/path', async () => {
        const rootTarget = `https://example.com/edvs/${uuid()}`;
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol w/ restriction to access to a specific
        // document under bob's capability
        const invocationTarget =
          `${bobZcap.invocationTarget}/a-specific-document`;
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
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

      it('should verify when invoking at an exact-match target ' +
        'w/query', async () => {
        const rootTarget = `https://example.com/edvs/${uuid()}`;
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol w/ restriction to access to a specific
        // document and query under bob's capability
        const invocationTarget =
          `${bobZcap.invocationTarget}?foo=bar`;
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes
        const doc = clone(mock.exampleDoc);
        const invocation = await _invoke({
          doc, invoker: carol, capability: carolZcap, capabilityAction: 'read'
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
        'target w/path', async () => {
        const rootTarget = `https://example.com/edvs/${uuid()}`;
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol w/ restriction to access to a specific
        // document under bob's capability
        const invocationTarget =
          `${bobZcap.invocationTarget}/a-specific-document`;
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes but erroneously with an invocation target that is
        // not permitted by her zcap *and* is not expected where she sends
        // the invocation
        const doc = clone(mock.exampleDoc);
        // Note: This is intentionally an invalid target (a doc that
        // carol should not have access to)
        const invalidTarget = `${rootTarget}/a-different-specific-document`;
        const invocation = await _invoke({
          doc, invoker: carol,
          purposeOptions: {
            capability: carolZcap,
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
          `Invocation target (${invalidTarget}) does not match capability ` +
          `target (${carolZcap.invocationTarget}).`);
      });

      it('should fail to verify when invoking at an unexpected ' +
        'target w/query', async () => {
        const rootTarget = `https://example.com/edvs/${uuid()}`;
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol w/ restriction to access to a specific
        // document under bob's capability
        const invocationTarget =
          `${bobZcap.invocationTarget}?foo=bar`;
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes but erroneously with an invocation target that is
        // not permitted by her zcap *and* is not expected where she sends
        // the invocation
        const doc = clone(mock.exampleDoc);
        // Note: This is intentionally an invalid target (a doc that
        // carol should not have access to)
        const invalidTarget =
          `${rootTarget}/a-different-specific-document?foo=bar`;
        const invocation = await _invoke({
          doc, invoker: carol,
          purposeOptions: {
            capability: carolZcap,
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
          `Invocation target (${invalidTarget}) does not match capability ` +
          `target (${carolZcap.invocationTarget}).`);
      });

      it('should verify when invoking at a valid sub target ' +
        'w/path', async () => {
        const rootTarget = `https://example.com/edvs/${uuid()}`;
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol w/ restriction to access to a specific
        // document under bob's capability
        const invocationTarget =
          `${bobZcap.invocationTarget}/a-specific-document`;
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes using an invocation target of a path that is a
        // subpath of her zcap's invocation target (which is permitted by
        // the verifier when `allowTargetAttenuation = true`
        const doc = clone(mock.exampleDoc);
        // Note: This is an attenuated path off of carol's zcap's target
        const validSubTarget = `${carolZcap.invocationTarget}/sub-path`;
        const invocation = await _invoke({
          doc, invoker: carol,
          purposeOptions: {
            capability: carolZcap,
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

      it('should verify when invoking at a valid sub target ' +
        'w/query', async () => {
        const rootTarget = `https://example.com/edvs/${uuid()}`;
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol w/ restriction to access to a specific
        // query under bob's capability
        const invocationTarget =
          `${bobZcap.invocationTarget}?foo=bar`;
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes using an invocation target of a path that is a
        // subpath of her zcap's invocation target (which is permitted by
        // the verifier when `allowTargetAttenuation = true`
        const doc = clone(mock.exampleDoc);
        // Note: This is an attenuated path off of carol's zcap's target
        const validSubTarget = `${carolZcap.invocationTarget}&baz=fuzz`;
        const invocation = await _invoke({
          doc, invoker: carol,
          purposeOptions: {
            capability: carolZcap,
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
        'target w/path', async () => {
        const rootTarget = `https://example.com/edvs/${uuid()}`;
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol w/ restriction to access to a specific
        // document under bob's capability
        const invocationTarget =
          `${bobZcap.invocationTarget}/a-specific-document`;
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes erroneously using an invocation target that is
        // not permitted by her zcap even though where she sends the invocation
        // is expecting that target
        const doc = clone(mock.exampleDoc);
        // Note: This is intentionally an invalid target (a doc that
        // carol should not have access to)
        const invalidTarget = `${rootTarget}/a-different-specific-document`;
        const invocation = await _invoke({
          doc, invoker: carol,
          purposeOptions: {
            capability: carolZcap,
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
          `target (${carolZcap.invocationTarget})`);
      });

      it('should fail to verify when invoking at an invalid ' +
        'target w/query', async () => {
        const rootTarget = `https://example.com/edvs/${uuid()}`;
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol w/ restriction to access to a specific
        // query under bob's capability
        const invocationTarget =
          `${bobZcap.invocationTarget}?foo=bar`;
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol invokes erroneously using an invocation target that is
        // not permitted by her zcap even though where she sends the invocation
        // is expecting that target
        const doc = clone(mock.exampleDoc);
        // Note: This is intentionally an invalid target (a doc that
        // carol should not have access to)
        const invalidTarget =
          `${rootTarget}/a-different-specific-document?foo=bar`;
        const invocation = await _invoke({
          doc, invoker: carol,
          purposeOptions: {
            capability: carolZcap,
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
          `target (${carolZcap.invocationTarget})`);
      });

      it('should fail to verify when allowTargetAttenuation is not ' +
        'explicitly allowed', async () => {
        const rootTarget =
          'https://example.com/edvs/2c2fe4ab-ff54-4a82-b103-f806f50d364e';
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        // carol delegates to diana w/ restriction to access to a specific
        // document under carol's capability
        const invocationTarget =
          `${carolZcap.invocationTarget}/a-specific-document`;
        const dianaZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: diana.id(),
            parentCapability: carolZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: carolZcap,
          delegator: carol
        });

        // NOTE: allowTargetAttenuation is intentionally not set
        // here, the default is false
        const result = await _verifyDelegation({
          delegation: dianaZcap,
          expectedRootCapability: rootCapability.id,
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.errors.should.have.length(1);
        const [error] = result.error.errors;
        error.message.should.contain('must be equivalent to its parent');
      });

      it('should verify chain w/inspectCapabilityChain', async () => {
        const rootTarget =
          'https://example.com/edvs/83d7e997-d742-4b1a-9033-968f222b9144';
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol
        const carolZcap = await _delegate({
          parentCapability: bobZcap,
          controller: carol,
          delegator: bob
        });

        // carol delegates to diana w/ restriction to access to a specific
        // document under carol's capability
        const invocationTarget =
          `${carolZcap.invocationTarget}/a-specific-document`;
        const dianaZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: diana.id(),
            parentCapability: carolZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: carolZcap,
          delegator: carol
        });

        let checkedChain = 0;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain++;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(4);
          capabilityChainMeta.should.be.an('array');
          capabilityChainMeta.should.have.length(4);
          _checkCapabilityChain({capabilityChain});
          _checkCapabilityChainMeta({capabilityChainMeta});
          // a real implementation would look for revocations here
          return {valid: true};
        };

        const result = await _verifyDelegation({
          delegation: dianaZcap,
          expectedRootCapability: rootCapability.id,
          inspectCapabilityChain,
          purposeOptions: {
            allowTargetAttenuation: true
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
        checkedChain.should.equal(1);
      });

      it('should fail to verify an increasingly permissive chain ' +
        'w/inspectCapabilityChain', async () => {
        const rootTarget =
          'https://example.com/edvs/d9dd2093-0908-47ba-8db7-954ff1cd81ee';
        const rootCapability = createRootCapability({
          controller: alice.id(),
          invocationTarget: rootTarget
        });
        addToLoader({doc: rootCapability});

        // alice delegates to bob
        const bobZcap = await _delegate({
          parentCapability: rootCapability,
          controller: bob,
          delegator: alice
        });

        // bob delegates to carol w/ restriction to access to a specific
        // document under bob's capability
        const invocationTarget =
          `${bobZcap.invocationTarget}/a-specific-document`;
        const carolZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: carol.id(),
            parentCapability: bobZcap.id,
            invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: bobZcap,
          delegator: bob
        });

        // carol delegates to diana erroneously expanding her access beyond
        // what bob restricted carol's to
        const dianaZcap = await _delegate({
          newCapability: {
            '@context': ZCAP_CONTEXT_URL,
            id: uuid(),
            controller: diana.id(),
            parentCapability: carolZcap.id,
            // NOTE: this is an invalid attempt to degate a capability to the
            // root of the EDV when carol's zcap has an invocationTarget that
            // is a specific EDV document
            invocationTarget: bobZcap.invocationTarget,
            expires: EXPIRES_3000_DATE
          },
          parentCapability: carolZcap,
          delegator: carol
        });

        let checkedChain = 0;
        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          checkedChain++;
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(4);
          capabilityChainMeta.should.be.an('array');
          capabilityChainMeta.should.have.length(4);
          _checkCapabilityChain({capabilityChain});
          _checkCapabilityChainMeta({capabilityChainMeta});
          // a real implementation would look for revocations here
          return {valid: true};
        };

        const result = await _verifyDelegation({
          delegation: dianaZcap,
          expectedRootCapability: rootCapability.id,
          inspectCapabilityChain,
          purposeOptions: {
            allowTargetAttenuation: true
          }
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.errors.should.have.length(1);
        const [error] = result.error.errors;
        error.message.should.include(
          'delegated capability must not be less restrictive');
        // should not get to check chain because of invalid zcap
        checkedChain.should.equal(0);
      });
    }); // end Path-based hierarchical attenuation
  });
});

function _checkCapabilityChain({capabilityChain}) {
  for(const c of capabilityChain) {
    c.should.be.an('object');
    c.should.have.property('id');
    c.should.have.property('controller');
    c.should.have.property('invocationTarget');
  }
}

function _checkCapabilityChainMeta({capabilityChainMeta}) {
  for(const [i, m] of capabilityChainMeta.entries()) {
    m.should.be.an('object');
    m.should.have.property('verifyResult');
    if(i === 0) {
      // root zcap verify result is `null`
      expect(m.verifyResult).to.be.null;
      continue;
    }
    m.verifyResult.should.have.property('verified');
    m.verifyResult.verified.should.be.true;
    m.verifyResult.should.have.property('results');
    m.verifyResult.results.length.should.equal(1);
    m.verifyResult.results[0].should.be.an('object');
    m.verifyResult.results[0].should.have.property('purposeResult');
    m.verifyResult.results[0].purposeResult.should.be.an('object');
    m.verifyResult.results[0].purposeResult.should.have.property('delegator');
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
      suite: new Ed25519Signature2020(),
      ...purposeOptions
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
  _capabilityChain, purposeOptions
}) {
  if(delegator) {
    key = delegator.get('capabilityDelegation', 0);
  }
  let purpose;
  if(purposeOptions) {
    // custom case
    purpose = new CapabilityDelegation({
      parentCapability, _capabilityChain, ...purposeOptions
    });
  } else {
    // common case
    purpose = new CapabilityDelegation({parentCapability, _capabilityChain});
  }
  if(!newCapability) {
    // generate default delegated zcap via `controller` and `parentCapability`
    newCapability = {
      '@context': ZCAP_CONTEXT_URL,
      id: uuid(),
      controller: typeof controller === 'string' ? controller : controller.id(),
      parentCapability: parentCapability.id,
      invocationTarget: parentCapability.invocationTarget,
      expires: EXPIRES_3000_DATE
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
  delegation, expectedRootCapability, inspectCapabilityChain,
  purposeOptions = {}
}) {
  return jsigs.verify(delegation, {
    documentLoader: testLoader,
    suite: new Ed25519Signature2020(),
    purpose: new CapabilityDelegation({
      suite: new Ed25519Signature2020(),
      expectedRootCapability,
      inspectCapabilityChain,
      ...purposeOptions
    })
  });
}

}
