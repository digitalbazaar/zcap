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
  ExpirationCaveat
} = zcapld;

const {
  SECURITY_CONTEXT_URL
} = jsigs;

const {Ed25519Signature2018} =
  require('@digitalbazaar/ed25519-signature-2018');

const {Ed25519VerificationKey2018} =
    require('@digitalbazaar/ed25519-verification-key-2018');

const {
  controllers,
  didDocs,
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
  context('Common', () => {
    describe('sign with capabilityInvocation proof purpose', () => {
      it('should succeed w/key invoker', async () => {
        const doc = clone(mock.exampleDoc);

        const signed = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              alice.get('verificationMethod', 0)
            ),
            date: CONSTANT_DATE
          }),
          purpose: new CapabilityInvocation({
            capability: capabilities.root.alpha.id
          })
        });
        expect(signed).to.deep.equal(mock.exampleDocWithInvocation.alpha);
      });

      it('should succeed w/controller invoker', async () => {
        const doc = clone(mock.exampleDoc);
        const signed = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              alice.get('verificationMethod', 0)
            ),
            date: CONSTANT_DATE
          }),
          purpose: new CapabilityInvocation({
            capability: capabilities.root.beta.id
          })
        });
        expect(signed).to.deep.equal(mock.exampleDocWithInvocation.beta);
      });

      it('should fail when missing "capability"', async () => {
        let err;
        try {
          const doc = clone(mock.exampleDoc);
          await jsigs.sign(doc, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                alice.get('verificationMethod', 0)
              )
            }),
            purpose: new CapabilityInvocation()
          });
        } catch(e) {
          err = e;
        }
        expect(err).to.exist;
        expect(err.message).to.equal('"capability" is required.');
      });
    });

    describe('sign with capabilityDelegation proof purpose', () => {
      it('should succeed w/key delegator', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's invocation key
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: 'https://whatacar.example/a-fancy-car/proc/7a397d7b-alpha',
          parentCapability: capabilities.root.alpha.id,
          invoker: bob.get('capabilityInvocation', 0).id
        };
        //  3. Sign the delegated capability with Alice's delegation key
        //     that was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              alice.get('verificationMethod', 0)
            ),
            date: CONSTANT_DATE
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.alpha.id]
          })
        });
        expect(delegatedCapability).to.deep.equal(capabilities.delegated.alpha);
      });

      it('should succeed w/controller delegator', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's invocation key
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: 'https://whatacar.example/a-fancy-car/proc/7a397d7b-beta',
          parentCapability: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key
        //     that was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              alice.get('verificationMethod', 0)
            ),
            date: CONSTANT_DATE
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        expect(delegatedCapability).to.deep.equal(capabilities.delegated.beta);
      });

      it('should fail when missing "capabilityChain" and "parentCapability"',
        async () => {
        let err;
        try {
          const doc = clone(mock.exampleDoc);
          await jsigs.sign(doc, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation()
          });
        } catch(e) {
          err = e;
        }
        expect(err).to.exist;
        expect(err.message).to.equal(
          'Cannot compute capability chain; capability has no ' +
          '"parentCapability".');
      });
    });
  });

  context('Verifying capability chains', () => {
    describe('Invoker and Delegator as keys', () => {
      it('should verify a self-invoked root capability', async () => {
        const result = await jsigs.verify(mock.exampleDocWithInvocation.alpha, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.alpha.id
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify w/array expected target', async () => {
        const result = await jsigs.verify(mock.exampleDocWithInvocation.alpha, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: [capabilities.root.alpha.id]
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify a capability chain of depth 2', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's invocation key
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.alpha.id,
          invocationTarget: capabilities.root.alpha.id,
          invoker: bob.get('capabilityInvocation', 0).id
        };
        //  3. Sign the delegated capability with Alice's delegation key
        //     that was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.alpha.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        // verify the delegation chain
        const result = await jsigs.verify(delegatedCapability, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation(),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a capability chain of depth 2 ' +
        'when the expectedRootCapability does not match', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's invocation key
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.alpha.id,
          invocationTarget: capabilities.root.alpha.id,
          invoker: bob.get('capabilityInvocation', 0).id
        };
        //  3. Sign the delegated capability with Alice's delegation key
        //     that was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.alpha.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        // verify the delegation chain
        const result = await jsigs.verify(delegatedCapability, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation(
            {expectedRootCapability: 'urn:uuid:fake'}),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain('does not match actual root capability');
      });

      it('should verify invoking a capability chain of depth 2', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's invocation key
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.alpha.id,
          invocationTarget: capabilities.root.alpha.id,
          invoker: bob.get('capabilityInvocation', 0).id
        };
        //  3. Sign the delegated capability with Alice's delegation key
        //     that was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.alpha.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   4. Use Bob's invocation key that was assigned as invoker in
        //      the delegated capability
        //   5. The invoker should be Bob's invocation key
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.alpha.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });
    });

    describe('Invoker and Delegator as controllers', () => {
      it('should verify a self-invoked root capability', async () => {
        const result = await jsigs.verify(mock.exampleDocWithInvocation.beta, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a root capability as delegated', async () => {
        // root has no invoker and no keys
        const doc = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid()
        };
        const result = await jsigs.verify(doc, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation(),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
      });

      it('should verify a self-invoked root ' +
        'capability with missing invoker and delegator', async () => {
        // invoke the root capability using the invoker key
        const doc = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid()
        };
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              alpha.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: didDocs.alpha.id
          })
        });
        // verify a self invoked capability
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: didDocs.alpha.id
          }),
          documentLoader: testLoader
        });

        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify a invoking root capability w/ separate target when ' +
        'a matching `expectedRootCapability` is given', async () => {
        const root = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          invocationTarget: uuid(),
          invoker: bob.id()
        };
        addToLoader({doc: root});
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: root.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: root.invocationTarget,
            expectedRootCapability: root.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify a root capability w/ separate target when ' +
        'a matching `expectedRootCapability` array is given', async () => {
        const root = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          invocationTarget: uuid(),
          invoker: bob.id()
        };
        addToLoader({doc: root});
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: root.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: root.invocationTarget,
            expectedRootCapability: [root.id],
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a root capability w/ separate target when ' +
        '`expectedRootCapability` is not a URI', async () => {
        const root = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          invocationTarget: uuid(),
          invoker: bob.id()
        };
        addToLoader({doc: root});
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: root.id
          })
        });
        // truncate the urn from the start of the root id
        // this will make it an invalid expectedRootCapability
        const expectedRootCapability = [root.id.replace('urn:uuid:', '')];
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: root.invocationTarget,
            expectedRootCapability,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
      });

      it('should fail to verify a root capability w/ separate target when ' +
        'no `expectedRootCapability` is given', async () => {
        const root = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          invocationTarget: uuid(),
          invoker: bob.id()
        };
        addToLoader({doc: root});
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: root.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: root.invocationTarget,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        // TODO: assert more about result.error
      });

      it('should verify a root capability w/ multiple controllers',
        async () => {
        const root = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          invocationTarget: uuid(),
          controller: ['urn:other', bob.id()],
        };
        addToLoader({doc: root});
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: root.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: root.invocationTarget,
            expectedRootCapability: root.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify a root capability w/ multiple invokers', async () => {
        const root = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          invocationTarget: uuid(),
          invoker: ['urn:other', bob.id()],
        };
        addToLoader({doc: root});
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: root.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: root.invocationTarget,
            expectedRootCapability: root.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify a capability chain of depth 2', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        const result = await jsigs.verify(delegatedCapability, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation(),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should verify invoking a capability chain of depth 2', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   4. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   5. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail if expectedRootCapability does not match', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   4. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   5. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            expectedRootCapability: 'urn:this-should-matter',
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'does not match actual root capability');
      });

      it('should fail if target does not match root ID', async () => {
        const mockRootCapability = clone(capabilities.root.beta);
        mockRootCapability.id = 'urn:bar';
        mockRootCapability.invocationTarget = 'urn:foo';
        addToLoader({doc: mockRootCapability});
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: mockRootCapability.id,
          invocationTarget: mockRootCapability.id,
          invoker: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [mockRootCapability.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   4. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   5. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: 'urn:foo',
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'root capability must not specify a different invocation target.');
      });

      it('should verify a capability chain of depth 2 and a ' +
        'valid caveat on one capability', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add a caveat that states the capability should expire an
        //      hour from now
        const expires = new Date();
        expires.setHours(expires.getHours() + 1);
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.id,
          invoker: bob.id()
        };
        new ExpirationCaveat({expires}).update(newCapability);
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018(),
            caveat: new ExpirationCaveat()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a capability chain of depth 2 when a ' +
        'caveat is not met on one capability', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add a caveat that states the capability should expire an
        //      hour ago
        const expires = new Date();
        expires.setHours(expires.getHours() - 1);
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.id,
          invoker: bob.id()
        };
        new ExpirationCaveat({expires}).update(newCapability);
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018(),
            caveat: new ExpirationCaveat()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.name.should.equal('VerificationError');
      });

      it('should verify a capability chain of depth 2 and an ' +
        'allowed action on one capability', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add an allowed action of `write`
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.id,
          invoker: bob.id(),
          allowedAction: 'write'
        };
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id,
            capabilityAction: 'write'
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a capability chain of depth 2 when a ' +
        '"capabilityAction" is required but missing', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add a caveat that states the capability should expire an
        //      hour ago
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.id,
          invoker: bob.id(),
          allowedAction: 'write'
        };
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            expectedAction: 'write',
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'action "undefined" does not match the expected capability action');
      });

      it('should fail to verify a capability chain of depth 2 when a ' +
        '"capabilityAction" is not in "allowedAction"', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add a caveat that states the capability should expire an
        //      hour ago
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.id,
          invoker: bob.id(),
          allowedAction: 'write'
        };
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id,
            capabilityAction: 'invalid'
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018()
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'action "invalid" is not allowed by the capability');
      });

      it('should verify a capability chain of depth 2 and a ' +
        'specific expected capability action', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add an allowed action of `write`
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id,
            capabilityAction: 'write'
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018(),
            capabilityAction: 'write'
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });

      it('should fail to verify a capability chain of depth 2 when an ' +
        'expected "capabilityAction" is required but missing', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add a caveat that states the capability should expire an
        //      hour ago
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018(),
            capabilityAction: 'write'
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'no proofs matched the required suite and purpose');
      });

      it('should fail to verify a capability chain of depth 2 when an ' +
        'expected "capabilityAction" does not match', async () => {
        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker should be Bob's ID
        //   3. Add a caveat that states the capability should expire an
        //      hour ago
        const newCapability = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: capabilities.root.beta.id,
          invocationTarget: capabilities.root.beta.id,
          invoker: bob.id()
        };
        //  4. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root capability
        const delegatedCapability = await jsigs.sign(newCapability, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [capabilities.root.beta.id]
          })
        });
        addToLoader({doc: delegatedCapability});
        //   5. Use Bob's invocation key that can be found in Bob's
        //      controller document of keys
        //   6. The invoker should be Bob's ID
        const doc = clone(mock.exampleDoc);
        const invocation = await jsigs.sign(doc, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityInvocation', 0))
          }),
          purpose: new CapabilityInvocation({
            capability: delegatedCapability.id,
            capabilityAction: 'write'
          })
        });
        const result = await jsigs.verify(invocation, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityInvocation({
            expectedTarget: capabilities.root.beta.id,
            suite: new Ed25519Signature2018(),
            capabilityAction: 'read'
          }),
          documentLoader: testLoader
        });
        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.name.should.equal('VerificationError');
        const [error] = result.error.errors;
        error.message.should.contain(
          'no proofs matched the required suite and purpose');
      });

      describe('chain depth of 3', () => {
        it('should verify a valid capability chain', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          addToLoader({doc: carolDelCap});
          const result = await jsigs.verify(carolDelCap, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityDelegation({
              suite: new Ed25519Signature2018()
            }),
            documentLoader: testLoader
          });
          expect(result).to.exist;
          expect(result.verified).to.be.true;
        });

        it('should fail to verify a capability chain ' +
          'with invalid allowedAction strings', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            allowedAction: 'read',
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            allowedAction: 'write',
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          addToLoader({doc: carolDelCap});
          const result = await jsigs.verify(carolDelCap, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityDelegation({
              suite: new Ed25519Signature2018()
            }),
            documentLoader: testLoader
          });
          should.exist(result);
          result.verified.should.be.false;
          should.exist(result.error);
          result.error.name.should.equal('VerificationError');
          const [error] = result.error.errors;
          error.message.should.contain(
            'delegated capability must be equivalent or more restrictive');
        });

        it('should fail to verify a capability chain ' +
          'with invalid allowedAction string vs array', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            allowedAction: 'read',
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            allowedAction: ['read', 'write'],
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          addToLoader({doc: carolDelCap});
          const result = await jsigs.verify(carolDelCap, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityDelegation({
              suite: new Ed25519Signature2018()
            }),
            documentLoader: testLoader
          });
          should.exist(result);
          result.verified.should.be.false;
          should.exist(result.error);
          result.error.name.should.equal('VerificationError');
          const [error] = result.error.errors;
          error.message.should.contain(
            'delegated capability must be equivalent or more restrictive');
        });

        it('should fail to verify a capability chain ' +
          'with invalid allowedAction arrays', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            allowedAction: ['read', 'write'],
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            allowedAction: ['foo', 'bar'],
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          addToLoader({doc: carolDelCap});
          const result = await jsigs.verify(carolDelCap, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityDelegation({
              suite: new Ed25519Signature2018()
            }),
            documentLoader: testLoader
          });
          should.exist(result);
          result.verified.should.be.false;
          should.exist(result.error);
          result.error.name.should.equal('VerificationError');
          const [error] = result.error.errors;
          error.message.should.contain(
            'delegated capability must be equivalent or more restrictive');
        });

        it('should verify a capability chain when child allowedAction is ' +
          'a valid subset of the parent allowedAction array', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            allowedAction: ['read', 'write'],
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            allowedAction: ['read'],
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          addToLoader({doc: carolDelCap});
          const result = await jsigs.verify(carolDelCap, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityDelegation({
              suite: new Ed25519Signature2018()
            }),
            documentLoader: testLoader
          });
          should.exist(result);
          result.verified.should.be.true;
        });

        it('should verify a capability chain when child allowedAction is ' +
          'a valid subset of the parent allowedAction undefined', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            allowedAction: 'read',
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          addToLoader({doc: carolDelCap});
          const result = await jsigs.verify(carolDelCap, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityDelegation({
              suite: new Ed25519Signature2018()
            }),
            documentLoader: testLoader
          });
          should.exist(result);
          result.verified.should.be.true;
        });

        it('should fail to verify a capability chain ' +
          'because of bad middle capability', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          ///    capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          // change ID to something else (breaking signature)
          bobDelCap.id = uuid();
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          addToLoader({doc: carolDelCap});
          const result = await jsigs.verify(carolDelCap, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityDelegation({
              suite: new Ed25519Signature2018()
            }),
            documentLoader: testLoader
          });
          expect(result).to.exist;
          expect(result.verified).to.be.false;
          result.error.name.should.equal('VerificationError');
        });

        it('should fail to verify a capability chain ' +
          'because of bad last capability', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          ///    capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          // change ID to something else (breaking signature)
          carolDelCap.id = uuid();
          addToLoader({doc: carolDelCap});
          const result = await jsigs.verify(carolDelCap, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityDelegation({
              suite: new Ed25519Signature2018()
            }),
            documentLoader: testLoader
          });
          expect(result).to.exist;
          expect(result.verified).to.be.false;
          result.error.name.should.equal('VerificationError');
          const [error] = result.error.errors;
          error.message.should.equal('Invalid signature.');
        });

        it('should verify a capability chain ' +
          'w/inspectCapabilityChain', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap]
            })
          });
          addToLoader({doc: carolDelCap});

          const inspectCapabilityChain = async ({
            capabilityChain, capabilityChainMeta
          }) => {
            capabilityChain.should.be.an('array');
            capabilityChain.should.have.length(2);
            capabilityChainMeta.should.be.an('array');
            capabilityChainMeta.should.have.length(2);
            _checkCapabilityChain({capabilityChain});
            // a real implementation would look for revocations here
            return {valid: true};
          };
          const result = await jsigs.verify(carolDelCap, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityDelegation({
              suite: new Ed25519Signature2018(),
              inspectCapabilityChain,
            }),
            documentLoader: testLoader
          });
          expect(result).to.exist;
          expect(result.verified).to.be.true;
        });
        it('should fail to verify a capability chain of depth 3 ' +
          'w/inspectCapabilityChain that includes a revoked capability',
          async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          addToLoader({doc: carolDelCap});

          const inspectCapabilityChain = async ({
            capabilityChain
          }) => {
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
          const result = await jsigs.verify(carolDelCap, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityDelegation({
              suite: new Ed25519Signature2018(),
              inspectCapabilityChain,
            }),
            documentLoader: testLoader
          });
          expect(result).to.exist;
          expect(result.verified).to.be.false;
          expect(result.error.errors[0]).to.exist;
          result.error.errors[0].message.should.contain('revoked');
        });

        it('should verify invoking a capability chain of depth 3', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          addToLoader({doc: carolDelCap});
          //   7. Use Carol's invocation key that can be found in Carol's
          //      controller document of keys
          //   8. The invoker should be Carol's ID
          const doc = clone(mock.exampleDoc);
          const invocation = await jsigs.sign(doc, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                carol.get('capabilityInvocation', 0))
            }),
            purpose: new CapabilityInvocation({
              capability: carolCap.id
            })
          });
          const result = await jsigs.verify(invocation, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityInvocation({
              expectedTarget: capabilities.root.beta.id,
              suite: new Ed25519Signature2018()
            }),
            documentLoader: testLoader
          });
          expect(result).to.exist;
          expect(result.verified).to.be.true;
        });

        it('should verify a capability chain of depth 3 w/ multiple delegators',
          async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: ['urn:other', bob.id()],
            delegator: ['urn:other', bob.id()]
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          addToLoader({doc: carolDelCap});
          //   7. Use Carol's invocation key that can be found in Carol's
          //      controller document of keys
          //   8. The invoker should be Carol's ID
          const doc = clone(mock.exampleDoc);
          const invocation = await jsigs.sign(doc, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                carol.get('capabilityInvocation', 0))
            }),
            purpose: new CapabilityInvocation({
              capability: carolCap.id
            })
          });
          const result = await jsigs.verify(invocation, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityInvocation({
              expectedTarget: capabilities.root.beta.id,
              suite: new Ed25519Signature2018()
            }),
            documentLoader: testLoader
          });
          expect(result).to.exist;
          expect(result.verified).to.be.true;
        });

        it('should fail to verify a capability chain of depth 3 when ' +
          'delegation is not permitted', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. Only the invoker should be Bob's ID, no delegator
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          addToLoader({doc: carolDelCap});
          //   7. Use Carol's invocation key that can be found in Carol's
          //      controller document of keys
          //   8. The invoker should be Carol's ID
          const doc = clone(mock.exampleDoc);
          const invocation = await jsigs.sign(doc, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                carol.get('capabilityInvocation', 0))
            }),
            purpose: new CapabilityInvocation({
              capability: carolCap.id
            })
          });
          const result = await jsigs.verify(invocation, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityInvocation({
              expectedTarget: capabilities.root.beta.id,
              suite: new Ed25519Signature2018()
            }),
            documentLoader: testLoader
          });
          expect(result).to.exist;
          expect(result.verified).to.be.false;
          result.error.name.should.equal('VerificationError');
        });

        it('should verify invoking a capability chain of depth 3 ' +
          'w/inspectCapabilityChain', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          addToLoader({doc: carolDelCap});
          //   7. Use Carol's invocation key that can be found in Carol's
          //      controller document of keys
          //   8. The invoker should be Carol's ID
          const doc = clone(mock.exampleDoc);
          const invocation = await jsigs.sign(doc, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                carol.get('capabilityInvocation', 0))
            }),
            purpose: new CapabilityInvocation({
              capability: carolCap.id
            })
          });

          const inspectCapabilityChain = async ({
            capabilityChain
          }) => {
            capabilityChain.should.be.an('array');
            capabilityChain.should.have.length(2);
            _checkCapabilityChain({capabilityChain});
            // a real implementation would look for revocations here
            return {valid: true};
          };
          const result = await jsigs.verify(invocation, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityInvocation({
              expectedTarget: capabilities.root.beta.id,
              suite: new Ed25519Signature2018(),
              inspectCapabilityChain,
            }),
            documentLoader: testLoader
          });

          expect(result).to.exist;
          expect(result.verified).to.be.true;
        });

        it('should fail invoking a capability chain of depth 3 ' +
          'w/inspectCapabilityChain and a revoked capability', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });
          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id()
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id]
            })
          });
          addToLoader({doc: carolDelCap});
          //   7. Use Carol's invocation key that can be found in Carol's
          //      controller document of keys
          //   8. The invoker should be Carol's ID
          const doc = clone(mock.exampleDoc);
          const invocation = await jsigs.sign(doc, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                carol.get('capabilityInvocation', 0))
            }),
            purpose: new CapabilityInvocation({
              capability: carolCap.id
            })
          });

          const inspectCapabilityChain = async ({
            capabilityChain
          }) => {
            should.exist(capabilityChain);
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
          const result = await jsigs.verify(invocation, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityInvocation({
              expectedTarget: capabilities.root.beta.id,
              suite: new Ed25519Signature2018(),
              inspectCapabilityChain,
            }),
            documentLoader: testLoader
          });
          expect(result).to.exist;
          expect(result.verified).to.be.false;
          expect(result.error.errors[0]).to.exist;
          result.error.errors[0].message.should.contain('revoked');
        });

        describe('expiration date', () => {
          it('CapabilityInvocation throws TypeError on currentDate = null',
            async () => {
            let result;
            let err;
            try {
              result = new CapabilityInvocation({
                expectedTarget:
                  'urn:uuid:1aaec12f-bcf2-40d8-8192-cc4dde9bca96',
                suite: new Ed25519Signature2018(),
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
                capabilityChain: [
                  'urn:uuid:1aaec12f-bcf2-40d8-8192-cc4dde9bca96',
                ],
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
          it('should verify invoking a capability with `expires`',
            async () => {
            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            let expires = new Date();
            expires.setHours(expires.getHours() + 1);
            expires = expires.toISOString();
            rootCapability.id = 'urn:zcap:9ff561b8-0b3f-4bbc-af00-03ba785a7fc6';
            rootCapability.expires = expires;
            addToLoader({doc: rootCapability});

            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id(),
              expires,
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID
            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id(),
              expires,
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018()
              }),
              documentLoader: testLoader
            });
            expect(result).to.exist;
            expect(result.verified).to.be.true;
          });

          it('should verify invoking a capability with `expires` ' +
            'and `currentDate` parameter in the past', async () => {
            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            // the capability is presently expired
            let expires = new Date();
            expires.setHours(expires.getHours() - 10);
            expires = expires.toISOString();
            rootCapability.id = 'urn:zcap:1c919b19-baab-45ee-b0ef-24309dfb355d';
            rootCapability.expires = expires;
            addToLoader({doc: rootCapability});

            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id(),
              expires,
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID
            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id(),
              expires,
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });

            // the capability was still valid 20 hours ago
            const currentDate = new Date();
            currentDate.setHours(currentDate.getHours() - 20);
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018(),
                currentDate,
              }),
              documentLoader: testLoader
            });
            expect(result).to.exist;
            expect(result.verified).to.be.true;
          });

          it('should fail invoking a capability with `expires` ' +
            'and `currentDate` parameter in the past', async () => {
            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            // the capability is presently expired
            let expires = new Date();
            expires.setHours(expires.getHours() - 50);
            expires = expires.toISOString();
            rootCapability.id = 'urn:zcap:142b0b4a-c664-4288-84e6-be0a59b6efa4';
            rootCapability.expires = expires;
            addToLoader({doc: rootCapability});

            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id(),
              expires,
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID
            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id(),
              expires,
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });

            // the capability was also expired 20 hours ago
            const currentDate = new Date();
            currentDate.setHours(currentDate.getHours() - 20);
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018(),
                currentDate,
              }),
              documentLoader: testLoader
            });
            expect(result).to.exist;
            expect(result.verified).to.be.false;
            should.exist(result.error);
            result.error.name.should.equal('VerificationError');
            const [error] = result.error.errors;
            error.message.should.equal('The root capability has expired.');
          });

          it('should fail invoking a capability with `expires` ' +
            'and `currentDate` parameter in the future', async () => {
            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            // the capability is presently valid
            let expires = new Date();
            expires.setHours(expires.getHours() + 50);
            expires = expires.toISOString();
            rootCapability.id = 'urn:zcap:bcbcde5e-d64a-4f46-a76e-daf52f63f702';
            rootCapability.expires = expires;
            addToLoader({doc: rootCapability});

            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id(),
              expires,
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID
            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id(),
              expires,
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });

            // the capability will have expired in 100 hours
            const currentDate = new Date();
            currentDate.setHours(currentDate.getHours() + 100);
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018(),
                currentDate,
              }),
              documentLoader: testLoader
            });
            expect(result).to.exist;
            expect(result.verified).to.be.false;
            should.exist(result.error);
            result.error.name.should.equal('VerificationError');
            const [error] = result.error.errors;
            error.message.should.equal('The root capability has expired.');
          });

          it('should fail invoking a capability with missing `expires` ' +
            'in the first delegated capability',
            async () => {
            // the root capability has expires, but the delegation does not

            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            let expires = new Date();
            expires.setHours(expires.getHours() + 1);
            expires = expires.toISOString();
            rootCapability.id = 'urn:zcap:7c496483-8e82-4c7c-867d-66874ca356f6';
            rootCapability.expires = expires;
            addToLoader({doc: rootCapability});

            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id()
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID
            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id(),
              expires,
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018()
              }),
              documentLoader: testLoader
            });
            expect(result).to.exist;
            expect(result.verified).to.be.false;
            should.exist(result.error);
            result.error.name.should.equal('VerificationError');
            const [error] = result.error.errors;
            error.message.should.include(
              'delegated capability must be equivalent or more restrictive');
          });

          it('should fail invoking a capability with missing `expires` in ' +
            'the second capability delegation', async () => {
            // the capability from alice to bob has proper expires, but the
            // capability from bob to carol does not

            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            let expires = new Date();
            expires.setHours(expires.getHours() + 1);
            expires = expires.toISOString();
            rootCapability.id = 'urn:zcap:ae96f88e-6b8a-4445-9b4f-03f45c3d1685';
            rootCapability.expires = expires;
            addToLoader({doc: rootCapability});

            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id(),
              expires,
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID
            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id()
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018()
              }),
              documentLoader: testLoader
            });
            expect(result).to.exist;
            expect(result.verified).to.be.false;
            should.exist(result.error);
            result.error.name.should.equal('VerificationError');
            const [error] = result.error.errors;
            error.message.should.include(
              'delegated capability must be equivalent or more restrictive');
          });

          it('should fail invoking a capability with expired ' +
            'root capability', async () => {
            // the entire chain has the same expiration date in the past

            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            let expires = new Date();
            expires.setHours(expires.getHours() - 1);
            expires = expires.toISOString();
            rootCapability.id = 'urn:zcap:028731be-69ae-460a-a4c6-5175883358a2';
            rootCapability.expires = expires;
            addToLoader({doc: rootCapability});

            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id(),
              expires,
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID
            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id(),
              expires,
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018()
              }),
              documentLoader: testLoader
            });
            expect(result).to.exist;
            expect(result.verified).to.be.false;
            should.exist(result.error);
            result.error.name.should.equal('VerificationError');
            const [error] = result.error.errors;
            error.message.should.contain('The root capability has expired.');
          });

          it('should fail invoking a capability with ' +
            'root capability that expires on the Unix epoch', async () => {
            // the entire chain has the same expiration date in the past

            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            // set the expires to the Unix epoch
            let expires = new Date(0);
            expires = expires.toISOString();

            rootCapability.id = 'urn:zcap:cbddee5a-09fb-44db-a921-70c36436c253';
            rootCapability.expires = expires;
            addToLoader({doc: rootCapability});

            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id(),
              expires,
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID
            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id(),
              expires,
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018()
              }),
              documentLoader: testLoader
            });
            expect(result).to.exist;
            expect(result.verified).to.be.false;
            should.exist(result.error);
            result.error.errors.should.have.length(1);
            const [error] = result.error.errors;
            error.message.should.contain(
              'root capability has expired');
          });

          it('should fail invoking a capability with expired ' +
            'second delegated capability', async () => {
            // the root capability specifies a date in the future, but
            // the delegation from bob to carol specifies a date that is in the
            // past

            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            let expires = new Date();
            expires.setHours(expires.getHours() + 10);
            expires = expires.toISOString();
            rootCapability.id = 'urn:zcap:3c034da3-8b5e-4fdc-b75d-8c37d73cd21e';
            rootCapability.expires = expires;
            addToLoader({doc: rootCapability});

            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id(),
              expires,
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID

            // set expires for this delegation well in the past
            expires = new Date();
            expires.setHours(expires.getHours() - 10);
            expires = expires.toISOString();
            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id(),
              expires,
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018()
              }),
              documentLoader: testLoader
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
            // the root capability specifies a date in the future, but
            // the delegation from bob to carol specifies a date that is in the
            // past

            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            let expires = new Date();
            expires.setHours(expires.getHours() + 10);
            expires = expires.toISOString();
            rootCapability.id = 'urn:zcap:6286a906-619b-4f5b-a8ae-af9fb774b070';
            rootCapability.expires = expires;
            addToLoader({doc: rootCapability});

            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id(),
              expires,
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID

            // set expires for this delegation to the Unix epoch
            expires = new Date(0);
            expires = expires.toISOString();
            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id(),
              expires,
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018()
              }),
              documentLoader: testLoader
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
          'first delegated capability that expires after root', async () => {
            // the root capability specifies a date in the future, but
            // the delegation from bob to carol specifies a date that is in the
            // past

            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            let expires = new Date();
            expires.setHours(expires.getHours() + 10);
            expires = expires.toISOString();
            rootCapability.id = 'urn:zcap:1e7dfae9-85a3-40d7-97ea-20105f0b9d99';
            rootCapability.expires = expires;
            addToLoader({doc: rootCapability});

            // set expires for this delegation beyond the expiration of the
            // root capability, which is not allowed
            expires = new Date();
            expires.setHours(expires.getHours() + 100);
            expires = expires.toISOString();
            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id(),
              expires,
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID

            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id(),
              expires,
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018()
              }),
              documentLoader: testLoader
            });
            expect(result).to.exist;
            expect(result.verified).to.be.false;
            should.exist(result.error);
            result.error.name.should.equal('VerificationError');
            const [error] = result.error.errors;
            error.message.should.contain(
              'delegated capability must be equivalent or more restrictive');
          });

          it('should fail invoking a capability with ' +
            'second delegated capability that expires after root', async () => {
            // the root capability specifies a date in the future, but
            // the delegation from bob to carol specifies a date that is in the
            // past

            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            let expires = new Date();
            expires.setHours(expires.getHours() + 10);
            expires = expires.toISOString();
            rootCapability.id = 'urn:zcap:79eed455-ff71-4302-96b5-436de2ca9190';
            rootCapability.expires = expires;
            addToLoader({doc: rootCapability});

            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id(),
              expires,
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID

            // set expires for this delegation beyond the expiration of the
            // root capability, which is not allowed
            expires = new Date();
            expires.setHours(expires.getHours() + 100);
            expires = expires.toISOString();
            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id(),
              expires,
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018()
              }),
              documentLoader: testLoader
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
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            rootCapability.id = 'urn:zcap:a0d0360b-7e93-4c9c-8804-69ca426c60c3';
            addToLoader({doc: rootCapability});

            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id(),
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID

            // set expires for this delegation well in the past
            let expires = new Date();
            expires.setHours(expires.getHours() + 10);
            expires = expires.toISOString();
            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id(),
              expires,
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018()
              }),
              documentLoader: testLoader
            });
            expect(result).to.exist;
            expect(result.verified).to.be.true;
          });

          it('should fail invoking a capability with only an expired ' +
            'second delegated capability', async () => {
            // only the second delegation has an expiration in the past

            // Create a delegated capability
            //   1. Parent capability should point to the root capability
            //   2. The invoker and delegator should be Bob's ID
            const rootCapability = Object.assign({}, capabilities.root.beta);

            rootCapability.id = 'urn:zcap:2c41869c-95bb-4e23-9bcd-2fbb320bb440';
            addToLoader({doc: rootCapability});

            const bobCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: rootCapability.id,
              invocationTarget: rootCapability.id,
              invoker: bob.id(),
              delegator: bob.id(),
            };
            //  3. Sign the delegated capability with Alice's delegation key;
            //     Alice's ID was specified as the delegator in the root
            //     capability
            const bobDelCap = await jsigs.sign(bobCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id]
              })
            });
            addToLoader({doc: bobDelCap});
            // Create a delegated capability for Carol
            //   4. Parent capability should point to Bob's capability
            //   5. The invoker should be Carol's ID

            // set expires for this delegation well in the past
            let expires = new Date();
            expires.setHours(expires.getHours() - 10);
            expires = expires.toISOString();
            const carolCap = {
              '@context': SECURITY_CONTEXT_URL,
              id: uuid(),
              parentCapability: bobCap.id,
              invocationTarget: bobCap.invocationTarget,
              invoker: carol.id(),
              expires,
            };
            //  6. Sign the delegated capability with Bob's delegation key
            //     that was specified as the delegator in Bob's capability
            const carolDelCap = await jsigs.sign(carolCap, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  bob.get('capabilityDelegation', 0))
              }),
              purpose: new CapabilityDelegation({
                capabilityChain: [rootCapability.id, bobCap.id]
              })
            });
            addToLoader({doc: carolDelCap});
            //   7. Use Carol's invocation key that can be found in Carol's
            //      controller document of keys
            //   8. The invoker should be Carol's ID
            const doc = clone(mock.exampleDoc);
            const invocation = await jsigs.sign(doc, {
              suite: new Ed25519Signature2018({
                key: new Ed25519VerificationKey2018(
                  carol.get('capabilityInvocation', 0))
              }),
              purpose: new CapabilityInvocation({
                capability: carolCap.id
              })
            });
            const result = await jsigs.verify(invocation, {
              suite: new Ed25519Signature2018(),
              purpose: new CapabilityInvocation({
                expectedTarget: rootCapability.id,
                suite: new Ed25519Signature2018()
              }),
              documentLoader: testLoader
            });
            expect(result).to.exist;
            expect(result.verified).to.be.false;
            should.exist(result.error);
            result.error.name.should.equal('VerificationError');
            const [error] = result.error.errors;
            error.message.should.equal(
              'A capability in the delegation chain has expired.');
          });
        }); // end expiration date
      }); // end chain depth of 3

      describe('chain depth of 4', () => {
        it('should verify a capability chain ' +
          'w/inspectCapabilityChain', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });

          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id(),
            delegator: carol.id(),
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobDelCap]
            })
          });
          addToLoader({doc: carolDelCap});

          // Create a delegated capability for Diana
          //   4. Parent capability should point to Carol's capability
          //   5. The invoker should be Diana's ID
          const dianaCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: carolCap.id,
            invocationTarget: carolCap.invocationTarget,
            invoker: diana.id()
          };
          //  6. Sign the delegated capability with Carol's delegation key
          //     that was specified as the delegator in Carol's capability
          const dianaDelCap = await jsigs.sign(dianaCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                carol.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id, carolCap]
            })
          });
          addToLoader({doc: dianaDelCap});

          const inspectCapabilityChain = async ({
            capabilityChain, capabilityChainMeta
          }) => {
            capabilityChain.should.be.an('array');
            capabilityChain.should.have.length(3);
            capabilityChainMeta.should.be.an('array');
            capabilityChainMeta.should.have.length(3);
            _checkCapabilityChain({capabilityChain});
            // a real implementation would look for revocations here
            return {valid: true};
          };

          const result = await jsigs.verify(dianaDelCap, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityDelegation({
              suite: new Ed25519Signature2018(),
              inspectCapabilityChain,
            }),
            documentLoader: testLoader
          });
          expect(result).to.exist;
          expect(result.verified).to.be.true;
        });

        it('should fail a capability chain that exceeds maxChainLength',
          async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });

          addToLoader({doc: bobDelCap});
          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id(),
            delegator: carol.id(),
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobDelCap]
            })
          });
          addToLoader({doc: carolDelCap});

          // Create a delegated capability for Diana
          //   4. Parent capability should point to Carol's capability
          //   5. The invoker should be Diana's ID
          const dianaCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: carolCap.id,
            invocationTarget: carolCap.invocationTarget,
            invoker: diana.id()
          };
          //  6. Sign the delegated capability with Carol's delegation key
          //     that was specified as the delegator in Carol's capability
          const dianaDelCap = await jsigs.sign(dianaCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                carol.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobCap.id, carolCap]
            })
          });
          addToLoader({doc: dianaDelCap});

          const inspectCapabilityChain = async ({
            capabilityChain, capabilityChainMeta
          }) => {
            capabilityChain.should.be.an('array');
            capabilityChain.should.have.length(3);
            capabilityChainMeta.should.be.an('array');
            capabilityChainMeta.should.have.length(3);
            _checkCapabilityChain({capabilityChain});
            // a real implementation would look for revocations here
            return {valid: true};
          };

          const result = await jsigs.verify(dianaDelCap, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityDelegation({
              suite: new Ed25519Signature2018(),
              inspectCapabilityChain,
              maxChainLength: 2,
            }),
            documentLoader: testLoader
          });
          expect(result).to.exist;
          expect(result.verified).to.be.false;
          should.exist(result.error);
          should.exist(result.error.errors);
          result.error.errors.should.have.length(1);
          result.error.errors[0].message.should.equal(
            'The capabability chain exceeds the maximum allowed length of 2.');
        });

        it('should verify a capability chain ' +
          'w/inspectCapabilityChain using embedded capabilities from ' +
          'capabilityChain', async () => {
          // Create a delegated capability
          //   1. Parent capability should point to the root capability
          //   2. The invoker and delegator should be Bob's ID
          const bobCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: capabilities.root.beta.id,
            invocationTarget: capabilities.root.beta.id,
            invoker: bob.id(),
            delegator: bob.id()
          };
          //  3. Sign the delegated capability with Alice's delegation key;
          //     Alice's ID was specified as the delegator in the root
          //     capability
          const bobDelCap = await jsigs.sign(bobCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id]
            })
          });

          // Create a delegated capability for Carol
          //   4. Parent capability should point to Bob's capability
          //   5. The invoker should be Carol's ID
          const carolCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: bobCap.id,
            invocationTarget: bobCap.invocationTarget,
            invoker: carol.id(),
            delegator: carol.id(),
          };
          //  6. Sign the delegated capability with Bob's delegation key
          //     that was specified as the delegator in Bob's capability
          const carolDelCap = await jsigs.sign(carolCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                bob.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [capabilities.root.beta.id, bobDelCap]
            })
          });

          // Create a delegated capability for Diana
          //   4. Parent capability should point to Carol's capability
          //   5. The invoker should be Diana's ID
          const dianaCap = {
            '@context': SECURITY_CONTEXT_URL,
            id: uuid(),
            parentCapability: carolCap.id,
            invocationTarget: carolCap.invocationTarget,
            invoker: diana.id()
          };
          //  6. Sign the delegated capability with Carol's delegation key
          //     that was specified as the delegator in Carol's capability
          const dianaDelCap = await jsigs.sign(dianaCap, {
            suite: new Ed25519Signature2018({
              key: new Ed25519VerificationKey2018(
                carol.get('capabilityDelegation', 0))
            }),
            purpose: new CapabilityDelegation({
              capabilityChain: [
                capabilities.root.beta.id, bobCap.id, carolDelCap
              ]
            })
          });

          const inspectCapabilityChain = async ({
            capabilityChain, capabilityChainMeta
          }) => {
            capabilityChain.should.be.an('array');
            capabilityChain.should.have.length(3);
            capabilityChainMeta.should.be.an('array');
            capabilityChainMeta.should.have.length(3);
            _checkCapabilityChain({capabilityChain});
            // a real implementation would look for revocations here
            return {valid: true};
          };

          const result = await jsigs.verify(dianaDelCap, {
            suite: new Ed25519Signature2018(),
            purpose: new CapabilityDelegation({
              suite: new Ed25519Signature2018(),
              inspectCapabilityChain,
            }),
            documentLoader: testLoader
          });
          expect(result).to.exist;
          expect(result.verified).to.be.true;
        });
      }); // end chain depth of 4
    });
    describe('Hierarchical Delegation', () => {
      it('should verify a capability chain with hierachical delegation',
        async () => {

        const rootCapability = {
          id: 'https://example.com/edvs/cc8b09fd-76e2-4fae-9bdd-2522b83a2971',
          controller: alice.id(),
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.id,
          invoker: bob.id(),
          delegator: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [rootCapability.id]
          })
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          invoker: carol.id(),
          delegator: carol.id(),
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [rootCapability.id, bobDelCap]
          })
        });

        // Create a delegated capability for Diana
        //   4. Parent capability should point to Carol's capability
        //   5. The invoker should be Diana's ID

        // delegate access to a specific document under carol's capability
        const invocationTarget =
          `${carolCap.invocationTarget}/a-specific-document`;
        const dianaCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          invocationTarget,
          invoker: diana.id()
        };

        //  6. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability
        const dianaDelCap = await jsigs.sign(dianaCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              carol.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [
              rootCapability.id, bobCap.id, carolDelCap
            ]
          })
        });

        const result = await jsigs.verify(dianaDelCap, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation({
            allowTargetAttenuation: true,
            suite: new Ed25519Signature2018(),
          }),
          documentLoader: testLoader
        });

        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });
      it('should fail hierachical delegation that is more permissive ' +
        'than the parent capability',
        async () => {

        const rootCapability = {
          id: 'https://example.com/edvs/357570f6-8df2-4e78-97dc-42260d64e78e',
          controller: alice.id(),
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.id,
          invoker: bob.id(),
          delegator: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [rootCapability.id]
          })
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID

        // delegate access to a specific document under bob's capability
        const invocationTarget =
          `${bobCap.invocationTarget}/a-specific-document`;
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget,
          invoker: carol.id(),
          delegator: carol.id(),
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [rootCapability.id, bobDelCap]
          })
        });

        // Create a delegated capability for Diana
        //   4. Parent capability should point to Carol's capability
        //   5. The invoker should be Diana's ID

        const dianaCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          // NOTE: this is an invalid attempt to degate a capability to the
          // root of the EDV when carol's zcap has an invocationTarget that
          // is a specific EDV document
          invocationTarget: bobCap.invocationTarget,
          invoker: diana.id()
        };

        //  6. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability
        const dianaDelCap = await jsigs.sign(dianaCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              carol.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [
              rootCapability.id, bobCap.id, carolDelCap
            ]
          })
        });

        const result = await jsigs.verify(dianaDelCap, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation({
            allowTargetAttenuation: true,
            suite: new Ed25519Signature2018(),
          }),
          documentLoader: testLoader
        });

        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.errors.should.have.length(1);
        const [error] = result.error.errors;
        error.message.should.include(
          'delegated capability must be equivalent or more restrictive');
      });
      it('should fail hierachical delegation when ' +
        'allowTargetAttenuation is not explicitly allowed',
        async () => {

        const rootCapability = {
          id: 'https://example.com/edvs/2c2fe4ab-ff54-4a82-b103-f806f50d364e',
          controller: alice.id(),
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.id,
          invoker: bob.id(),
          delegator: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [rootCapability.id]
          })
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          invoker: carol.id(),
          delegator: carol.id(),
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [rootCapability.id, bobDelCap]
          })
        });

        // Create a delegated capability for Diana
        //   4. Parent capability should point to Carol's capability
        //   5. The invoker should be Diana's ID

        // delegate access to a specific document under carol's capability
        const invocationTarget =
          `${carolCap.invocationTarget}/a-specific-document`;
        const dianaCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          invocationTarget,
          invoker: diana.id()
        };

        //  6. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability
        const dianaDelCap = await jsigs.sign(dianaCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              carol.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [
              rootCapability.id, bobCap.id, carolDelCap
            ]
          })
        });

        const result = await jsigs.verify(dianaDelCap, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation({
            // NOTE: allowTargetAttenuation is intentionally not set
            // here, the default is false
            // allowTargetAttenuation: true,
            suite: new Ed25519Signature2018(),
          }),
          documentLoader: testLoader
        });

        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.errors.should.have.length(1);
        const [error] = result.error.errors;
        error.message.should.contain('must be equivalent to its parent');
      });
      it('should verify a capability chain with hierachical delegation ' +
        'and inspectCapabilityChain',
        async () => {

        const rootCapability = {
          id: 'https://example.com/edvs/83d7e997-d742-4b1a-9033-968f222b9144',
          controller: alice.id(),
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.id,
          invoker: bob.id(),
          delegator: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [rootCapability.id]
          })
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget: bobCap.invocationTarget,
          invoker: carol.id(),
          delegator: carol.id(),
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [rootCapability.id, bobDelCap]
          })
        });

        // Create a delegated capability for Diana
        //   4. Parent capability should point to Carol's capability
        //   5. The invoker should be Diana's ID

        // delegate access to a specific document under carol's capability
        const invocationTarget =
          `${carolCap.invocationTarget}/a-specific-document`;
        const dianaCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          invocationTarget,
          invoker: diana.id()
        };

        //  6. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability
        const dianaDelCap = await jsigs.sign(dianaCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              carol.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [
              rootCapability.id, bobCap.id, carolDelCap
            ]
          })
        });

        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(3);
          capabilityChainMeta.should.be.an('array');
          capabilityChainMeta.should.have.length(3);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {valid: true};
        };

        const result = await jsigs.verify(dianaDelCap, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation({
            allowTargetAttenuation: true,
            suite: new Ed25519Signature2018(),
            inspectCapabilityChain,
          }),
          documentLoader: testLoader
        });

        expect(result).to.exist;
        expect(result.verified).to.be.true;
      });
      it('should fail an increasingly permissive capability chain with ' +
        'hierachical delegation and inspectCapabilityChain',
        async () => {

        const rootCapability = {
          id: 'https://example.com/edvs/d9dd2093-0908-47ba-8db7-954ff1cd81ee',
          controller: alice.id(),
        };
        addToLoader({doc: rootCapability});

        // Create a delegated capability
        //   1. Parent capability should point to the root capability
        //   2. The invoker and delegator should be Bob's ID
        const bobCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: rootCapability.id,
          invocationTarget: rootCapability.id,
          invoker: bob.id(),
          delegator: bob.id()
        };
        //  3. Sign the delegated capability with Alice's delegation key;
        //     Alice's ID was specified as the delegator in the root
        //     capability
        const bobDelCap = await jsigs.sign(bobCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(alice.get('verificationMethod', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [rootCapability.id]
          })
        });

        // Create a delegated capability for Carol
        //   4. Parent capability should point to Bob's capability
        //   5. The invoker should be Carol's ID

        // delegate access to a specific document under bob's capability
        const invocationTarget =
          `${bobCap.invocationTarget}/a-specific-document`;
        const carolCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: bobCap.id,
          invocationTarget,
          invoker: carol.id(),
          delegator: carol.id(),
        };
        //  6. Sign the delegated capability with Bob's delegation key
        //     that was specified as the delegator in Bob's capability
        const carolDelCap = await jsigs.sign(carolCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              bob.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [rootCapability.id, bobDelCap]
          })
        });

        // Create a delegated capability for Diana
        //   4. Parent capability should point to Carol's capability
        //   5. The invoker should be Diana's ID
        const dianaCap = {
          '@context': SECURITY_CONTEXT_URL,
          id: uuid(),
          parentCapability: carolCap.id,
          // NOTE: this is an invalid attempt to degate a capability to the
          // root of the EDV when carol's zcap has an invocationTarget that
          // is a specific EDV document
          invocationTarget: bobCap.invocationTarget,
          invoker: diana.id()
        };

        //  6. Sign the delegated capability with Carol's delegation key
        //     that was specified as the delegator in Carol's capability
        const dianaDelCap = await jsigs.sign(dianaCap, {
          suite: new Ed25519Signature2018({
            key: new Ed25519VerificationKey2018(
              carol.get('capabilityDelegation', 0))
          }),
          purpose: new CapabilityDelegation({
            capabilityChain: [
              rootCapability.id, bobCap.id, carolDelCap
            ]
          })
        });

        const inspectCapabilityChain = async ({
          capabilityChain, capabilityChainMeta
        }) => {
          capabilityChain.should.be.an('array');
          capabilityChain.should.have.length(3);
          capabilityChainMeta.should.be.an('array');
          capabilityChainMeta.should.have.length(3);
          _checkCapabilityChain({capabilityChain});
          // a real implementation would look for revocations here
          return {valid: true};
        };

        const result = await jsigs.verify(dianaDelCap, {
          suite: new Ed25519Signature2018(),
          purpose: new CapabilityDelegation({
            allowTargetAttenuation: true,
            suite: new Ed25519Signature2018(),
            inspectCapabilityChain,
          }),
          documentLoader: testLoader
        });

        expect(result).to.exist;
        expect(result.verified).to.be.false;
        result.error.errors.should.have.length(1);
        result.error.errors[0].errors.should.have.length(1);
        const [error] = result.error.errors[0].errors;
        error.message.should.include(
          'delegated capability must be equivalent or more restrictive');
      });
    }); // end Hierarchical Delegation
  });
});

};

function _checkCapabilityChain({capabilityChain}) {
  for(const [i, c] of capabilityChain.entries()) {
    c.should.be.an('object');
    c.should.have.property('id');
    c.should.have.property('invoker');
    // the last capability will not have a delegator field
    if(i < capabilityChain.length - 1) {
      c.should.have.property('delegator');
    }
  }
}
