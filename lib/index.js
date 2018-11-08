/**
 * Copyright (c) 2018 Digital Bazaar, Inc.
 *
 * @author Christopher Lemmer Webber
 * @author Ganesh Annan <gannan@digitalbazaar.com>
 * 
 */
'use strict';

const proofPurposes = {
  CapabilityInvocation: require('./CapabilityInvocation'),
  CapabilityDelegation: require('./CapabilityDelegation')
};

module.exports = {
  proofPurposes,
  install: jsigs => {
    for(const proofPurpose in proofPurposes) {
      jsigs.proofPurposes[proofPurpose] = proofPurposes[proofPurpose];
    }
  }
};
