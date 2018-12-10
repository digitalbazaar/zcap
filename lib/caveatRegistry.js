/*!
 * Copyright (c) 2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const vocab = require('./vocab');

const {ExpireAtUri} = vocab;

const defaultCaveatRegistry = {};
module.exports = defaultCaveatRegistry;

defaultCaveatRegistry[ExpireAtUri] = checkExpireAtCaveat;

async function checkExpireAtCaveat({caveat, purposeParameters}) {
  let currDate;
  if('getDate' in purposeParameters) {
    currDate = purposeParameters.getDate();
  } else {
    currDate = new Date();
  }
  const expiresDate = new Date(caveat.expires);
  return currDate <= expiresDate;
}
