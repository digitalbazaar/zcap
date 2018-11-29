/**
 * Copyright (c) 2018 Digital Bazaar, Inc.
 *
 * @author Christopher Lemmer Webber
 * @author Ganesh Annan <gannan@digitalbazaar.com>
 *
 */
'use strict';

const utils = require('./utils');
const vocab = require('./vocab');

const {ExpireAtUri, RestrictActionUri} = vocab;

const defaultCaveatRegistry = {};
module.exports = defaultCaveatRegistry;

defaultCaveatRegistry[ExpireAtUri] = checkExpireAtCaveat;
defaultCaveatRegistry[RestrictActionUri] = checkRestrictActionCaveat;

async function checkExpireAtCaveat({caveat, capability, purposeParameters}) {
  const {expireAtUri} = vocab;

  let currDate;
  if('getDate' in purposeParameters) {
    currDate = purposeParameters.getDate();
  } else {
    currDate = new Date();
  }
  // FIXME: is it true that `expiresDate` is a Date?
  const expiresDate = new Date(utils.getOne(purposeParameters[expireAtUri]));
  return currDate <= expiresDate;
}

function checkRestrictActionCaveat({caveat, capability, purposeParameters}) {
  const {restrictActionUri} = vocab;

  return caveat[restrictActionUri].includes(
    utils.getOne(capability['@type']));
}
