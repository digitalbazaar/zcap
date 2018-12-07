/**
 * Copyright (c) 2018 Digital Bazaar, Inc.
 *
 * @author Christopher Lemmer Webber
 * @author Ganesh Annan <gannan@digitalbazaar.com>
 *
 */
'use strict';

// FIXME: Update ocap context url before release
const ocapBaseUri = 'https://example.org/ocap/v1#';

// Vocabulary URIs
const ExpireAtUri = prefixedOcapUri('ExpireAt');
const expireAtUri = prefixedOcapUri('expireAt');

module.exports = {
  ExpireAtUri,
  expireAtUri
};

function prefixedOcapUri(suffix) {
  return ocapBaseUri + suffix;
}
