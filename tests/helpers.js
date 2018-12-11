const api = {};
module.exports = api;

api.Owner = class Owner {
  constructor(doc) {
    // doc is the key owner document
    this.doc = doc;
  }

  id() {
    return this.doc.id;
  }

  get(keyType, index) {
    return this.doc[keyType][index];
  }
};

const b = a=>a?(a^Math.random()*16>>a/4).toString(16):([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g,b);
api.uuid = () => `urn:uuid:${b()}`;
