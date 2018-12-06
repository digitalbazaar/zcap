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
