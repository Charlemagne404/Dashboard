const mongoose = require('mongoose');

// Short lived, single-use ceremonies. Mongo TTL cleanup is not expiry enforcement.
const schema = new mongoose.Schema({
  _id: { type: String, required: true },
  kind: { type: String, enum: ['oauth', 'webauthn'], required: true },
  browserHash: { type: String, default: '' },
  verifier: { type: String, default: '' },
  nonce: { type: String, default: '' },
  expiresAt: { type: Date, required: true },
}, { versionKey: false });
schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
module.exports = mongoose.model('AuthChallenge', schema);
