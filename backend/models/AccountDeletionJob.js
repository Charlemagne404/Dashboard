const mongoose = require('mongoose');
const schema = new mongoose.Schema({
  _id: { type: mongoose.Schema.Types.ObjectId, required: true },
  createdAt: { type: Date, default: Date.now },
}, { versionKey: false });
module.exports = mongoose.model('AccountDeletionJob', schema);
