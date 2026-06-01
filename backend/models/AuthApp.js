const mongoose = require('mongoose');

const authAppSchema = new mongoose.Schema(
  {
    appId: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      maxlength: 80,
      index: true,
    },
    displayName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 120,
    },
    status: {
      type: String,
      enum: ['active', 'disabled'],
      default: 'active',
      index: true,
    },
    allowedOrigins: {
      type: [String],
      default: [],
    },
    allowedRedirectOrigins: {
      type: [String],
      default: [],
    },
    requiredLinkedProviders: {
      type: [String],
      default: [],
    },
    policyResolver: {
      type: String,
      default: null,
      trim: true,
      maxlength: 120,
    },
    dashboardUrl: {
      type: String,
      default: '',
      trim: true,
      maxlength: 2000,
    },
    firstParty: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  }
);

module.exports = mongoose.model('AuthApp', authAppSchema);
