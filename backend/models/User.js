const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const loginEventSchema = new mongoose.Schema(
  {
    at: { type: Date, default: Date.now },
    ip: { type: String, default: '' },
    userAgent: { type: String, default: '' },
  },
  { _id: false }
);

const loginDayCountSchema = new mongoose.Schema(
  {
    day: { type: String, required: true, trim: true, maxlength: 10 },
    count: { type: Number, default: 0, min: 0 },
  },
  { _id: false }
);

const refreshSessionSchema = new mongoose.Schema(
  {
    sid: { type: String, required: true },
    label: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now },
    lastUsedAt: { type: Date, default: Date.now },
    ip: { type: String, default: '' },
    userAgent: { type: String, default: '' },
    deviceFingerprint: { type: String, default: '' },
    currentRefreshTokenId: { type: String, default: '' },
    previousRefreshTokenId: { type: String, default: '' },
    previousRefreshTokenGraceUntil: { type: Date, default: null },
  },
  { _id: false }
);

const knownDeviceSchema = new mongoose.Schema(
  {
    fingerprint: { type: String, required: true, trim: true, maxlength: 128 },
    label: { type: String, default: '', trim: true, maxlength: 60 },
    trusted: { type: Boolean, default: false },
    firstSeenAt: { type: Date, default: Date.now },
    lastSeenAt: { type: Date, default: Date.now },
    lastIp: { type: String, default: '' },
    userAgent: { type: String, default: '' },
  },
  { _id: false }
);

const auditEventSchema = new mongoose.Schema(
  {
    at: { type: Date, default: Date.now },
    type: { type: String, required: true, trim: true, maxlength: 60 },
    message: { type: String, default: '', trim: true, maxlength: 240 },
    ip: { type: String, default: '' },
    userAgent: { type: String, default: '' },
    meta: {
      type: Object,
      default: {},
    },
  },
  { _id: false }
);

const passkeySchema = new mongoose.Schema(
  {
    credentialId: { type: String, required: true, trim: true, maxlength: 512 },
    publicKey: { type: Buffer, required: true },
    counter: { type: Number, default: 0, min: 0 },
    transports: {
      type: [String],
      default: [],
    },
    deviceType: {
      type: String,
      enum: ['singleDevice', 'multiDevice'],
      default: 'singleDevice',
    },
    backedUp: { type: Boolean, default: false },
    aaguid: { type: String, default: '', trim: true, maxlength: 64 },
    name: { type: String, default: '', trim: true, maxlength: 80 },
    createdAt: { type: Date, default: Date.now },
    lastUsedAt: { type: Date, default: null },
  },
  { _id: false }
);

const oauthIdentitySchema = new mongoose.Schema(
  {
    provider: { type: String, required: true, trim: true, lowercase: true, maxlength: 40 },
    providerUserId: { type: String, required: true, trim: true, maxlength: 160 },
    username: { type: String, default: '', trim: true, maxlength: 120 },
    email: { type: String, default: '', trim: true, lowercase: true, maxlength: 320 },
    emailVerified: { type: Boolean, default: false },
    profileUrl: { type: String, default: '', trim: true, maxlength: 1000 },
    avatarUrl: { type: String, default: '', trim: true, maxlength: 1000 },
    linkedAt: { type: Date, default: Date.now },
    lastUsedAt: { type: Date, default: null },
  },
  { _id: false }
);

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true,
    },
    username: {
      type: String,
      unique: true,
      sparse: true,
      lowercase: true,
      trim: true,
      minlength: 3,
      maxlength: 30,
      match: /^[a-z0-9](?:[a-z0-9._-]{1,28}[a-z0-9])?$/,
      index: true,
    },
    displayName: {
      type: String,
      default: '',
      trim: true,
      maxlength: 60,
    },
    accountRole: {
      type: String,
      enum: ['user', 'owner'],
      default: 'user',
      index: true,
    },
    accountStatus: {
      type: String,
      enum: ['active', 'suspended'],
      default: 'active',
      index: true,
    },
    accountStatusReason: {
      type: String,
      default: '',
      trim: true,
      maxlength: 240,
    },
    password: { type: String, required: true },
    refreshTokenVersion: { type: Number, default: 0 },
    refreshSessions: {
      type: [refreshSessionSchema],
      default: [],
    },
    isVerified: { type: Boolean, default: false },
    verificationToken: { type: String, default: '' },
    verificationTokenExpires: { type: Date, default: null },
    emailDelivery: {
      verificationLastSentAt: { type: Date, default: null },
    },
    passwordResetToken: { type: String, default: '' },
    passwordResetTokenExpires: { type: Date, default: null },
    passwordResetRequestedAt: { type: Date, default: null },
    lastLoginAt: { type: Date },
    lastLoginIp: { type: String, default: '' },
    recentLogins: {
      type: [loginEventSchema],
      default: [],
    },
    loginDayCounts: {
      type: [loginDayCountSchema],
      default: [],
    },
    knownDevices: {
      type: [knownDeviceSchema],
      default: [],
    },
    auditEvents: {
      type: [auditEventSchema],
      default: [],
    },
    profile: {
      avatar: { type: String, default: '', maxlength: 350000 },
      avatarMeta: {
        kind: { type: String, default: '', trim: true, lowercase: true, maxlength: 24 },
        mimeType: { type: String, default: '', trim: true, lowercase: true, maxlength: 40 },
        width: { type: Number, default: 0, min: 0, max: 4096 },
        height: { type: Number, default: 0, min: 0, max: 4096 },
        updatedAt: { type: Date, default: null },
      },
      headline: { type: String, default: '', maxlength: 100 },
      role: { type: String, default: '', maxlength: 100 },
      organization: { type: String, default: '', maxlength: 100 },
      currentFocus: { type: String, default: '', maxlength: 160 },
      focusAreas: {
        type: [String],
        default: [],
      },
      pronouns: { type: String, default: '', maxlength: 40 },
      bio: { type: String, default: '', maxlength: 320 },
      location: { type: String, default: '', maxlength: 120 },
      website: { type: String, default: '', maxlength: 240 },
      timezone: { type: String, default: 'UTC', maxlength: 80 },
      language: { type: String, default: 'en', maxlength: 32 },
    },
    linkedAccounts: {
      google: { type: String, default: '' },
      facebook: { type: String, default: '' },
      github: { type: String, default: '' },
      twitter: { type: String, default: '' },
      linkedin: { type: String, default: '' },
      discord: { type: String, default: '' },
      apple: { type: String, default: '' },
      microsoft: { type: String, default: '' },
    },
    oauthIdentities: {
      type: [oauthIdentitySchema],
      default: [],
    },
    integrations: {
      vanguard: {
        trusted: { type: Boolean, default: false },
        staff: { type: Boolean, default: false },
        flagged: { type: Boolean, default: false },
        aiDenied: { type: Boolean, default: false },
        flagReason: { type: String, default: '', trim: true, maxlength: 240 },
        flaggedAt: { type: Date, default: null },
      },
    },
    preferences: {
      profilePublic: { type: Boolean, default: true },
      searchable: { type: Boolean, default: true },
      notifications: {
        email: { type: Boolean, default: true },
        sms: { type: Boolean, default: false },
        push: { type: Boolean, default: true },
        weeklyDigest: { type: Boolean, default: true },
        security: { type: Boolean, default: true },
      },
      appearance: {
        theme: {
          type: String,
          enum: ['system', 'graphite', 'midnight', 'alpine', 'heritage', 'dawn', 'night', 'ocean'],
          default: 'graphite',
        },
        compactMode: { type: Boolean, default: false },
        reducedMotion: { type: Boolean, default: false },
        highContrast: { type: Boolean, default: false },
        dashboardDensity: {
          type: String,
          enum: ['comfortable', 'compact', 'spacious'],
          default: 'comfortable',
        },
      },
      publicProfile: {
        headline: { type: Boolean, default: true },
        role: { type: Boolean, default: true },
        organization: { type: Boolean, default: true },
        bio: { type: Boolean, default: true },
        currentFocus: { type: Boolean, default: true },
        focusAreas: { type: Boolean, default: true },
        pronouns: { type: Boolean, default: false },
        location: { type: Boolean, default: true },
        website: { type: Boolean, default: true },
        timezone: { type: Boolean, default: false },
        language: { type: Boolean, default: false },
        linkedAccounts: { type: Boolean, default: false },
        memberSince: { type: Boolean, default: true },
      },
    },
    security: {
      loginAlerts: { type: Boolean, default: true },
      loginAlertLastSentAt: { type: Date, default: null },
      loginAlertLastDeviceFingerprint: { type: String, default: '', trim: true, maxlength: 128 },
      passwordChangedAt: { type: Date, default: null },
      mfa: {
        enabled: { type: Boolean, default: false },
        secret: { type: String, default: '' },
        backupCodes: {
          type: [String],
          default: [],
        },
        pendingSecret: { type: String, default: '' },
        pendingBackupCodes: {
          type: [String],
          default: [],
        },
        pendingCreatedAt: { type: Date, default: null },
        enrolledAt: { type: Date, default: null },
        lastUsedAt: { type: Date, default: null },
      },
      passkeys: {
        type: [passkeySchema],
        default: [],
      },
    },
  },
  {
    timestamps: true,
  }
);

userSchema.index({ 'security.passkeys.credentialId': 1 }, { unique: true, sparse: true });
userSchema.index(
  { 'oauthIdentities.provider': 1, 'oauthIdentities.providerUserId': 1 },
  { unique: true, sparse: true }
);
userSchema.index({ accountRole: 1, accountStatus: 1, updatedAt: -1 });

userSchema.pre('save', async function onSave(next) {
  if (!this.displayName && this.email) {
    const [localPart] = String(this.email).split('@');
    this.displayName = localPart || 'User';
  }

  if (!this.isModified('password')) {
    return next();
  }

  this.password = await bcrypt.hash(this.password, 10);
  this.security.passwordChangedAt = new Date();
  return next();
});

userSchema.methods.comparePassword = function comparePassword(candidate) {
  return bcrypt.compare(candidate, this.password);
};

module.exports = mongoose.model('User', userSchema);
