const mongoose = require('mongoose');
const { logError } = require('../utils/safeLog');
const User = require('../models/User');
const {
  DISCORD_PROVIDER,
  sanitizeText,
  normalizeSnowflake,
  findDiscordOauthIdentity,
  getVanguardFlags,
  ensureVanguardState,
  buildVanguardResolvedUser,
} = require('../utils/vanguardIntegration');

const MAX_AUDIT_EVENTS = 120;
const VANGUARD_USER_SELECT =
  '_id __v email username displayName isVerified oauthIdentities integrations auditEvents createdAt updatedAt';

const appendVanguardAuditEvent = (user, req, type, message, meta = {}) => {
  const events = Array.isArray(user.auditEvents) ? user.auditEvents : [];
  events.push({
    at: new Date(),
    type,
    message: sanitizeText(message, 240),
    ip: sanitizeText(req.ip, 120),
    userAgent: sanitizeText(req.headers['user-agent'], 300),
    meta: {
      actor: 'vanguard-service',
      instanceId: sanitizeText(req.vanguardClient?.instanceId, 160),
      ...meta,
    },
  });
  user.auditEvents = events.slice(-MAX_AUDIT_EVENTS);
};

const findUserByDiscordUserId = async (discordUserId) =>
  User.findOne({
    oauthIdentities: {
      $elemMatch: {
        provider: DISCORD_PROVIDER,
        providerUserId: discordUserId,
      },
    },
  }).select(VANGUARD_USER_SELECT);

const resolveTargetUser = async (payload = {}) => {
  const continentalId = sanitizeText(
    payload.continentalUserId || payload.continentalId || payload.accountId,
    64
  );
  if (mongoose.Types.ObjectId.isValid(continentalId)) {
    return User.findById(continentalId).select(VANGUARD_USER_SELECT);
  }

  const discordUserId = normalizeSnowflake(
    payload.discordUserId || payload.userId || payload.targetUserId
  );
  if (discordUserId) {
    return findUserByDiscordUserId(discordUserId);
  }

  return null;
};

const serializeResolveResponse = (user, discordUserId = '') => ({
  linked: Boolean(user),
  discordUserId,
  user: user ? buildVanguardResolvedUser(user) : null,
  flags: user
    ? getVanguardFlags(user)
    : {
        trusted: false,
        staff: false,
        flagged: false,
        bannedFromAi: false,
        flagReason: '',
        flaggedAt: null,
      },
  oauth: user
    ? {
        provider: DISCORD_PROVIDER,
        linked: Boolean(findDiscordOauthIdentity(user)?.providerUserId),
      }
    : {
        provider: DISCORD_PROVIDER,
        linked: false,
      },
});

exports.health = async (req, res) => {
  const config = req.vanguardConfig;

  return res.json({
    service: 'vanguard-integration',
    status: 'ok',
    configured: true,
    authorized: config.licenseAuthorized,
    reason: config.licenseReason,
    allowedGuildIdsCount: config.allowedGuildIds.length,
    entitlements: config.entitlements,
    instanceId: sanitizeText(req.vanguardClient?.instanceId, 160),
    requestId: req.requestId,
  });
};

exports.verifyLicense = async (req, res) => {
  const config = req.vanguardConfig;
  const guildIds = Array.isArray(req.body?.guildIds)
    ? req.body.guildIds.map((value) => normalizeSnowflake(value)).filter(Boolean)
    : [];

  return res.json({
    authorized: config.licenseAuthorized,
    reason: config.licenseReason,
    allowedGuildIds: config.allowedGuildIds,
    entitlements: config.entitlements,
    instanceId: sanitizeText(req.vanguardClient?.instanceId, 160),
    botUserId: sanitizeText(req.body?.botUserId, 160),
    guildCount: Math.max(0, Math.round(Number(req.body?.guildCount) || guildIds.length || 0)),
    guildIds,
    requestId: req.requestId,
  });
};

exports.resolveUser = async (req, res) => {
  const discordUserId = normalizeSnowflake(
    req.body?.discordUserId || req.body?.userId || req.query?.discordUserId
  );
  const continentalId = sanitizeText(
    req.body?.continentalUserId || req.body?.continentalId || req.query?.continentalId,
    64
  );

  if (!discordUserId && !mongoose.Types.ObjectId.isValid(continentalId)) {
    return res.status(400).json({
      message: 'Provide a valid discordUserId or continentalId.',
      requestId: req.requestId,
    });
  }

  try {
    const user = await resolveTargetUser({
      discordUserId,
      continentalId,
    });

    return res.json({
      ...serializeResolveResponse(user, discordUserId),
      requestId: req.requestId,
    });
  } catch (err) {
    logError('Resolve Vanguard user error:', err);
    return res.status(500).json({
      message: 'Failed to resolve the Continental ID account.',
      requestId: req.requestId,
    });
  }
};

exports.flagUser = async (req, res) => {
  const reason = sanitizeText(req.body?.reason, 240);

  try {
    const user = await resolveTargetUser(req.body || {});
    if (!user) {
      return res.status(404).json({
        message: 'No Continental ID account is linked to that target.',
        requestId: req.requestId,
      });
    }

    const state = ensureVanguardState(user);
    state.flagged = true;
    state.flagReason = reason;
    state.flaggedAt = new Date();
    appendVanguardAuditEvent(user, req, 'vanguard_flagged', 'Flagged by Vanguard service.', {
      reason,
    });
    await user.save();

    return res.json({
      message: 'Continental ID account flagged for Vanguard review.',
      ...serializeResolveResponse(user, normalizeSnowflake(req.body?.discordUserId || req.body?.userId)),
      requestId: req.requestId,
    });
  } catch (err) {
    logError('Flag Vanguard user error:', err);
    return res.status(500).json({
      message: 'Failed to flag the Continental ID account.',
      requestId: req.requestId,
    });
  }
};

exports.unflagUser = async (req, res) => {
  try {
    const user = await resolveTargetUser(req.body || {});
    if (!user) {
      return res.status(404).json({
        message: 'No Continental ID account is linked to that target.',
        requestId: req.requestId,
      });
    }

    const state = ensureVanguardState(user);
    state.flagged = false;
    state.flagReason = '';
    state.flaggedAt = null;
    appendVanguardAuditEvent(user, req, 'vanguard_unflagged', 'Vanguard flag removed.', {});
    await user.save();

    return res.json({
      message: 'Continental ID account unflagged for Vanguard review.',
      ...serializeResolveResponse(user, normalizeSnowflake(req.body?.discordUserId || req.body?.userId)),
      requestId: req.requestId,
    });
  } catch (err) {
    logError('Unflag Vanguard user error:', err);
    return res.status(500).json({
      message: 'Failed to unflag the Continental ID account.',
      requestId: req.requestId,
    });
  }
};
