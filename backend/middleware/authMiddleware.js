const User = require('../models/User');
const {
  ACCESS_TOKEN_AUDIENCE,
  verifyTypedJwt,
} = require('../utils/tokenHardening');
const {
  isOwnerRole,
  isSuspendedAccount,
  normalizeAccountRole,
  normalizeAccountStatus,
} = require('../utils/accountAccess');

const buildAuthErrorPayload = (req, code, message) => ({
  authenticated: false,
  correlationId: String(req?.requestId || '').trim(),
  error: {
    code,
    correlationId: String(req?.requestId || '').trim(),
    message,
    retryable: false,
  },
  message,
  requestId: String(req?.requestId || '').trim(),
});

module.exports = async (req, res, next) => {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');

  if (scheme !== 'Bearer' || !token) {
    return res
      .status(401)
      .json(buildAuthErrorPayload(req, 'auth/access-token-missing', 'Authorization token required.'));
  }

  let decoded;
  try {
    decoded = verifyTypedJwt({
      token,
      secret: process.env.JWT_SECRET,
      audience: ACCESS_TOKEN_AUDIENCE,
      type: 'access_token',
      allowLegacy: true,
    });
  } catch (err) {
    return res
      .status(401)
      .json(buildAuthErrorPayload(req, 'auth/invalid-token', 'Token invalid or expired.'));
  }

  const userId = String(decoded?.userId || decoded?.sub || '').trim();
  if (!userId) {
    return res
      .status(401)
      .json(buildAuthErrorPayload(req, 'auth/invalid-token', 'Invalid token payload.'));
  }

  try {
    const user = await User.findById(userId).select(
      '_id refreshTokenVersion refreshSessions accountRole accountStatus'
    );
    if (!user) {
      return res
        .status(401)
        .json(buildAuthErrorPayload(req, 'auth/user-not-found', 'User not found for token.'));
    }

    if (isSuspendedAccount(user.accountStatus)) {
      return res
        .status(403)
        .json(buildAuthErrorPayload(req, 'auth/account-suspended', 'This account is suspended.'));
    }

    if (user.refreshTokenVersion !== decoded.tokenVersion) {
      return res
        .status(401)
        .json(buildAuthErrorPayload(req, 'auth/session-revoked', 'Session is no longer valid.'));
    }

    const sid = String(decoded.sid || '').trim();
    if (sid) {
      const hasActiveSession = Array.isArray(user.refreshSessions)
        ? user.refreshSessions.some((session) => String(session?.sid || '').trim() === sid)
        : false;

      if (!hasActiveSession) {
        return res
          .status(401)
          .json(buildAuthErrorPayload(req, 'auth/session-revoked', 'Session has been revoked.'));
      }
    }

    req.user = {
      id: String(user._id),
      tokenVersion: decoded.tokenVersion,
      sid: sid || null,
      accountRole: normalizeAccountRole(user.accountRole),
      accountStatus: normalizeAccountStatus(user.accountStatus),
      isOwner: isOwnerRole(user.accountRole),
    };

    return next();
  } catch (err) {
    return next(err);
  }
};
