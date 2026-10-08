const User = require('../models/User');
const AuthApp = require('../models/AuthApp');
const { isSessionActive } = require('../utils/sessionPolicy');
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
    });
  } catch (err) {
    return res
      .status(401)
      .json(buildAuthErrorPayload(req, 'auth/invalid-token', 'Token invalid or expired.'));
  }

  const userId = String(decoded?.userId || decoded?.sub || '').trim();
  if (!/^[a-f0-9]{24}$/i.test(userId) || !decoded.sid || !Number.isInteger(decoded.tokenVersion)) {
    return res
      .status(401)
      .json(buildAuthErrorPayload(req, 'auth/invalid-token', 'Invalid token payload.'));
  }

  try {
    const user = await User.findById(userId).select(
      '_id refreshTokenVersion refreshSessions accountRole accountStatus isVerified security.mfa.enabled'
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

    if (!user.isVerified) {
      return res.status(403).json(buildAuthErrorPayload(req, 'auth/email-unverified', 'Email verification required.'));
    }

    if (user.refreshTokenVersion !== decoded.tokenVersion) {
      return res
        .status(401)
        .json(buildAuthErrorPayload(req, 'auth/session-revoked', 'Session is no longer valid.'));
    }

    const sid = String(decoded.sid || '').trim();
    if (sid) {
      const hasActiveSession = Array.isArray(user.refreshSessions)
        ? user.refreshSessions.some((session) => String(session?.sid || '').trim() === sid && isSessionActive(session))
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
      mfaEnabled: user.security?.mfa?.enabled === true,
      sessionCreatedAt: user.refreshSessions.find((session) => session.sid === sid)?.createdAt,
      targetOrigin: String(decoded.targetOrigin || ''),
      canManageIdentity: decoded.identityManagement === true &&
        user.refreshSessions.some((session) => session.sid === sid && session.identityManagement === true),
    };

    const baseUrl = req.baseUrl.toLowerCase();
    const endpoint = req.path.toLowerCase().replace(/\/+$/, '') || '/';
    if (baseUrl === '/api/auth' && endpoint !== '/me' && !req.user.canManageIdentity) {
      return res.status(403).json(buildAuthErrorPayload(req, 'auth/insufficient-scope', 'Use the Continental ID dashboard to manage this account.'));
    }

    if (baseUrl === '/api/grimoire' && !req.user.canManageIdentity && !(await AuthApp.exists({
      appId: 'grimoire', status: 'active', allowedOrigins: decoded.targetOrigin,
    }))) {
      return res.status(403).json(buildAuthErrorPayload(req, 'auth/insufficient-scope', 'Token is not authorized for Grimoire.'));
    }

    return next();
  } catch (err) {
    return next(err);
  }
};
