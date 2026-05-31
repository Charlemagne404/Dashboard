const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} = require('@simplewebauthn/server');
const { isoBase64URL, isoUint8Array } = require('@simplewebauthn/server/helpers');
const ApiRateLimitBucket = require('../models/ApiRateLimitBucket');
const LoginThrottle = require('../models/LoginThrottle');
const User = require('../models/User');
const sendEmail = require('../utils/email');
const { createEmailVerificationToken } = require('../utils/emailVerification');
const {
  buildOtpAuthQrDataUrl,
  buildOtpAuthUrl,
  generateBackupCodes,
  generateMfaSecret,
  verifyTotp,
} = require('../utils/mfa');
const {
  decryptMfaSecret,
  encryptMfaSecret,
  hashBackupCodeForStorage,
  normalizeUserSecurityState,
  verifyStoredBackupCodeHash,
} = require('../utils/securityHardening');
const {
  ACCESS_TOKEN_AUDIENCE,
  DEVICE_COOKIE_AUDIENCE,
  OAUTH_STATE_AUDIENCE,
  REFRESH_TOKEN_AUDIENCE,
  WEBAUTHN_CHALLENGE_AUDIENCE,
  signTypedJwt,
  verifyTypedJwt,
} = require('../utils/tokenHardening');
const {
  DISPLAY_NAME_MODERATION_MESSAGE,
  USERNAME_VALIDATION_MESSAGE,
  USERNAME_MODERATION_MESSAGE,
  containsBlockedNameTerm,
  ensureStoredUsername,
  ensureUserIdentityFields,
  getDisplayableUsername,
  isValidUsername,
  normalizeUsername,
} = require('../utils/userIdentity');
const { buildVanguardAccountState } = require('../utils/vanguardIntegration');
const {
  ACCOUNT_ROLE_OWNER,
  ACCOUNT_ROLE_USER,
  ACCOUNT_STATUS_ACTIVE,
  ACCOUNT_STATUS_SUSPENDED,
  buildAuthorityPayload,
  isOwnerRole,
  isSuspendedAccount,
  normalizeAccountRole,
  normalizeAccountStatus,
  shouldAutoGrantOwnerRole,
} = require('../utils/accountAccess');

const ACCESS_TOKEN_TTL = process.env.JWT_EXPIRES_IN || '15m';
const REFRESH_TOKEN_TTL = process.env.REFRESH_TOKEN_EXPIRES_IN || '7d';

const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_RECENT_LOGIN_EVENTS = 50;
const RECENT_LOGIN_RESPONSE_LIMIT = 20;
const MAX_ACTIVE_SESSIONS = 12;
const LOGIN_RATE_WINDOW_MS = Number(process.env.LOGIN_RATE_WINDOW_MS) || 10 * 60 * 1000;
const LOGIN_RATE_MAX_ATTEMPTS = Number(process.env.LOGIN_RATE_MAX_ATTEMPTS) || 8;
const LOGIN_BLOCK_MS = Number(process.env.LOGIN_BLOCK_MS) || 15 * 60 * 1000;
const PASSWORD_RESET_RATE_WINDOW_MS =
  Number(process.env.PASSWORD_RESET_RATE_WINDOW_MS) || 15 * 60 * 1000;
const PASSWORD_RESET_RATE_MAX_ATTEMPTS =
  Number(process.env.PASSWORD_RESET_RATE_MAX_ATTEMPTS) || 4;
const PASSWORD_RESET_BLOCK_MS =
  Number(process.env.PASSWORD_RESET_BLOCK_MS) || 60 * 60 * 1000;
const VERIFICATION_RESEND_RATE_WINDOW_MS =
  Number(process.env.VERIFICATION_RESEND_RATE_WINDOW_MS) || 15 * 60 * 1000;
const VERIFICATION_RESEND_RATE_MAX_ATTEMPTS =
  Number(process.env.VERIFICATION_RESEND_RATE_MAX_ATTEMPTS) || 4;
const VERIFICATION_RESEND_BLOCK_MS =
  Number(process.env.VERIFICATION_RESEND_BLOCK_MS) || 60 * 60 * 1000;
const MFA_RATE_WINDOW_MS = Number(process.env.MFA_RATE_WINDOW_MS) || 10 * 60 * 1000;
const MFA_RATE_MAX_ATTEMPTS = Number(process.env.MFA_RATE_MAX_ATTEMPTS) || 5;
const MFA_BLOCK_MS = Number(process.env.MFA_BLOCK_MS) || 15 * 60 * 1000;
const REFRESH_TOKEN_REPLAY_GRACE_MS =
  Number(process.env.REFRESH_TOKEN_REPLAY_GRACE_MS) || 15_000;
const LOGIN_ACTIVITY_RETENTION_DAYS = 45;
const MAX_AUDIT_EVENTS = 120;
const MAX_KNOWN_DEVICES = 24;
const PASSWORD_RESET_TTL_MS = Number(process.env.PASSWORD_RESET_TTL_MS) || 60 * 60 * 1000;
const PASSWORD_RESET_EMAIL_COOLDOWN_MS =
  Number(process.env.PASSWORD_RESET_EMAIL_COOLDOWN_MS) || 10 * 60 * 1000;
const VERIFICATION_EMAIL_COOLDOWN_MS =
  Number(process.env.VERIFICATION_EMAIL_COOLDOWN_MS) || 30 * 60 * 1000;
const LOGIN_ALERT_EMAIL_COOLDOWN_MS =
  Number(process.env.LOGIN_ALERT_EMAIL_COOLDOWN_MS) || 12 * 60 * 60 * 1000;
const RETURNING_ACCOUNT_INACTIVE_DAYS =
  Number(process.env.RETURNING_ACCOUNT_INACTIVE_DAYS) || 120;
const RETURNING_ACCOUNT_PASSWORD_REVIEW_DAYS =
  Number(process.env.RETURNING_ACCOUNT_PASSWORD_REVIEW_DAYS) || 180;
const EMAIL_DAILY_LIMIT = Number(process.env.EMAIL_DAILY_LIMIT) || 100;
const EMAIL_MONTHLY_LIMIT = Number(process.env.EMAIL_MONTHLY_LIMIT) || 3000;
const NEW_DEVICE_SESSION_WINDOW_MS = 15 * 60 * 1000;
const MAX_PASSKEYS = 20;
const DEVICE_ID_COOKIE = 'deviceId';
const WEBAUTHN_CHALLENGE_COOKIE = 'webauthnChallenge';
const DEVICE_ID_TTL_MS = Number(process.env.DEVICE_ID_TTL_MS) || 365 * DAY_MS;
const WEBAUTHN_CHALLENGE_TTL_MS = 10 * 60 * 1000;
const WEBAUTHN_RP_NAME = process.env.WEBAUTHN_RP_NAME || 'Continental ID';
const WEBAUTHN_DEFAULT_RP_ID = process.env.WEBAUTHN_RP_ID || 'continental-hub.com';
const WEBAUTHN_CONTINENTAL_HOST_SUFFIX = '.continental-hub.com';
const OAUTH_STATE_TTL_SEC = 10 * 60;
const OAUTH_PROVIDER_GITHUB = 'github';
const OAUTH_PROVIDER_GOOGLE = 'google';
const OAUTH_PROVIDER_DISCORD = 'discord';
const OAUTH_PROVIDER_MICROSOFT = 'microsoft';
const OAUTH_PROVIDERS = [
  OAUTH_PROVIDER_GITHUB,
  OAUTH_PROVIDER_GOOGLE,
  OAUTH_PROVIDER_DISCORD,
  OAUTH_PROVIDER_MICROSOFT,
];

const LINKED_PROVIDERS = [
  'google',
  'facebook',
  'github',
  'twitter',
  'linkedin',
  'discord',
  'apple',
  'microsoft',
];

const ALLOWED_THEMES = new Set(['system', 'graphite', 'midnight', 'alpine', 'heritage', 'dawn', 'night', 'ocean']);
const ALLOWED_DENSITIES = new Set(['comfortable', 'compact', 'spacious']);

const DEFAULT_NOTIFICATIONS = {
  email: true,
  sms: false,
  push: true,
  weeklyDigest: true,
  security: true,
};

const DEFAULT_APPEARANCE = {
  theme: 'graphite',
  compactMode: false,
  reducedMotion: false,
  highContrast: false,
  dashboardDensity: 'comfortable',
};
const DEFAULT_PUBLIC_PROFILE = {
  headline: true,
  role: true,
  organization: true,
  bio: true,
  currentFocus: true,
  focusAreas: true,
  pronouns: false,
  location: true,
  website: true,
  timezone: false,
  language: false,
  linkedAccounts: false,
  memberSince: true,
};

const DEFAULT_DASHBOARD_ORIGIN = 'https://dashboard.continental-hub.com';
const DEFAULT_LOGIN_ORIGIN = 'https://login.continental-hub.com';
const DEFAULT_VANGUARD_ORIGIN = 'https://vanguard.continental-hub.com';
const DEFAULT_OAUTH_APP_ORIGINS = [
  'https://blueprint.continental-hub.com',
  DEFAULT_DASHBOARD_ORIGIN,
  DEFAULT_LOGIN_ORIGIN,
  'https://pulse.continental-hub.com',
  DEFAULT_VANGUARD_ORIGIN,
  'https://charlemagne404.github.io',
  'https://grimoire.continental-hub.com',
  'https://stepcast.continental-hub.com',
  'https://mpmc.ddns.net',
];
const configuredOauthAppOrigins = Array.from(
  new Set(
    [
      ...String(process.env.OAUTH_APP_ORIGINS || '').split(','),
      ...String(process.env.ALLOWED_ORIGINS || '').split(','),
    ]
      .map((value) => value.trim())
      .filter(Boolean)
  )
);
const allowDefaultOauthAppOrigins =
  String(process.env.ALLOW_DEFAULT_TRUSTED_ORIGINS || 'true') !== 'false';
const OAUTH_APP_ORIGINS = new Set([
  ...(allowDefaultOauthAppOrigins ? DEFAULT_OAUTH_APP_ORIGINS : []),
  ...configuredOauthAppOrigins,
]);
const DEFAULT_LOGIN_POPUP_URL = `${DEFAULT_LOGIN_ORIGIN}/popup.html`;
const DEFAULT_EMAIL_VERIFY_PATH = '/verify.html';
const DEFAULT_PASSWORD_RESET_PATH = '/reset-password.html';
const AUTH_RESULT_MARKER_KEY = 'continentalAuth';
const AUTH_POPUP_MESSAGE_SOURCE = 'continental-id';
const AUTH_POPUP_MESSAGE_TYPE = 'auth-result';
const AUTH_ERROR_CODE = {
  accessTokenMissing: 'auth/access-token-missing',
  authorizationDenied: 'auth/authorization-denied',
  emailUnverified: 'auth/email-unverified',
  identityConflict: 'auth/identity-conflict',
  invalidCredentials: 'auth/invalid-credentials',
  invalidRefreshSession: 'auth/invalid-refresh-session',
  invalidToken: 'auth/invalid-token',
  mfaBlocked: 'auth/mfa-blocked',
  mfaRequired: 'auth/mfa-required',
  originRejected: 'auth/origin-rejected',
  popupMessageRejected: 'auth/popup-message-rejected',
  refreshSessionMissing: 'auth/refresh-session-missing',
  registrationFailed: 'auth/registration-failed',
  sessionRevoked: 'auth/session-revoked',
  suspended: 'auth/account-suspended',
  unavailable: 'auth/unavailable',
  userNotFound: 'auth/user-not-found',
} ;
const EMAIL_VERIFICATION_SUBJECT = 'Verify your Continental ID email';
const PASSWORD_RESET_SUBJECT = 'Reset your Continental ID password';
const AVATAR_DATA_URL_MAX_LENGTH = 350000;
const AVATAR_DATA_URL_PATTERN = /^data:image\/(?:png|jpe?g|gif|webp);base64,[a-z0-9+/=]+$/i;
const MFA_BACKUP_CODE_COUNT = 8;
const MAX_FOCUS_AREAS = 8;
const OWNER_USER_LIST_LIMIT = 100;

const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj || {}, key);

const toObjectIdString = (value) => String(value || '');
const normalizeEmail = (email) => String(email || '').trim().toLowerCase();
const normalizeLoginIdentifier = (value) => String(value || '').trim().toLowerCase();
const sanitizeText = (value, maxLength = 120) => String(value || '').trim().slice(0, maxLength);
const hashToken = (value) => crypto.createHash('sha256').update(String(value || '')).digest('hex');

const isValidEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

const sanitizeDisplayName = (displayName, email = '') => {
  const cleaned = sanitizeText(displayName, 60);
  if (cleaned.length >= 2 && !containsBlockedNameTerm(cleaned)) return cleaned;

  const fallback = sanitizeText(String(email).split('@')[0], 60);
  if (fallback && !containsBlockedNameTerm(fallback)) return fallback;

  return 'User';
};

const isStrongPassword = (password) => {
  if (typeof password !== 'string') return false;
  if (password.length < 8) return false;

  const hasUppercase = /[A-Z]/.test(password);
  const hasLowercase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);

  return hasUppercase && hasLowercase && hasNumber;
};

const parseClientIp = (req) => {
  return sanitizeText(req.ip || req.socket?.remoteAddress || 'unknown', 80);
};

const parseUserAgent = (req) => sanitizeText(req.headers['user-agent'] || 'Unknown browser/device', 300);

const buildLoginThrottleExpiry = (now = Date.now()) =>
  new Date(now + Math.max(LOGIN_RATE_WINDOW_MS, LOGIN_BLOCK_MS) + 60_000);

const isDuplicateKeyError = (err) => err?.code === 11000;
const getDuplicateFieldName = (err) =>
  Object.keys(err?.keyPattern || err?.keyValue || {}).find(Boolean) || '';
const getDuplicateUserFieldMessage = (err) => {
  const field = getDuplicateFieldName(err);
  if (field === 'username') return 'Username is already in use.';
  if (field === 'email') return 'Email is already in use.';
  return 'That account identity is already in use.';
};
const createHttpError = (statusCode, message) => {
  const error = new Error(message);
  error.statusCode = statusCode;
  return error;
};
const sanitizeOwnerStatusReason = (value, fallback = '') => sanitizeText(value, 240) || fallback;
const normalizeOwnerUserListLimit = (value) =>
  Math.max(1, Math.min(OWNER_USER_LIST_LIMIT, Math.trunc(Number(value) || 25)));
const normalizeOwnerSearchQuery = (value) => sanitizeText(value, 80);
const normalizeOwnerUserId = (value) => sanitizeText(value, 120);

const buildActivityDay = (value = new Date()) => {
  const date = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toISOString().slice(0, 10);
};

const parseActivityDayStart = (value) => {
  const day = String(value || '').trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(day)) return Number.NaN;
  return Date.parse(`${day}T00:00:00.000Z`);
};

const escapeRegex = (value) => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const getRequestOrigin = (req) => {
  const forwardedProto = sanitizeText(
    String(req.headers['x-forwarded-proto'] || '').split(',')[0],
    20
  ).toLowerCase();
  const browserOrigin = extractBrowserOrigin(req);
  let protocol = forwardedProto || (req.secure ? 'https' : '');

  if (!protocol && browserOrigin) {
    try {
      protocol = new URL(browserOrigin).protocol.replace(':', '').toLowerCase();
    } catch {
      protocol = '';
    }
  }

  if (!protocol) {
    protocol = 'http';
  }

  const host = sanitizeText(req.headers['x-forwarded-host'] || req.headers.host, 200);

  if (!host) return '';

  try {
    return new URL(`${protocol}://${host}`).origin;
  } catch {
    return '';
  }
};

const isLocalHostname = (hostname) => hostname === 'localhost' || hostname === '127.0.0.1';

const isContinentalHostname = (hostname) =>
  hostname === 'continental-hub.com' || hostname.endsWith('.continental-hub.com');

const isSameSiteRequest = (req) => {
  const requestOrigin = getRequestOrigin(req);
  const browserOrigin = extractBrowserOrigin(req);
  if (!requestOrigin || !browserOrigin) {
    return true;
  }

  try {
    const requestUrl = new URL(requestOrigin);
    const browserUrl = new URL(browserOrigin);

    if (requestUrl.origin === browserUrl.origin) {
      return true;
    }

    if (isLocalHostname(requestUrl.hostname) && isLocalHostname(browserUrl.hostname)) {
      return true;
    }

    if (isContinentalHostname(requestUrl.hostname) && isContinentalHostname(browserUrl.hostname)) {
      return requestUrl.protocol === browserUrl.protocol;
    }
  } catch {
    return true;
  }

  return false;
};

const resolveAbsoluteUrl = (value) => {
  const raw = sanitizeText(value, 2000);
  if (!raw) return '';

  try {
    return new URL(raw).toString();
  } catch {
    return '';
  }
};

const normalizeOrigin = (value) => String(value || '').trim().replace(/\/+$/, '');

const extractBrowserOrigin = (req) => {
  const headerOrigin = normalizeOrigin(req.headers.origin);
  if (headerOrigin) return headerOrigin;

  const referer = String(req.headers.referer || '').trim();
  if (!referer) return '';

  try {
    return normalizeOrigin(new URL(referer).origin);
  } catch {
    return '';
  }
};

const resolveWebAuthnRpId = (origin) => {
  const explicitRpId = sanitizeText(process.env.WEBAUTHN_RP_ID, 255);
  if (explicitRpId) {
    return explicitRpId.toLowerCase();
  }

  try {
    const hostname = new URL(origin).hostname.toLowerCase();
    if (!hostname) return '';
    if (hostname === 'localhost' || hostname === '127.0.0.1') return hostname;
    if (
      hostname === WEBAUTHN_DEFAULT_RP_ID ||
      hostname.endsWith(WEBAUTHN_CONTINENTAL_HOST_SUFFIX)
    ) {
      return WEBAUTHN_DEFAULT_RP_ID;
    }
    return hostname;
  } catch {
    return '';
  }
};

const resolveWebAuthnContext = (req) => {
  const origin = extractBrowserOrigin(req);
  const rpID = resolveWebAuthnRpId(origin);
  if (!origin || !rpID) {
    throw createHttpError(400, 'A trusted browser origin is required for passkeys.');
  }

  return { origin, rpID };
};

const isHostedLoginOrigin = (value) => {
  const resolved = resolveAbsoluteUrl(value);
  if (!resolved) return false;

  try {
    const origin = new URL(resolved).origin;
    return origin === DEFAULT_DASHBOARD_ORIGIN || origin === DEFAULT_LOGIN_ORIGIN;
  } catch {
    return false;
  }
};

const resolveLoginPopupPageUrl = (req) => {
  const explicitLoginPopupUrl = resolveAbsoluteUrl(
    process.env.LOGIN_POPUP_URL || process.env.PUBLIC_LOGIN_POPUP_URL || process.env.PUBLIC_LOGIN_URL
  );
  if (explicitLoginPopupUrl) {
    return explicitLoginPopupUrl;
  }

  const appBaseUrl = resolveAbsoluteUrl(
    process.env.APP_BASE_URL || process.env.PUBLIC_APP_URL || process.env.PUBLIC_BASE_URL
  );
  if (isHostedLoginOrigin(appBaseUrl)) {
    return DEFAULT_LOGIN_POPUP_URL;
  }

  if ((process.env.NODE_ENV || 'development') !== 'production') {
    const requestOrigin = getRequestOrigin(req);
    if (isHostedLoginOrigin(requestOrigin)) {
      return DEFAULT_LOGIN_POPUP_URL;
    }
  }

  return '';
};

const getUtcDayWindowStart = (value = Date.now()) => {
  const date = new Date(value);
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
};

const getUtcMonthWindowStart = (value = Date.now()) => {
  const date = new Date(value);
  return new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), 1));
};

const addUtcDays = (value, days) => {
  const date = new Date(value);
  date.setUTCDate(date.getUTCDate() + days);
  return date;
};

const addUtcMonths = (value, months) => {
  const date = new Date(value);
  date.setUTCMonth(date.getUTCMonth() + months);
  return date;
};

const escapeHtml = (value) =>
  String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const resolveEmailVerificationPageUrl = (req) => {
  const explicitVerifyUrl = resolveAbsoluteUrl(process.env.EMAIL_VERIFY_URL);
  if (explicitVerifyUrl) {
    return explicitVerifyUrl;
  }

  const loginPopupUrl = resolveLoginPopupPageUrl(req);
  if (loginPopupUrl) {
    return new URL('verify.html', loginPopupUrl).toString();
  }

  const appBaseUrl = resolveAbsoluteUrl(
    process.env.APP_BASE_URL || process.env.PUBLIC_APP_URL || process.env.PUBLIC_BASE_URL
  );
  if (appBaseUrl) {
    return new URL(DEFAULT_EMAIL_VERIFY_PATH, appBaseUrl).toString();
  }

  if ((process.env.NODE_ENV || 'development') !== 'production') {
    const requestOrigin = getRequestOrigin(req);
    if (requestOrigin) {
      return new URL(DEFAULT_EMAIL_VERIFY_PATH, requestOrigin).toString();
    }
  }

  return '';
};

const buildEmailVerificationUrl = (req, token) => {
  const baseUrl = resolveEmailVerificationPageUrl(req);
  if (!baseUrl || !token) return '';

  const url = new URL(baseUrl);
  url.searchParams.set('token', token);
  return url.toString();
};

const isTrustedOauthAppOrigin = (origin) => {
  if (!origin) return false;

  try {
    const parsed = new URL(origin);
    if (isLocalHostname(parsed.hostname)) return true;
    return OAUTH_APP_ORIGINS.has(parsed.origin);
  } catch {
    return false;
  }
};

const getDefaultTrustedOauthAppOrigin = () => {
  if (isTrustedOauthAppOrigin(DEFAULT_DASHBOARD_ORIGIN)) {
    return DEFAULT_DASHBOARD_ORIGIN;
  }

  const firstTrustedOrigin = Array.from(OAUTH_APP_ORIGINS).find((origin) => isTrustedOauthAppOrigin(origin));
  return firstTrustedOrigin || '';
};

const resolveTrustedOauthAppOrigin = (value, fallback = DEFAULT_DASHBOARD_ORIGIN) => {
  const origin = normalizeOrigin(value);
  if (isTrustedOauthAppOrigin(origin)) {
    return origin;
  }

  const normalizedFallback = normalizeOrigin(fallback);
  if (isTrustedOauthAppOrigin(normalizedFallback)) {
    return normalizedFallback;
  }

  return getDefaultTrustedOauthAppOrigin();
};

const resolveTrustedOauthRedirectUrl = (value, fallbackOrigin = DEFAULT_DASHBOARD_ORIGIN) => {
  const safeOrigin = resolveTrustedOauthAppOrigin(
    fallbackOrigin,
    getDefaultTrustedOauthAppOrigin() || DEFAULT_DASHBOARD_ORIGIN
  );
  if (!safeOrigin) {
    return '';
  }

  try {
    const resolved = new URL(String(value || '/'), safeOrigin);
    if (!isTrustedOauthAppOrigin(resolved.origin)) {
      return new URL('/', safeOrigin).toString();
    }
    return resolved.toString();
  } catch {
    return new URL('/', safeOrigin).toString();
  }
};

const buildAuthResultMessagePayload = (
  req,
  {
    accessToken = '',
    apiBaseUrl = '',
    code = '',
    event = 'login_success',
    message = '',
    provider = '',
    user = null,
  } = {}
) => {
  const normalizedEvent = sanitizeText(event, 80) || 'login_success';
  const token = sanitizeText(accessToken, 4000);
  const correlationId = sanitizeText(req?.requestId, 120);
  const messagePayload = {
    source: AUTH_POPUP_MESSAGE_SOURCE,
    type: AUTH_POPUP_MESSAGE_TYPE,
    event: normalizedEvent,
    correlationId,
  };

  const normalizedCode = sanitizeText(code, 120);
  const normalizedMessage = sanitizeText(message, 400);
  const normalizedProvider = sanitizeText(provider, 80).toLowerCase();
  const normalizedApiBaseUrl = sanitizeText(apiBaseUrl, 2000);

  if (normalizedCode) messagePayload.code = normalizedCode;
  if (normalizedMessage) messagePayload.message = normalizedMessage;
  if (normalizedProvider) messagePayload.provider = normalizedProvider;
  if (normalizedApiBaseUrl) messagePayload.apiBaseUrl = normalizedApiBaseUrl;

  if (normalizedEvent === 'login_success') {
    messagePayload.legacyType = 'LOGIN_SUCCESS';
    if (token) {
      messagePayload.accessToken = token;
      messagePayload.token = token;
    }
    if (user) {
      messagePayload.user = user;
    }
  } else if (normalizedEvent === 'oauth_linked') {
    messagePayload.legacyType = 'OAUTH_LINKED';
  } else if (normalizedEvent === 'login_error') {
    messagePayload.legacyType = 'LOGIN_ERROR';
    if (normalizedMessage) {
      messagePayload.error = normalizedMessage;
    }
  }

  return messagePayload;
};

const appendAuthPayloadToRedirectUrl = (redirectUrl, messagePayload) => {
  const token = sanitizeText(messagePayload?.accessToken || messagePayload?.token, 4000);
  const apiBaseUrl = sanitizeText(messagePayload?.apiBaseUrl, 2000);
  const authEvent =
    sanitizeText(messagePayload?.event, 120) ||
    (sanitizeText(messagePayload?.type, 120) === 'LOGIN_SUCCESS'
      ? 'login_success'
      : sanitizeText(messagePayload?.type, 120) === 'LOGIN_ERROR'
        ? 'login_error'
        : sanitizeText(messagePayload?.type, 120) === 'OAUTH_LINKED'
          ? 'oauth_linked'
          : '');
  const code = sanitizeText(messagePayload?.code, 120);
  const message = sanitizeText(messagePayload?.message || messagePayload?.error, 400);
  const correlationId = sanitizeText(messagePayload?.correlationId, 120);
  const provider = sanitizeText(messagePayload?.provider, 80).toLowerCase();

  if (!authEvent || (!token && !apiBaseUrl && !code && !message)) {
    return redirectUrl;
  }

  try {
    const resolved = new URL(String(redirectUrl || DEFAULT_DASHBOARD_ORIGIN));
    const hashParams = new URLSearchParams(resolved.hash.replace(/^#/, ''));

    hashParams.set(AUTH_RESULT_MARKER_KEY, '1');
    hashParams.set('authEvent', authEvent);
    if (token) {
      hashParams.set('accessToken', token);
      hashParams.set('token', token);
    }
    if (apiBaseUrl) {
      hashParams.set('apiBaseUrl', apiBaseUrl);
    }
    if (code) {
      hashParams.set('authCode', code);
    }
    if (message) {
      hashParams.set('authMessage', message);
    }
    if (correlationId) {
      hashParams.set('correlationId', correlationId);
    }
    if (provider) {
      hashParams.set('provider', provider);
    }

    resolved.hash = hashParams.toString();
    return resolved.toString();
  } catch {
    return redirectUrl;
  }
};

const buildOauthStateToken = (payload) =>
  signTypedJwt({
    secret: process.env.JWT_SECRET,
    payload,
    expiresIn: OAUTH_STATE_TTL_SEC,
    audience: OAUTH_STATE_AUDIENCE,
    type: 'oauth_state',
  });

const readOauthStateToken = (state) => {
  const token = sanitizeText(state, 4000);
  if (!token) {
    throw createHttpError(400, 'OAuth state is missing or invalid.');
  }

  try {
    return verifyTypedJwt({
      token,
      secret: process.env.JWT_SECRET,
      audience: OAUTH_STATE_AUDIENCE,
      type: 'oauth_state',
    });
  } catch {
    throw createHttpError(400, 'OAuth state is missing or invalid.');
  }
};

const getOauthProviderLabel = (provider) => {
  const normalized = sanitizeText(provider, 40).toLowerCase();
  if (normalized === OAUTH_PROVIDER_GITHUB) return 'GitHub';
  if (normalized === OAUTH_PROVIDER_GOOGLE) return 'Google';
  if (normalized === OAUTH_PROVIDER_DISCORD) return 'Discord';
  if (normalized === OAUTH_PROVIDER_MICROSOFT) return 'Microsoft';
  return 'OAuth provider';
};

const resolveOauthCallbackUrl = (provider, req) => {
  const normalized = sanitizeText(provider, 40).toLowerCase();
  const envKeyMap = {
    [OAUTH_PROVIDER_GITHUB]: 'GITHUB_OAUTH_CALLBACK_URL',
    [OAUTH_PROVIDER_GOOGLE]: 'GOOGLE_OAUTH_CALLBACK_URL',
    [OAUTH_PROVIDER_DISCORD]: 'DISCORD_OAUTH_CALLBACK_URL',
    [OAUTH_PROVIDER_MICROSOFT]: 'MICROSOFT_OAUTH_CALLBACK_URL',
  };
  const explicit = resolveAbsoluteUrl(process.env[envKeyMap[normalized]]);
  if (explicit) return explicit;

  const requestOrigin = getRequestOrigin(req);
  if (!requestOrigin) {
    throw createHttpError(
      500,
      `${getOauthProviderLabel(normalized)} OAuth callback URL is not configured.`
    );
  }

  return new URL(`/api/auth/oauth/${normalized}/callback`, requestOrigin).toString();
};

const getGithubOauthConfig = (req) => {
  const clientId = sanitizeText(process.env.GITHUB_CLIENT_ID, 200);
  const clientSecret = sanitizeText(process.env.GITHUB_CLIENT_SECRET, 400);
  if (!clientId || !clientSecret) {
    throw createHttpError(503, 'GitHub sign-in is not configured on this server.');
  }

  return {
    provider: OAUTH_PROVIDER_GITHUB,
    label: getOauthProviderLabel(OAUTH_PROVIDER_GITHUB),
    clientId,
    clientSecret,
    callbackUrl: resolveOauthCallbackUrl(OAUTH_PROVIDER_GITHUB, req),
    authorizeUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    scopes: ['read:user', 'user:email'],
    authorizeParams: {
      allow_signup: 'true',
    },
    tokenRequestFormat: 'form',
    profileStrategy: 'github',
  };
};

const getGoogleOauthConfig = (req) => {
  const clientId = sanitizeText(process.env.GOOGLE_CLIENT_ID, 200);
  const clientSecret = sanitizeText(process.env.GOOGLE_CLIENT_SECRET, 400);
  if (!clientId || !clientSecret) {
    throw createHttpError(503, 'Google sign-in is not configured on this server.');
  }

  return {
    provider: OAUTH_PROVIDER_GOOGLE,
    label: getOauthProviderLabel(OAUTH_PROVIDER_GOOGLE),
    clientId,
    clientSecret,
    callbackUrl: resolveOauthCallbackUrl(OAUTH_PROVIDER_GOOGLE, req),
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    userInfoUrl: 'https://openidconnect.googleapis.com/v1/userinfo',
    scopes: ['openid', 'email', 'profile'],
    authorizeParams: {
      prompt: 'select_account',
    },
    tokenRequestFormat: 'form',
    requireAuthorizationCodeGrant: true,
    profileStrategy: 'oidc',
    trustEmailWithoutExplicitVerification: false,
  };
};

const getDiscordOauthConfig = (req) => {
  const clientId = sanitizeText(process.env.DISCORD_CLIENT_ID, 200);
  const clientSecret = sanitizeText(process.env.DISCORD_CLIENT_SECRET, 400);
  if (!clientId || !clientSecret) {
    throw createHttpError(503, 'Discord sign-in is not configured on this server.');
  }

  return {
    provider: OAUTH_PROVIDER_DISCORD,
    label: getOauthProviderLabel(OAUTH_PROVIDER_DISCORD),
    clientId,
    clientSecret,
    callbackUrl: resolveOauthCallbackUrl(OAUTH_PROVIDER_DISCORD, req),
    authorizeUrl: 'https://discord.com/oauth2/authorize',
    tokenUrl: 'https://discord.com/api/oauth2/token',
    userInfoUrl: 'https://discord.com/api/users/@me',
    scopes: ['identify', 'email'],
    tokenRequestFormat: 'form',
    requireAuthorizationCodeGrant: true,
    profileStrategy: 'discord',
  };
};

const getMicrosoftOauthConfig = (req) => {
  const clientId = sanitizeText(process.env.MICROSOFT_CLIENT_ID || process.env.AZURE_CLIENT_ID, 200);
  const clientSecret = sanitizeText(
    process.env.MICROSOFT_CLIENT_SECRET || process.env.AZURE_CLIENT_SECRET,
    400
  );
  const tenant =
    sanitizeText(process.env.MICROSOFT_TENANT_ID || process.env.AZURE_TENANT_ID, 120) ||
    'common';
  if (!clientId || !clientSecret) {
    throw createHttpError(503, 'Microsoft sign-in is not configured on this server.');
  }

  return {
    provider: OAUTH_PROVIDER_MICROSOFT,
    label: getOauthProviderLabel(OAUTH_PROVIDER_MICROSOFT),
    clientId,
    clientSecret,
    callbackUrl: resolveOauthCallbackUrl(OAUTH_PROVIDER_MICROSOFT, req),
    authorizeUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
    tokenUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
    userInfoUrl: 'https://graph.microsoft.com/oidc/userinfo',
    scopes: ['openid', 'email', 'profile'],
    authorizeParams: {
      prompt: 'select_account',
    },
    tokenRequestFormat: 'form',
    requireAuthorizationCodeGrant: true,
    profileStrategy: 'oidc',
    trustEmailWithoutExplicitVerification: true,
  };
};

const getOauthProviderConfig = (provider, req) => {
  const normalized = sanitizeText(provider, 40).toLowerCase();
  if (normalized === OAUTH_PROVIDER_GITHUB) {
    return getGithubOauthConfig(req);
  }
  if (normalized === OAUTH_PROVIDER_GOOGLE) {
    return getGoogleOauthConfig(req);
  }
  if (normalized === OAUTH_PROVIDER_DISCORD) {
    return getDiscordOauthConfig(req);
  }
  if (normalized === OAUTH_PROVIDER_MICROSOFT) {
    return getMicrosoftOauthConfig(req);
  }

  throw createHttpError(404, 'That identity provider is not supported yet.');
};

const isOauthProviderAvailable = (provider) => {
  const normalized = sanitizeText(provider, 40).toLowerCase();
  if (normalized === OAUTH_PROVIDER_GITHUB) {
    return Boolean(
      sanitizeText(process.env.GITHUB_CLIENT_ID, 200) &&
        sanitizeText(process.env.GITHUB_CLIENT_SECRET, 400)
    );
  }
  if (normalized === OAUTH_PROVIDER_GOOGLE) {
    return Boolean(
      sanitizeText(process.env.GOOGLE_CLIENT_ID, 200) &&
        sanitizeText(process.env.GOOGLE_CLIENT_SECRET, 400)
    );
  }
  if (normalized === OAUTH_PROVIDER_DISCORD) {
    return Boolean(
      sanitizeText(process.env.DISCORD_CLIENT_ID, 200) &&
        sanitizeText(process.env.DISCORD_CLIENT_SECRET, 400)
    );
  }
  if (normalized === OAUTH_PROVIDER_MICROSOFT) {
    return Boolean(
      sanitizeText(process.env.MICROSOFT_CLIENT_ID || process.env.AZURE_CLIENT_ID, 200) &&
        sanitizeText(process.env.MICROSOFT_CLIENT_SECRET || process.env.AZURE_CLIENT_SECRET, 400)
    );
  }

  return false;
};

const serializeOauthIdentity = (identity = {}, providerConfig = null) => ({
  provider: sanitizeText(identity?.provider || providerConfig?.provider, 40).toLowerCase(),
  linked: Boolean(identity?.provider && identity?.providerUserId),
  providerUserId: sanitizeText(identity?.providerUserId, 160),
  username: sanitizeText(identity?.username, 120),
  email: sanitizeText(identity?.email, 320).toLowerCase(),
  emailVerified: Boolean(identity?.emailVerified),
  profileUrl: sanitizeText(identity?.profileUrl, 1000),
  avatarUrl: sanitizeText(identity?.avatarUrl, 1000),
  linkedAt: identity?.linkedAt || null,
  lastUsedAt: identity?.lastUsedAt || null,
  available: Boolean(providerConfig),
});

const getStoredOauthIdentities = (user) =>
  Array.isArray(user?.oauthIdentities) ? user.oauthIdentities : [];

const findOauthIdentityForUser = (user, provider) =>
  getStoredOauthIdentities(user).find(
    (identity) => sanitizeText(identity?.provider, 40).toLowerCase() === sanitizeText(provider, 40).toLowerCase()
  ) || null;

const buildOauthProvidersState = (user) => {
  const providerStates = {};

  for (const provider of OAUTH_PROVIDERS) {
    providerStates[provider] = {
      ...serializeOauthIdentity(findOauthIdentityForUser(user, provider), { provider }),
      available: isOauthProviderAvailable(provider),
    };
  }

  return providerStates;
};

const findUserByOauthIdentity = async (provider, providerUserId) => {
  const normalizedProvider = sanitizeText(provider, 40).toLowerCase();
  const normalizedProviderUserId = sanitizeText(providerUserId, 160);
  if (!normalizedProvider || !normalizedProviderUserId) return null;

  return User.findOne({
    oauthIdentities: {
      $elemMatch: {
        provider: normalizedProvider,
        providerUserId: normalizedProviderUserId,
      },
    },
  }).select(FULL_USER_SELECT_FIELDS);
};

const upsertOauthIdentity = (user, identity) => {
  const provider = sanitizeText(identity?.provider, 40).toLowerCase();
  const providerUserId = sanitizeText(identity?.providerUserId, 160);
  if (!provider || !providerUserId) {
    throw createHttpError(400, 'OAuth identity is incomplete.');
  }

  const identities = getStoredOauthIdentities(user);
  const nextIdentity = {
    provider,
    providerUserId,
    username: sanitizeText(identity?.username, 120),
    email: sanitizeText(identity?.email, 320).toLowerCase(),
    emailVerified: Boolean(identity?.emailVerified),
    profileUrl: sanitizeText(identity?.profileUrl, 1000),
    avatarUrl: sanitizeText(identity?.avatarUrl, 1000),
    linkedAt: identity?.linkedAt || new Date(),
    lastUsedAt: identity?.lastUsedAt || null,
  };
  const existingIndex = identities.findIndex(
    (entry) => sanitizeText(entry?.provider, 40).toLowerCase() === provider
  );

  if (existingIndex >= 0) {
    identities[existingIndex] = {
      ...identities[existingIndex],
      ...nextIdentity,
      linkedAt: identities[existingIndex]?.linkedAt || nextIdentity.linkedAt,
    };
  } else {
    identities.push(nextIdentity);
  }

  user.oauthIdentities = identities;
};

const removeOauthIdentity = (user, provider) => {
  const normalizedProvider = sanitizeText(provider, 40).toLowerCase();
  const identities = getStoredOauthIdentities(user);
  const next = identities.filter(
    (identity) => sanitizeText(identity?.provider, 40).toLowerCase() !== normalizedProvider
  );

  if (next.length === identities.length) {
    return false;
  }

  user.oauthIdentities = next;
  return true;
};

const requestOauthAccessToken = async (config, code) => {
  const bodyPayload = {
    client_id: config.clientId,
    client_secret: config.clientSecret,
    code: sanitizeText(code, 4000),
    redirect_uri: config.callbackUrl,
  };
  if (config.requireAuthorizationCodeGrant) {
    bodyPayload.grant_type = 'authorization_code';
  }

  const isFormRequest = config.tokenRequestFormat === 'form';
  const response = await fetch(config.tokenUrl, {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': isFormRequest ? 'application/x-www-form-urlencoded' : 'application/json',
      'User-Agent': 'continental-id-auth',
    },
    body: isFormRequest
      ? new URLSearchParams(bodyPayload).toString()
      : JSON.stringify(bodyPayload),
  });

  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload?.access_token) {
    throw createHttpError(
      502,
      payload?.error_description ||
        payload?.error?.message ||
        payload?.error ||
        `${config.label} token exchange failed.`
    );
  }

  return payload;
};

const requestGithubProfile = async (accessToken) => {
  const headers = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${accessToken}`,
    'User-Agent': 'continental-id-auth',
  };

  const profileResponse = await fetch('https://api.github.com/user', { headers });
  const profile = await profileResponse.json().catch(() => ({}));
  if (!profileResponse.ok || !profile?.id) {
    throw createHttpError(502, 'GitHub profile request failed.');
  }

  const emailResponse = await fetch('https://api.github.com/user/emails', { headers });
  const emails = await emailResponse.json().catch(() => []);
  const emailList = Array.isArray(emails) ? emails : [];
  const preferredEmail =
    emailList.find((entry) => entry?.verified && entry?.primary) ||
    emailList.find((entry) => entry?.verified) ||
    emailList.find((entry) => entry?.primary) ||
    null;

  return {
    provider: OAUTH_PROVIDER_GITHUB,
    providerUserId: sanitizeText(profile.id, 160),
    username: sanitizeText(profile.login, 120),
    displayName: sanitizeText(profile.name, 60) || sanitizeText(profile.login, 60) || 'User',
    email: normalizeEmail(preferredEmail?.email || profile.email || ''),
    emailVerified: Boolean(preferredEmail?.verified),
    profileUrl: sanitizeText(profile.html_url, 1000),
    avatarUrl: sanitizeText(profile.avatar_url, 1000),
  };
};

const requestDiscordProfile = async (config, accessToken) => {
  const response = await fetch(config.userInfoUrl, {
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${accessToken}`,
      'User-Agent': 'continental-id-auth',
    },
  });
  const profile = await response.json().catch(() => ({}));
  if (!response.ok || !profile?.id) {
    throw createHttpError(502, 'Discord profile request failed.');
  }

  const avatarHash = sanitizeText(profile.avatar, 160);
  const avatarUrl = avatarHash
    ? `https://cdn.discordapp.com/avatars/${sanitizeText(profile.id, 160)}/${avatarHash}.png?size=256`
    : '';
  const username = sanitizeText(profile.username, 120);
  const displayName =
    sanitizeText(profile.global_name, 60) ||
    username ||
    sanitizeDisplayName('', normalizeEmail(profile.email || '')) ||
    'User';
  const email = normalizeEmail(profile.email || '');

  return {
    provider: OAUTH_PROVIDER_DISCORD,
    providerUserId: sanitizeText(profile.id, 160),
    username,
    displayName,
    email: isValidEmail(email) ? email : '',
    emailVerified: Boolean(profile.verified),
    profileUrl: `https://discord.com/users/${sanitizeText(profile.id, 160)}`,
    avatarUrl,
  };
};

const decodeOauthIdTokenClaims = (idToken) => {
  const token = String(idToken || '').trim();
  if (!token) return {};

  const decoded = jwt.decode(token, { json: true });
  return decoded && typeof decoded === 'object' ? decoded : {};
};

const requestOidcUserInfo = async (config, accessToken) => {
  const response = await fetch(config.userInfoUrl, {
    headers: {
      Accept: 'application/json',
      Authorization: `Bearer ${accessToken}`,
      'User-Agent': 'continental-id-auth',
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || !payload?.sub) {
    throw createHttpError(502, `${config.label} profile request failed.`);
  }
  return payload;
};

const requestOidcProfile = async (config, tokenPayload) => {
  const accessToken = String(tokenPayload?.access_token || '').trim();
  if (!accessToken) {
    throw createHttpError(502, `${config.label} token exchange did not return an access token.`);
  }

  const userInfo = await requestOidcUserInfo(config, accessToken);
  const idTokenClaims = decodeOauthIdTokenClaims(tokenPayload?.id_token);
  const claims = {
    ...idTokenClaims,
    ...userInfo,
  };
  const rawEmail = normalizeEmail(claims.email || claims.preferred_username || '');
  const email = isValidEmail(rawEmail) ? rawEmail : '';
  const displayName =
    sanitizeText(claims.name, 60) ||
    sanitizeText(claims.given_name, 60) ||
    sanitizeDisplayName('', email) ||
    'User';
  const profileUrl = sanitizeText(claims.profile, 1000);
  const avatarUrl = sanitizeText(claims.picture, 1000);
  const emailVerified = hasOwn(claims, 'email_verified')
    ? Boolean(claims.email_verified)
    : Boolean(email && config.trustEmailWithoutExplicitVerification);

  return {
    provider: config.provider,
    providerUserId: sanitizeText(claims.sub, 160),
    username: '',
    displayName,
    email,
    emailVerified,
    profileUrl,
    avatarUrl,
  };
};

const requestOauthIdentityProfile = async (config, tokenPayload) => {
  if (config.profileStrategy === 'github') {
    return requestGithubProfile(String(tokenPayload?.access_token || '').trim());
  }

  if (config.profileStrategy === 'discord') {
    return requestDiscordProfile(config, String(tokenPayload?.access_token || '').trim());
  }

  if (config.profileStrategy === 'oidc') {
    return requestOidcProfile(config, tokenPayload);
  }

  throw createHttpError(500, 'OAuth provider profile strategy is not configured.');
};

const buildOauthAuthorizeUrl = (config, state) => {
  const authorizeUrl = new URL(config.authorizeUrl);
  authorizeUrl.searchParams.set('client_id', config.clientId);
  authorizeUrl.searchParams.set('redirect_uri', config.callbackUrl);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('scope', config.scopes.join(' '));
  authorizeUrl.searchParams.set('state', state);

  if (config.authorizeParams && typeof config.authorizeParams === 'object') {
    for (const [key, value] of Object.entries(config.authorizeParams)) {
      if (value === undefined || value === null || value === '') continue;
      authorizeUrl.searchParams.set(key, String(value));
    }
  }

  return authorizeUrl.toString();
};

const renderOauthResultPage = ({
  title = 'Authentication complete',
  message = 'You can close this window.',
  redirectUrl = DEFAULT_DASHBOARD_ORIGIN,
  targetOrigin = '',
  messagePayload = null,
  closeWindow = true,
}) => {
  const safeTitle = String(title || 'Authentication complete');
  const safeMessage = String(message || 'You can close this window.');
  const normalizedTitle = safeTitle.toLowerCase();
  const normalizedMessage = safeMessage.toLowerCase();
  const isManualVerification =
    normalizedTitle.includes('additional verification required') ||
    normalizedMessage.includes('multi-factor authentication');
  const isSuccess = Boolean(messagePayload);
  const tone = isSuccess ? 'success' : isManualVerification ? 'action' : 'error';
  const eyebrow = isSuccess
    ? 'Secure handoff'
    : isManualVerification
      ? 'Additional verification'
      : 'Sign-in issue';
  const primaryLabel = isSuccess
    ? 'Continue now'
    : isManualVerification
      ? 'Continue to secure sign-in'
      : 'Return to sign-in';
  const redirectDelayMs = isSuccess ? 1200 : isManualVerification ? 1600 : 2200;
  const redirectNote = isSuccess
    ? 'Your session is ready. Redirecting now.'
    : isManualVerification
      ? 'We are taking you back to the secure sign-in screen so you can finish with your password and MFA.'
      : 'We are taking you back to the previous sign-in step so you can try again.';
  const helperTitle = isSuccess
    ? 'What happens next'
    : isManualVerification
      ? 'Finish sign-in in 3 steps'
      : 'Next steps';
  const helperItems = isSuccess
    ? [
        'Your app receives the completed sign-in result.',
        'This window can close or redirect automatically.',
        'If nothing happens, use the button below to continue.',
      ]
    : isManualVerification
      ? [
          'Your provider account was recognized successfully.',
          'Enter your Continental ID password on the next screen.',
          'Complete MFA with your authenticator app or a backup code.',
        ]
      : [
          'Return to the secure sign-in screen.',
          'Try the same provider again or use another method.',
          'If the issue persists, retry from the app that opened this window.',
        ];
  const helperList = helperItems
    .map((item, index) => `<li><span>${index + 1}</span><p>${escapeHtml(item)}</p></li>`)
    .join('');
  const resolvedRedirectUrl = appendAuthPayloadToRedirectUrl(redirectUrl, messagePayload);

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(safeTitle)}</title>
  <style>
    :root {
      color-scheme: dark;
      --page: #08111d;
      --page-soft: #102033;
      --surface: rgba(8, 17, 29, 0.78);
      --panel: rgba(12, 24, 39, 0.9);
      --panel-border: rgba(182, 202, 231, 0.14);
      --text: #edf3fb;
      --text-soft: #b3c3d8;
      --action: #84a2d6;
      --action-soft: rgba(132, 162, 214, 0.14);
      --success: #7cb792;
      --success-soft: rgba(124, 183, 146, 0.14);
      --error: #e48c88;
      --error-soft: rgba(228, 140, 136, 0.14);
      --shadow: 0 32px 90px rgba(0, 0, 0, 0.38);
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      font-family: 'Avenir Next', 'Segoe UI Variable', 'Segoe UI', sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top right, rgba(132, 162, 214, 0.2), transparent 34%),
        radial-gradient(circle at bottom left, rgba(33, 61, 97, 0.26), transparent 28%),
        linear-gradient(180deg, #06101b, var(--page) 54%, var(--page-soft));
    }

    main {
      position: relative;
      width: min(760px, 100%);
      overflow: hidden;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 30px;
      background: var(--surface);
      box-shadow: var(--shadow);
      backdrop-filter: blur(20px);
    }

    main::before {
      content: '';
      position: absolute;
      inset: 0;
      background:
        linear-gradient(140deg, rgba(255, 255, 255, 0.08), transparent 28%),
        linear-gradient(320deg, rgba(132, 162, 214, 0.14), transparent 36%);
      pointer-events: none;
    }

    .shell {
      position: relative;
      display: grid;
      grid-template-columns: minmax(240px, 0.88fr) minmax(320px, 1fr);
      min-height: 100%;
    }

    .hero,
    .content {
      padding: 32px;
    }

    .hero {
      background:
        linear-gradient(180deg, rgba(132, 162, 214, 0.16), rgba(8, 17, 29, 0.08)),
        linear-gradient(160deg, rgba(5, 14, 24, 0.94), rgba(14, 27, 43, 0.88));
      border-right: 1px solid rgba(255, 255, 255, 0.06);
    }

    .hero-badge {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      min-height: 38px;
      padding: 0 14px;
      border-radius: 999px;
      font-size: 0.78rem;
      font-weight: 800;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: rgba(232, 239, 249, 0.82);
      background: rgba(255, 255, 255, 0.06);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.08);
    }

    .hero-badge::before {
      content: '';
      width: 10px;
      height: 10px;
      border-radius: 999px;
      background: ${tone === 'success' ? 'var(--success)' : tone === 'action' ? 'var(--action)' : 'var(--error)'};
      box-shadow: 0 0 0 6px ${tone === 'success'
        ? 'var(--success-soft)'
        : tone === 'action'
          ? 'var(--action-soft)'
          : 'var(--error-soft)'};
    }

    .hero h1,
    .content h2 {
      margin: 0;
      font-family: 'Sora', 'Avenir Next', 'Segoe UI Variable', sans-serif;
      line-height: 1.05;
    }

    .hero h1 {
      margin-top: 22px;
      font-size: clamp(2rem, 6vw, 3rem);
      max-width: 10ch;
    }

    .hero p {
      margin: 16px 0 0;
      max-width: 28ch;
      line-height: 1.65;
      color: rgba(233, 241, 251, 0.74);
    }

    .hero-note {
      margin-top: 26px;
      padding: 16px 18px;
      border: 1px solid ${tone === 'success'
        ? 'rgba(124, 183, 146, 0.2)'
        : tone === 'action'
          ? 'rgba(132, 162, 214, 0.2)'
          : 'rgba(228, 140, 136, 0.2)'};
      border-radius: 18px;
      background: ${tone === 'success'
        ? 'var(--success-soft)'
        : tone === 'action'
          ? 'var(--action-soft)'
          : 'var(--error-soft)'};
      color: ${tone === 'success' ? '#d8f3e1' : tone === 'action' ? '#dde8fb' : '#ffd9d4'};
    }

    .hero-note strong {
      display: block;
      margin-bottom: 8px;
      font-size: 0.95rem;
      color: #f7fbff;
    }

    .content {
      display: grid;
      gap: 20px;
      background: linear-gradient(180deg, var(--panel), rgba(9, 19, 31, 0.94));
    }

    .summary {
      padding: 18px;
      border: 1px solid var(--panel-border);
      border-radius: 22px;
      background: rgba(255, 255, 255, 0.03);
    }

    .summary p {
      margin: 0;
      line-height: 1.65;
      color: var(--text-soft);
    }

    .steps {
      padding: 20px;
      border-radius: 22px;
      border: 1px solid var(--panel-border);
      background: linear-gradient(180deg, rgba(255, 255, 255, 0.03), rgba(132, 162, 214, 0.05));
    }

    .steps h2 {
      font-size: 1.05rem;
      margin-bottom: 16px;
    }

    .steps ol {
      display: grid;
      gap: 14px;
      margin: 0;
      padding: 0;
      list-style: none;
    }

    .steps li {
      display: grid;
      grid-template-columns: 34px 1fr;
      gap: 12px;
      align-items: start;
    }

    .steps span {
      display: inline-grid;
      place-items: center;
      width: 34px;
      height: 34px;
      border-radius: 999px;
      font-size: 0.9rem;
      font-weight: 800;
      color: #f6fbff;
      background: linear-gradient(135deg, #8fa6cf, #4d6f99);
      box-shadow: 0 10px 22px rgba(6, 14, 23, 0.28);
    }

    .steps li p {
      margin: 4px 0 0;
      color: var(--text-soft);
      line-height: 1.55;
    }

    .actions {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }

    .primary,
    .secondary {
      min-height: 48px;
      padding: 0 18px;
      border-radius: 999px;
      border: 0;
      font: inherit;
      font-weight: 800;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      cursor: pointer;
      transition: transform 0.18s ease, opacity 0.18s ease, background-color 0.18s ease;
    }

    .primary {
      flex: 1 1 220px;
      color: #f7fbff;
      background: linear-gradient(135deg, #8fa6cf, #4d6f99);
      box-shadow: 0 16px 28px rgba(22, 38, 59, 0.34);
    }

    .secondary {
      flex: 1 1 180px;
      border: 1px solid var(--panel-border);
      color: var(--text-soft);
      background: rgba(255, 255, 255, 0.03);
    }

    .primary:hover,
    .secondary:hover {
      transform: translateY(-1px);
    }

    .footer {
      display: flex;
      justify-content: space-between;
      gap: 14px;
      align-items: center;
      flex-wrap: wrap;
      color: #8ea2be;
      font-size: 0.92rem;
    }

    .footer strong {
      color: #dfe9f8;
    }

    @media (max-width: 720px) {
      body { padding: 14px; }
      .shell { grid-template-columns: 1fr; }
      .hero { border-right: 0; border-bottom: 1px solid rgba(255, 255, 255, 0.06); }
      .hero,
      .content { padding: 24px 20px; }
      .hero h1 { max-width: none; }
    }
  </style>
</head>
<body>
  <main>
    <div class="shell">
      <section class="hero">
        <div class="hero-badge">${escapeHtml(eyebrow)}</div>
        <h1>${escapeHtml(safeTitle)}</h1>
        <p>${escapeHtml(safeMessage)}</p>
        <div class="hero-note">
          <strong>${escapeHtml(redirectNote)}</strong>
          Use the button below if the redirect does not happen automatically.
        </div>
      </section>

      <section class="content">
        <div class="summary">
          <p>${isManualVerification
            ? 'Your identity provider sign-in completed, but account policy still requires your regular Continental ID sign-in flow.'
            : isSuccess
              ? 'Your secure sign-in has been accepted. This window will finish the handoff automatically.'
              : 'This sign-in attempt could not be completed from the provider callback alone, so we are routing you back to a safer recovery point.'}</p>
        </div>

        <section class="steps" aria-labelledby="oauth-helper-title">
          <h2 id="oauth-helper-title">${escapeHtml(helperTitle)}</h2>
          <ol>${helperList}</ol>
        </section>

        <div class="actions">
          <a id="continue-link" class="primary" href="${escapeHtml(resolvedRedirectUrl)}">${escapeHtml(primaryLabel)}</a>
          <button id="close-window-btn" class="secondary" type="button">Close this window</button>
        </div>

        <div class="footer">
          <span id="redirect-copy">Redirecting in <strong id="redirect-countdown">${Math.ceil(
            redirectDelayMs / 1000
          )}</strong>s</span>
          <span>Continental ID secure callback</span>
        </div>
      </section>
    </div>
  </main>
  <script>
    const payload = ${JSON.stringify(messagePayload || null)};
    const targetOrigin = ${JSON.stringify(targetOrigin || '')};
    const redirectUrl = ${JSON.stringify(resolvedRedirectUrl)};
    const closeWindow = ${JSON.stringify(Boolean(closeWindow))};
    const redirectDelayMs = ${JSON.stringify(redirectDelayMs)};
    const countdownEl = document.getElementById('redirect-countdown');
    const redirectCopyEl = document.getElementById('redirect-copy');
    const closeWindowBtn = document.getElementById('close-window-btn');

    let hasRedirected = false;
    let countdownTimer = 0;

    const closePopup = () => {
      window.close();
    };

    const startRedirectCountdown = () => {
      if (!redirectUrl || hasRedirected) {
        if (redirectCopyEl) {
          redirectCopyEl.textContent = 'You can close this window when you are done.';
        }
        return;
      }

      const startedAt = Date.now();
      const renderCountdown = () => {
        const remainingMs = Math.max(0, redirectDelayMs - (Date.now() - startedAt));
        const remainingSeconds = Math.max(0, Math.ceil(remainingMs / 1000));

        if (countdownEl) {
          countdownEl.textContent = String(remainingSeconds);
        }

        if (remainingMs <= 0) {
          window.clearInterval(countdownTimer);
          hasRedirected = true;
          window.location.replace(redirectUrl);
        }
      };

      renderCountdown();
      countdownTimer = window.setInterval(renderCountdown, 250);
    };

    if (closeWindowBtn) {
      closeWindowBtn.addEventListener('click', closePopup);
    }

    if (payload && window.opener && !window.opener.closed && targetOrigin) {
      try {
        window.opener.postMessage(payload, targetOrigin);
        window.setTimeout(() => {
          try {
            if (window.opener && !window.opener.closed) {
              window.opener.postMessage(payload, targetOrigin);
            }
          } catch {
            // Ignore retry failures and fall back to redirect handling.
          }
        }, 80);
        if (closeWindow) {
          if (redirectCopyEl) {
            redirectCopyEl.textContent = 'Sign-in complete. Closing this window.';
          }
          window.setTimeout(closePopup, 140);
          window.setTimeout(() => {
            if (!hasRedirected && redirectUrl) {
              hasRedirected = true;
              window.location.replace(redirectUrl);
            }
          }, 260);
        } else {
          startRedirectCountdown();
        }
      } catch {
        startRedirectCountdown();
      }
    } else {
      startRedirectCountdown();
    }
  </script>
</body>
</html>`;
};

const prepareEmailVerification = (user) => {
  const verification = createEmailVerificationToken();

  user.isVerified = false;
  user.verificationToken = verification.hashedToken;
  user.verificationTokenExpires = verification.expiresAt;

  return verification;
};

const hasPendingEmailVerification = (user) =>
  Boolean(
    sanitizeText(user?.verificationToken, 160) &&
      user?.verificationTokenExpires &&
      new Date(user.verificationTokenExpires).getTime() > Date.now()
  );

const getVerificationEmailCooldownRemainingMs = (user) => {
  const sentAt = new Date(user?.emailDelivery?.verificationLastSentAt || 0).getTime();
  if (!sentAt) return 0;
  return Math.max(0, sentAt + VERIFICATION_EMAIL_COOLDOWN_MS - Date.now());
};

const createPasswordResetToken = () => {
  const token = crypto.randomBytes(32).toString('hex');
  return {
    token,
    hashedToken: hashToken(token),
    expiresAt: new Date(Date.now() + PASSWORD_RESET_TTL_MS),
  };
};

const preparePasswordReset = (user) => {
  const reset = createPasswordResetToken();
  user.passwordResetToken = reset.hashedToken;
  user.passwordResetTokenExpires = reset.expiresAt;
  user.passwordResetRequestedAt = new Date();
  return reset;
};

const clearPasswordReset = (user) => {
  if (!user) return;
  user.passwordResetToken = '';
  user.passwordResetTokenExpires = null;
};

const formatEmailDate = (value) => new Date(value).toUTCString();

const EMAIL_THEME_PALETTES = {
  graphite: {
    pageBg: '#0f141c',
    shellBg: '#161c26',
    heroBg: '#232d3b',
    contentBg: '#1a212d',
    panelBg: '#253041',
    shellBorder: '#344154',
    text: '#eef1f6',
    muted: '#a8b2c3',
    footer: '#a8b2c3',
    label: '#9aa6bb',
    accent: '#6c84af',
    accentStrong: '#8fa6cf',
    accentSoft: '#1e2939',
    secondary: '#d0ab73',
    secondarySoft: '#332a1d',
    buttonText: '#ffffff',
  },
  midnight: {
    pageBg: '#07111e',
    shellBg: '#0b1727',
    heroBg: '#112338',
    contentBg: '#0d1a2b',
    panelBg: '#112338',
    shellBorder: '#22344a',
    text: '#edf3fb',
    muted: '#9fb3ca',
    footer: '#95a5bd',
    label: '#7d8ea5',
    accent: '#4d6f99',
    accentStrong: '#6f8bb2',
    accentSoft: '#15283e',
    secondary: '#c9a46f',
    secondarySoft: '#2e261d',
    buttonText: '#ffffff',
  },
  alpine: {
    pageBg: '#0b1418',
    shellBg: '#132127',
    heroBg: '#22404c',
    contentBg: '#16262c',
    panelBg: '#1a3138',
    shellBorder: '#36525b',
    text: '#f4f5ef',
    muted: '#b5b7ad',
    footer: '#b5b7ad',
    label: '#c1bfac',
    accent: '#9fbfb4',
    accentStrong: '#cfe0d8',
    accentSoft: '#23363a',
    secondary: '#a59772',
    secondarySoft: '#332f24',
    buttonText: '#0b1418',
  },
  heritage: {
    pageBg: '#f7f2ea',
    shellBg: '#ffffff',
    heroBg: '#eff5f2',
    contentBg: '#ffffff',
    panelBg: '#f7f2ea',
    shellBorder: '#d9d3ca',
    text: '#1c2530',
    muted: '#69707d',
    footer: '#69707d',
    label: '#7b766d',
    accent: '#146f63',
    accentStrong: '#0d5a52',
    accentSoft: '#e3f0ed',
    secondary: '#c38a4a',
    secondarySoft: '#f4eadb',
    buttonText: '#ffffff',
  },
  dawn: {
    pageBg: '#fbf2ea',
    shellBg: '#fff9f4',
    heroBg: '#f7ede6',
    contentBg: '#fff9f4',
    panelBg: '#fbf2ea',
    shellBorder: '#e8d8cb',
    text: '#251f20',
    muted: '#736667',
    footer: '#736667',
    label: '#876d57',
    accent: '#99572d',
    accentStrong: '#7a431f',
    accentSoft: '#f3e6dd',
    secondary: '#c68b54',
    secondarySoft: '#faeedf',
    buttonText: '#ffffff',
  },
  night: {
    pageBg: '#0b151b',
    shellBg: '#102229',
    heroBg: '#163640',
    contentBg: '#11252c',
    panelBg: '#163039',
    shellBorder: '#25444d',
    text: '#edf3ef',
    muted: '#a0aea9',
    footer: '#a0aea9',
    label: '#b3c1bc',
    accent: '#a7d8c3',
    accentStrong: '#81c7ae',
    accentSoft: '#1d342f',
    secondary: '#f0bd86',
    secondarySoft: '#362d23',
    buttonText: '#0b151b',
  },
  ocean: {
    pageBg: '#071825',
    shellBg: '#0b2635',
    heroBg: '#12425a',
    contentBg: '#0d2a3b',
    panelBg: '#123345',
    shellBorder: '#245066',
    text: '#eefaff',
    muted: '#9ec3d0',
    footer: '#9ec3d0',
    label: '#a8d0dc',
    accent: '#66d7d0',
    accentStrong: '#40beb7',
    accentSoft: '#123840',
    secondary: '#f1c177',
    secondarySoft: '#382c1f',
    buttonText: '#062027',
  },
};

const normalizeEmailTheme = (value) => {
  const normalized = sanitizeText(value, 24).toLowerCase();
  if (normalized && ALLOWED_THEMES.has(normalized) && normalized !== 'system') {
    return normalized;
  }

  return DEFAULT_APPEARANCE.theme === 'system' ? 'graphite' : DEFAULT_APPEARANCE.theme;
};

const getEmailThemePalette = (theme) =>
  EMAIL_THEME_PALETTES[normalizeEmailTheme(theme)] || EMAIL_THEME_PALETTES.graphite;

const resolveEmailHeroImageUrl = () => {
  const explicitHeroImageUrl = resolveAbsoluteUrl(
    process.env.EMAIL_HERO_IMAGE_URL || process.env.PUBLIC_EMAIL_HERO_IMAGE_URL
  );
  if (explicitHeroImageUrl) {
    return explicitHeroImageUrl;
  }

  return `${DEFAULT_DASHBOARD_ORIGIN}/images/placeHolder2.jpg`;
};

const renderEmailParagraphs = (paragraphs = [], styles = {}) => {
  const mergedStyles = {
    margin: '0 0 14px 0',
    fontFamily: "'Aptos','Segoe UI',Arial,sans-serif",
    fontSize: '16px',
    lineHeight: '1.75',
    color: '#1f2937',
    ...styles,
  };
  const styleAttr = Object.entries(mergedStyles)
    .map(([key, value]) => `${key}:${value};`)
    .join('');

  return paragraphs
    .filter(Boolean)
    .map((paragraph, index, array) => {
      const marginStyle =
        index === array.length - 1
          ? styleAttr.replace('margin:0 0 14px 0;', 'margin:0;')
          : styleAttr;
      return `<p style="${marginStyle}">${paragraph}</p>`;
    })
    .join('');
};

const renderEmailBulletList = (
  items = [],
  { bulletColor = '#0f766e', textColor = '#334155', dotHalo = 'transparent' } = {}
) => {
  const normalizedItems = items.filter(Boolean);
  if (!normalizedItems.length) return '';

  return `
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;margin:0;">
      ${normalizedItems
        .map(
          (item) => `
            <tr>
              <td valign="top" style="width:32px;padding:0 0 12px 0;">
                <table role="presentation" cellpadding="0" cellspacing="0" style="margin:2px 0 0 0;">
                  <tr>
                    <td style="width:12px;height:12px;border-radius:999px;background-color:${bulletColor};box-shadow:0 0 0 6px ${dotHalo};font-size:0;line-height:0;">&nbsp;</td>
                  </tr>
                </table>
              </td>
              <td style="padding:0 0 12px 0;font-family:'Aptos','Segoe UI',Arial,sans-serif;font-size:15px;line-height:1.7;color:${textColor};">
                ${item}
              </td>
            </tr>
          `
        )
        .join('')}
    </table>
  `;
};

const renderEmailDetailRows = (
  rows = [],
  { borderColor = '#dbe4ea', labelColor = '#64748b', valueColor = '#0f172a' } = {}
) => {
  const normalizedRows = rows.filter((row) => row?.label && row?.value);
  if (!normalizedRows.length) return '';

  return normalizedRows
    .map(
      (row, index) => `
        <tr>
          <td style="padding:${index === 0 ? '0' : '14px'} 0 0 0;border-top:${index === 0 ? '0' : `1px solid ${borderColor}`};">
            <p style="margin:0 0 4px 0;font-family:'Aptos','Segoe UI',Arial,sans-serif;font-size:11px;line-height:1.4;letter-spacing:0.16em;text-transform:uppercase;color:${labelColor};font-weight:700;">
              ${row.label}
            </p>
            <p style="margin:0;font-family:'Aptos','Segoe UI',Arial,sans-serif;font-size:15px;line-height:1.7;color:${valueColor};">
              ${row.value}
            </p>
          </td>
        </tr>
      `
    )
    .join('');
};

const buildBrandedEmailHtml = ({
  preheader = '',
  theme = DEFAULT_APPEARANCE.theme,
  eyebrow = 'Continental ID',
  title = '',
  lead = '',
  greeting = '',
  bodyParagraphs = [],
  ctaLabel = '',
  ctaUrl = '',
  detailTitle = '',
  detailRows = [],
  bulletTitle = '',
  bulletItems = [],
  fallbackLabel = '',
  footerNote = '',
  heroImageUrl = '',
}) => {
  const palette = getEmailThemePalette(theme);
  const safePreheader = escapeHtml(preheader);
  const safeEyebrow = escapeHtml(eyebrow);
  const safeTitle = escapeHtml(title);
  const safeLead = escapeHtml(lead);
  const safeGreeting = greeting;
  const safeCtaLabel = escapeHtml(ctaLabel);
  const safeCtaUrl = escapeHtml(ctaUrl);
  const safeDetailTitle = escapeHtml(detailTitle);
  const safeBulletTitle = escapeHtml(bulletTitle);
  const safeFallbackLabel = escapeHtml(fallbackLabel);
  const safeFooterNote = escapeHtml(footerNote);
  const safeHeroImageUrl = escapeHtml(heroImageUrl);
  const hasHeroImage = Boolean(safeHeroImageUrl);

  return `
    <div style="display:none;max-height:0;max-width:0;overflow:hidden;opacity:0;color:transparent;">
      ${safePreheader}
    </div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;margin:0;padding:28px 12px;background-color:${palette.pageBg};">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;max-width:720px;margin:0 auto;">
            <tr>
              <td style="padding:0 0 16px 0;text-align:center;">
                <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 auto;">
                  <tr>
                    <td style="padding:8px 14px;border-radius:999px;background-color:${palette.accentSoft};border:1px solid ${palette.shellBorder};font-family:'Aptos','Segoe UI',Arial,sans-serif;font-size:11px;line-height:1.2;letter-spacing:0.18em;text-transform:uppercase;color:${palette.accentStrong};font-weight:700;">
                      ${safeEyebrow}
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            <tr>
              <td style="padding:0;">
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background-color:${palette.shellBg};border:1px solid ${palette.shellBorder};border-radius:30px;overflow:hidden;">
                  ${
                    hasHeroImage
                      ? `
                        <tr>
                          <td style="padding:0;">
                            <img src="${safeHeroImageUrl}" alt="Continental ID header image" width="720" style="display:block;width:100%;height:auto;border:0;outline:none;text-decoration:none;" />
                          </td>
                        </tr>
                      `
                      : ''
                  }
                  <tr>
                    <td style="height:6px;background-color:${palette.secondary};font-size:0;line-height:0;">&nbsp;</td>
                  </tr>
                  <tr>
                    <td style="padding:28px 28px 24px 28px;background-color:${palette.heroBg};border-bottom:1px solid ${palette.shellBorder};">
                      <table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 18px 0;">
                        <tr>
                          <td style="padding:7px 12px;border-radius:999px;background-color:${palette.secondarySoft};font-family:'Aptos','Segoe UI',Arial,sans-serif;font-size:11px;line-height:1.2;letter-spacing:0.16em;text-transform:uppercase;color:${palette.secondary};font-weight:700;">
                            Dashboard-aligned design
                          </td>
                        </tr>
                      </table>
                      <p style="margin:0 0 14px 0;font-family:'Sora','Aptos Display','Segoe UI',Arial,sans-serif;font-size:36px;line-height:1.08;color:${palette.text};font-weight:700;letter-spacing:-0.03em;">
                        ${safeTitle}
                      </p>
                      <p style="margin:0;font-family:'Aptos','Segoe UI',Arial,sans-serif;font-size:17px;line-height:1.75;color:${palette.muted};">
                        ${safeLead}
                      </p>
                    </td>
                  </tr>
                </table>
                <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;background-color:${palette.contentBg};border-left:1px solid ${palette.shellBorder};border-right:1px solid ${palette.shellBorder};border-bottom:1px solid ${palette.shellBorder};border-radius:0 0 30px 30px;">
                  <tr>
                    <td style="padding:30px 28px 28px 28px;">
                      ${renderEmailParagraphs([safeGreeting], {
                        margin: '0 0 16px 0',
                        fontSize: '16px',
                        lineHeight: '1.75',
                        color: palette.text,
                      })}
                      ${renderEmailParagraphs(bodyParagraphs, {
                        color: palette.text,
                      })}
                      ${
                        safeCtaLabel && safeCtaUrl
                          ? `
                            <table role="presentation" cellpadding="0" cellspacing="0" style="margin:26px 0 24px 0;">
                              <tr>
                                <td style="border-radius:16px;background-color:${palette.accent};box-shadow:inset 0 -2px 0 rgba(0,0,0,0.16);">
                                  <a href="${safeCtaUrl}" style="display:inline-block;padding:15px 26px;font-family:'Aptos','Segoe UI',Arial,sans-serif;font-size:15px;line-height:1.2;font-weight:700;color:${palette.buttonText};text-decoration:none;">
                                    ${safeCtaLabel}
                                  </a>
                                </td>
                              </tr>
                            </table>
                          `
                          : ''
                      }
                      ${
                        safeDetailTitle && detailRows.length
                          ? `
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;margin:0 0 22px 0;background-color:${palette.panelBg};border:1px solid ${palette.shellBorder};border-radius:22px;">
                              <tr>
                                <td style="padding:20px 20px 18px 20px;">
                                  <p style="margin:0 0 14px 0;font-family:'Aptos','Segoe UI',Arial,sans-serif;font-size:12px;line-height:1.4;letter-spacing:0.14em;text-transform:uppercase;color:${palette.accentStrong};font-weight:700;">
                                    ${safeDetailTitle}
                                  </p>
                                  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;">
                                    ${renderEmailDetailRows(detailRows, {
                                      borderColor: palette.shellBorder,
                                      labelColor: palette.label,
                                      valueColor: palette.text,
                                    })}
                                  </table>
                                </td>
                              </tr>
                            </table>
                          `
                          : ''
                      }
                      ${
                        safeBulletTitle && bulletItems.length
                          ? `
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;margin:0 0 22px 0;background-color:${palette.panelBg};border:1px solid ${palette.shellBorder};border-radius:22px;">
                              <tr>
                                <td style="padding:20px;">
                                  <p style="margin:0 0 14px 0;font-family:'Aptos','Segoe UI',Arial,sans-serif;font-size:12px;line-height:1.4;letter-spacing:0.14em;text-transform:uppercase;color:${palette.secondary};font-weight:700;">
                                    ${safeBulletTitle}
                                  </p>
                                  ${renderEmailBulletList(bulletItems, {
                                    bulletColor: palette.accent,
                                    textColor: palette.text,
                                    dotHalo: palette.accentSoft,
                                  })}
                                </td>
                              </tr>
                            </table>
                          `
                          : ''
                      }
                      ${
                        safeFallbackLabel && safeCtaUrl
                          ? `
                            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="width:100%;margin:0;background-color:${palette.panelBg};border:1px solid ${palette.shellBorder};border-radius:20px;">
                              <tr>
                                <td style="padding:18px 20px;">
                                  <p style="margin:0 0 10px 0;font-family:'Aptos','Segoe UI',Arial,sans-serif;font-size:14px;line-height:1.7;color:${palette.muted};">
                                    ${safeFallbackLabel}
                                  </p>
                                  <p style="margin:0;font-family:'Aptos','Segoe UI',Arial,sans-serif;font-size:14px;line-height:1.8;word-break:break-all;">
                                    <a href="${safeCtaUrl}" style="color:${palette.accentStrong};text-decoration:underline;">
                                      ${safeCtaUrl}
                                    </a>
                                  </p>
                                </td>
                              </tr>
                            </table>
                          `
                          : ''
                      }
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
            <tr>
              <td style="padding:18px 20px 0 20px;text-align:center;font-family:'Aptos','Segoe UI',Arial,sans-serif;font-size:12px;line-height:1.8;color:${palette.footer};">
                ${safeFooterNote}
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  `;
};

const buildVerificationEmailContent = (user, verificationUrl, expiresAt) => {
  const displayName = sanitizeText(user?.displayName || user?.email, 60) || 'there';
  const emailAddress = sanitizeText(user?.email, 160);
  const expiresLabel = formatEmailDate(expiresAt);
  const safeDisplayName = escapeHtml(displayName);
  const safeEmailAddress = escapeHtml(emailAddress);
  const verificationTarget = emailAddress
    ? `the email address ${emailAddress}`
    : 'your email address';
  const safeVerificationTarget = safeEmailAddress
    ? `the email address <strong>${safeEmailAddress}</strong>`
    : 'your email address';

  return {
    subject: EMAIL_VERIFICATION_SUBJECT,
    text: [
      `Hi ${displayName},`,
      '',
      `Verify ${verificationTarget} on your Continental ID account by opening this link:`,
      verificationUrl,
      '',
      `This link expires on ${expiresLabel}.`,
      'If you did not create this account, you can ignore this message.',
    ].join('\n'),
    html: buildBrandedEmailHtml({
      preheader: 'Verify your Continental ID email to finish setting up your account.',
      theme: user?.preferences?.appearance?.theme,
      heroImageUrl: resolveEmailHeroImageUrl(),
      title: 'Verify your email',
      lead: 'Finish setting up your account and keep sign-in trusted across the dashboard.',
      greeting: `Hi ${safeDisplayName},`,
      bodyParagraphs: [
        `We received a request to verify ${safeVerificationTarget} for your Continental ID account.`,
        'Use the button below to confirm the address and unlock verified sign-in.',
      ],
      ctaLabel: 'Verify email address',
      ctaUrl: verificationUrl,
      detailTitle: 'Verification details',
      detailRows: [
        { label: 'Address', value: safeEmailAddress || 'Your email address' },
        { label: 'Link expires', value: escapeHtml(expiresLabel) },
      ],
      bulletTitle: 'What happens next',
      bulletItems: [
        'Your email address is marked as verified for this account.',
        'You can complete sign-in flows that require email verification.',
        'If this was not your account creation attempt, no action is required.',
      ],
      fallbackLabel: 'If the button does not work, copy and paste this link into your browser:',
      footerNote: 'This verification link was sent for Continental ID account setup.',
    }),
  };
};

const resolvePasswordResetPageUrl = (req) => {
  const explicitResetUrl = resolveAbsoluteUrl(
    process.env.PASSWORD_RESET_URL || process.env.PASSWORD_RESET_PAGE_URL
  );
  if (explicitResetUrl) {
    return explicitResetUrl;
  }

  const loginPopupUrl = resolveLoginPopupPageUrl(req);
  if (loginPopupUrl) {
    return new URL('reset-password.html', loginPopupUrl).toString();
  }

  const appBaseUrl = resolveAbsoluteUrl(
    process.env.APP_BASE_URL || process.env.PUBLIC_APP_URL || process.env.PUBLIC_BASE_URL
  );
  if (appBaseUrl) {
    return new URL(DEFAULT_PASSWORD_RESET_PATH, appBaseUrl).toString();
  }

  if ((process.env.NODE_ENV || 'development') !== 'production') {
    const requestOrigin = getRequestOrigin(req);
    if (requestOrigin) {
      return new URL(DEFAULT_PASSWORD_RESET_PATH, requestOrigin).toString();
    }
  }

  return '';
};

const buildPasswordResetUrl = (req, token) => {
  const baseUrl = resolvePasswordResetPageUrl(req);
  if (!baseUrl || !token) return '';

  const url = new URL(baseUrl);
  url.searchParams.set('token', token);
  return url.toString();
};

const buildPasswordResetEmailContent = (user, resetUrl, expiresAt) => {
  const displayName = sanitizeText(user?.displayName || user?.email, 60) || 'there';
  const expiresLabel = formatEmailDate(expiresAt);
  const safeDisplayName = escapeHtml(displayName);

  return {
    subject: PASSWORD_RESET_SUBJECT,
    text: [
      `Hi ${displayName},`,
      '',
      'Open this link to reset your Continental ID password:',
      resetUrl,
      '',
      `This link expires on ${expiresLabel}.`,
      'If you did not request this, you can ignore this message.',
    ].join('\n'),
    html: buildBrandedEmailHtml({
      preheader: 'Use this secure link to reset your Continental ID password.',
      theme: user?.preferences?.appearance?.theme,
      heroImageUrl: resolveEmailHeroImageUrl(),
      title: 'Reset your password',
      lead: 'A password reset was requested for your Continental ID account.',
      greeting: `Hi ${safeDisplayName},`,
      bodyParagraphs: [
        'Use the secure link below to choose a new password and restore access to your account.',
        'For security, this reset link works only for a limited time.',
      ],
      ctaLabel: 'Reset password',
      ctaUrl: resetUrl,
      detailTitle: 'Reset details',
      detailRows: [
        { label: 'Link expires', value: escapeHtml(expiresLabel) },
        { label: 'Requested for', value: 'Your Continental ID account' },
      ],
      bulletTitle: 'Security notes',
      bulletItems: [
        'After resetting, use the new password the next time you sign in.',
        'If you did not request this reset, you can ignore this email.',
        'If you keep receiving unexpected reset emails, review your account security.',
      ],
      fallbackLabel: 'If the button does not work, copy and paste this link into your browser:',
      footerNote: 'This password reset email was sent because a reset request was submitted for your account.',
    }),
  };
};

const serializeVerificationDelivery = (delivery) => {
  const payload = {
    sent: Boolean(delivery?.sent),
  };

  const reason = sanitizeText(delivery?.reason, 60);
  if (reason) {
    payload.reason = reason;
  }

  return payload;
};

const getVerificationDeliveryMessage = (
  successMessage,
  cooldownMessage,
  failureMessage,
  delivery
) => {
  if (delivery?.sent) {
    return successMessage;
  }

  if (delivery?.reason === 'cooldown') {
    return cooldownMessage;
  }

  return failureMessage;
};

const reserveEmailQuotaWindow = async ({ key, windowStart, expiresAt, limit, amount = 1 }) => {
  const normalizedAmount = Math.max(1, Math.trunc(Number(amount || 1)));
  const maxAllowedCount = limit - normalizedAmount;

  if (maxAllowedCount < 0) {
    return false;
  }

  const entry = await ApiRateLimitBucket.findOneAndUpdate(
    {
      key,
      windowStart,
      count: { $lte: maxAllowedCount },
    },
    {
      $setOnInsert: {
        expiresAt,
      },
      $inc: {
        count: normalizedAmount,
      },
    },
    {
      upsert: true,
      new: true,
    }
  ).lean();

  return Boolean(entry);
};

const rollbackEmailQuotaWindow = async ({ key, windowStart, amount = 1 }) => {
  const normalizedAmount = Math.max(1, Math.trunc(Number(amount || 1)));
  await ApiRateLimitBucket.updateOne(
    { key, windowStart },
    {
      $inc: {
        count: -normalizedAmount,
      },
    }
  );
};

const reserveEmailQuota = async (recipientCount = 1) => {
  const amount = Math.max(1, Math.trunc(Number(recipientCount || 1)));
  const now = Date.now();
  const dayWindowStart = getUtcDayWindowStart(now);
  const monthWindowStart = getUtcMonthWindowStart(now);
  const dayKey = 'outbound-email:global:day';
  const monthKey = 'outbound-email:global:month';

  const reservedDay = await reserveEmailQuotaWindow({
    key: dayKey,
    windowStart: dayWindowStart,
    expiresAt: addUtcDays(dayWindowStart, 2),
    limit: EMAIL_DAILY_LIMIT,
    amount,
  });

  if (!reservedDay) {
    return { ok: false, reason: 'quota_daily_limit' };
  }

  const reservedMonth = await reserveEmailQuotaWindow({
    key: monthKey,
    windowStart: monthWindowStart,
    expiresAt: addUtcMonths(monthWindowStart, 2),
    limit: EMAIL_MONTHLY_LIMIT,
    amount,
  });

  if (!reservedMonth) {
    await rollbackEmailQuotaWindow({
      key: dayKey,
      windowStart: dayWindowStart,
      amount,
    });
    return { ok: false, reason: 'quota_monthly_limit' };
  }

  return {
    ok: true,
    reservation: {
      amount,
      dayKey,
      dayWindowStart,
      monthKey,
      monthWindowStart,
    },
  };
};

const deliverManagedEmail = async ({
  user = null,
  to,
  subject,
  text,
  html,
  onSent = null,
} = {}) => {
  const recipients = (Array.isArray(to) ? to : [to]).filter(Boolean);
  if (recipients.length === 0) {
    return { sent: false, reason: 'missing_recipient' };
  }

  const quota = await reserveEmailQuota(recipients.length);
  if (!quota.ok) {
    return { sent: false, reason: quota.reason };
  }

  const rollbackReservation = async () => {
    await rollbackEmailQuotaWindow({
      key: quota.reservation.dayKey,
      windowStart: quota.reservation.dayWindowStart,
      amount: quota.reservation.amount,
    });
    await rollbackEmailQuotaWindow({
      key: quota.reservation.monthKey,
      windowStart: quota.reservation.monthWindowStart,
      amount: quota.reservation.amount,
    });
  };

  let response = null;
  try {
    response = await sendEmail({
      to: recipients,
      subject,
      text,
      html,
    });

    if (response?.skipped) {
      await rollbackReservation();
      return {
        sent: false,
        reason: sanitizeText(response.reason, 60) || 'email_skipped',
      };
    }
  } catch (err) {
    await rollbackReservation();
    console.error('Managed email delivery error:', err);
    return { sent: false, reason: 'delivery_error' };
  }

  try {
    if (typeof onSent === 'function') {
      onSent();
    }

    if (user?.isModified && user.isModified()) {
      await user.save();
    }
  } catch (err) {
    console.error('Email post-send persistence error:', err);
  }

  return {
    sent: true,
    id: sanitizeText(response?.id, 120),
  };
};

const sendVerificationEmail = async (user, req, verification) => {
  if (!user?.email || !verification?.token) {
    return { sent: false };
  }

  const verificationUrl = buildEmailVerificationUrl(req, verification.token);
  if (!verificationUrl) {
    console.warn('Verification email URL is not configured; skipping verification email.');
    return { sent: false, reason: 'url_not_configured' };
  }

  const emailContent = buildVerificationEmailContent(user, verificationUrl, verification.expiresAt);
  return deliverManagedEmail({
    user,
    to: user.email,
    subject: emailContent.subject,
    text: emailContent.text,
    html: emailContent.html,
    onSent: () => {
      user.emailDelivery = user.emailDelivery || {};
      user.emailDelivery.verificationLastSentAt = new Date();
    },
  });
};

const sendPasswordResetEmail = async (user, req, reset) => {
  if (!user?.email || !reset?.token) {
    return { sent: false };
  }

  const resetUrl = buildPasswordResetUrl(req, reset.token);
  if (!resetUrl) {
    console.warn('Password reset URL is not configured; skipping password reset email.');
    return { sent: false, reason: 'url_not_configured' };
  }

  const emailContent = buildPasswordResetEmailContent(user, resetUrl, reset.expiresAt);
  return deliverManagedEmail({
    to: user.email,
    subject: emailContent.subject,
    text: emailContent.text,
    html: emailContent.html,
  });
};

const buildSecurityEmailContent = ({ user = null, title, intro, details = [] }) => {
  const safeTitle = escapeHtml(title || 'Security alert');
  const safeIntro = escapeHtml(intro || 'A security-sensitive action was detected on your account.');
  const normalizedDetails = Array.isArray(details)
    ? details.map((item) => sanitizeText(item, 240)).filter(Boolean)
    : [];

  return {
    text: [
      title || 'Security alert',
      '',
      intro || 'A security-sensitive action was detected on your account.',
      '',
      ...normalizedDetails.map((item) => `- ${item}`),
    ].join('\n'),
    html: buildBrandedEmailHtml({
      preheader: title || 'Security alert for your Continental ID account.',
      theme: user?.preferences?.appearance?.theme,
      heroImageUrl: resolveEmailHeroImageUrl(),
      eyebrow: 'Security notice',
      title: title || 'Security alert',
      lead: 'A security-sensitive action was detected on your Continental ID account.',
      greeting: 'Security notice,',
      bodyParagraphs: [safeIntro],
      detailTitle: normalizedDetails.length ? 'Event details' : '',
      detailRows: normalizedDetails.map((item, index) => ({
        label: `Detail ${index + 1}`,
        value: escapeHtml(item),
      })),
      bulletTitle: 'Recommended next steps',
      bulletItems: [
        'Review the activity details below and confirm that you recognize them.',
        'If this action was not expected, change your password immediately.',
        'Check recent sign-ins and revoke access on devices you do not recognize.',
      ],
      footerNote: 'This alert was sent because security notifications are enabled for your Continental ID account.',
    }),
  };
};

const shouldSendSecurityNotifications = (user, emailOverride = '') =>
  Boolean(
    sanitizeText(emailOverride || user?.email, 320) &&
      (hasOwn(user?.preferences?.notifications || {}, 'security')
        ? user?.preferences?.notifications?.security
        : DEFAULT_NOTIFICATIONS.security)
  );

const shouldSendLoginAlert = (user) =>
  shouldSendSecurityNotifications(user) &&
  Boolean(hasOwn(user?.security || {}, 'loginAlerts') ? user?.security?.loginAlerts : true);

const shouldSendLoginAlertForDevice = (user, deviceFingerprint = '') => {
  if (!shouldSendLoginAlert(user)) {
    return false;
  }

  const lastSentAt = user?.security?.loginAlertLastSentAt
    ? new Date(user.security.loginAlertLastSentAt).getTime()
    : 0;
  const cooldownActive =
    lastSentAt > 0 && lastSentAt + LOGIN_ALERT_EMAIL_COOLDOWN_MS > Date.now();
  const normalizedFingerprint = sanitizeText(deviceFingerprint, 128);
  const lastFingerprint = sanitizeText(user?.security?.loginAlertLastDeviceFingerprint, 128);

  if (!cooldownActive) {
    return true;
  }

  return Boolean(normalizedFingerprint && lastFingerprint && normalizedFingerprint !== lastFingerprint);
};

const sendSecurityAlertEmail = async (user, subject, title, intro, details = [], options = {}) => {
  const recipient = sanitizeText(options.emailOverride || user?.email, 320);
  if (!shouldSendSecurityNotifications(user, recipient)) {
    return { sent: false };
  }

  const emailContent = buildSecurityEmailContent({ user, title, intro, details });
  return deliverManagedEmail({
    user,
    to: recipient,
    subject,
    text: emailContent.text,
    html: emailContent.html,
    onSent: () => {
      if (!options.trackLoginAlert) {
        return;
      }

      user.security = user.security || {};
      user.security.loginAlertLastSentAt = new Date();
      user.security.loginAlertLastDeviceFingerprint = sanitizeText(
        options.deviceFingerprint,
        128
      );
    },
  });
};

const EMAIL_PREVIEW_TYPES = new Set([
  'verification',
  'password-reset',
  'login-alert',
  'password-changed',
]);

const buildEmailPreviewUser = (theme) => ({
  email: 'alex.mercer@continental-hub.com',
  displayName: 'Alex Mercer',
  preferences: {
    appearance: {
      theme: normalizeEmailTheme(theme),
    },
  },
});

const buildPreviewBaseUrl = (req) => {
  const requestOrigin = getRequestOrigin(req);
  if (requestOrigin) return requestOrigin;
  return DEFAULT_DASHBOARD_ORIGIN;
};

const buildEmailPreviewContent = (type, theme, req) => {
  const previewType = EMAIL_PREVIEW_TYPES.has(type) ? type : 'verification';
  const previewTheme = normalizeEmailTheme(theme);
  const user = buildEmailPreviewUser(previewTheme);
  const baseUrl = buildPreviewBaseUrl(req);

  if (previewType === 'password-reset') {
    return buildPasswordResetEmailContent(
      user,
      `${baseUrl}/reset-password.html?token=preview-reset-token`,
      new Date(Date.now() + PASSWORD_RESET_TTL_MS)
    );
  }

  if (previewType === 'login-alert') {
    return buildSecurityEmailContent({
      user,
      title: 'New device sign-in to Continental ID',
      intro: 'A sign-in from a device we had not seen before was detected on your account.',
      details: [
        `Time: ${new Date().toUTCString()}`,
        'IP address: 203.0.113.42',
        'Device: Safari on macOS 15',
        'Location: Stockholm, Sweden',
      ],
    });
  }

  if (previewType === 'password-changed') {
    return buildSecurityEmailContent({
      user,
      title: 'Your Continental ID password was changed',
      intro: 'Your Continental ID password was updated.',
      details: [
        `Time: ${new Date().toUTCString()}`,
        'IP address: 203.0.113.42',
      ],
    });
  }

  return buildVerificationEmailContent(
    user,
    `${baseUrl}/verify.html?token=preview-verification-token`,
    new Date(Date.now() + VERIFICATION_EMAIL_COOLDOWN_MS)
  );
};

exports.previewEmailHtml = (req, res) => {
  const type = sanitizeText(req.params?.type || req.query?.type || 'verification', 40);
  const theme = sanitizeText(req.query?.theme || DEFAULT_APPEARANCE.theme, 24);
  const emailContent = buildEmailPreviewContent(type, theme, req);

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(emailContent.html);
};

exports.previewEmailIndex = (req, res) => {
  const requestedType = sanitizeText(req.query?.type || 'verification', 40);
  const requestedTheme = normalizeEmailTheme(req.query?.theme || DEFAULT_APPEARANCE.theme);
  const selectedType = EMAIL_PREVIEW_TYPES.has(requestedType) ? requestedType : 'verification';
  const typeOptions = [
    ['verification', 'Verification'],
    ['password-reset', 'Password Reset'],
    ['login-alert', 'New Login Alert'],
    ['password-changed', 'Password Changed'],
  ];
  const themeOptions = ['midnight', 'alpine', 'heritage', 'dawn', 'night', 'ocean'];
  const previewBasePath = '/api/auth/email-preview';
  const previewSrc = `${previewBasePath}/${selectedType}?theme=${encodeURIComponent(requestedTheme)}`;

  const page = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Continental ID Email Preview</title>
  <style>
    :root {
      color-scheme: dark;
      --bg-1: #07111e;
      --bg-2: #0b1727;
      --surface: rgba(9, 18, 31, 0.92);
      --surface-soft: rgba(17, 34, 56, 0.88);
      --line: rgba(176, 194, 220, 0.18);
      --text: #edf3fb;
      --muted: #95a5bd;
      --accent: #c9a46f;
      --accent-soft: rgba(201, 164, 111, 0.12);
      --button: #4d6f99;
      --button-strong: #385476;
      --shadow: 0 24px 60px rgba(1, 8, 18, 0.32);
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Manrope", "Segoe UI", sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at top right, rgba(77, 111, 153, 0.18), transparent 28%),
        radial-gradient(circle at bottom left, rgba(201, 164, 111, 0.12), transparent 30%),
        linear-gradient(180deg, var(--bg-1), var(--bg-2));
    }

    .shell {
      width: min(1280px, calc(100vw - 32px));
      margin: 24px auto;
      display: grid;
      grid-template-columns: 320px minmax(0, 1fr);
      gap: 18px;
    }

    .panel,
    .preview {
      border: 1px solid var(--line);
      border-radius: 24px;
      background: linear-gradient(180deg, var(--surface), var(--surface-soft));
      box-shadow: var(--shadow);
      overflow: hidden;
    }

    .panel {
      padding: 22px;
    }

    .eyebrow {
      margin: 0 0 10px;
      font-size: 12px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--accent);
      font-weight: 800;
    }

    h1 {
      margin: 0;
      font-family: "Sora", "Segoe UI", sans-serif;
      font-size: 28px;
      line-height: 1.05;
      letter-spacing: -0.03em;
    }

    .copy {
      margin: 14px 0 0;
      color: var(--muted);
      line-height: 1.65;
    }

    .group {
      margin-top: 24px;
      display: grid;
      gap: 10px;
    }

    .group-label {
      font-size: 12px;
      letter-spacing: 0.14em;
      text-transform: uppercase;
      color: var(--muted);
      font-weight: 700;
    }

    .option-grid {
      display: grid;
      gap: 10px;
    }

    .option-link {
      display: block;
      padding: 14px 16px;
      border-radius: 18px;
      border: 1px solid var(--line);
      background: rgba(255, 255, 255, 0.02);
      color: var(--text);
      text-decoration: none;
      font-weight: 700;
    }

    .option-link:hover {
      border-color: rgba(201, 164, 111, 0.4);
      background: var(--accent-soft);
    }

    .option-link.active {
      border-color: rgba(201, 164, 111, 0.46);
      background: var(--accent-soft);
    }

    .option-note {
      display: block;
      margin-top: 6px;
      color: var(--muted);
      font-size: 14px;
      font-weight: 500;
    }

    .actions {
      margin-top: 24px;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }

    .button {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 44px;
      padding: 0 16px;
      border-radius: 999px;
      background: linear-gradient(180deg, var(--button), var(--button-strong));
      color: #fff;
      text-decoration: none;
      font-weight: 800;
    }

    .button.secondary {
      background: transparent;
      border: 1px solid var(--line);
      color: var(--text);
    }

    .preview-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 18px 22px;
      border-bottom: 1px solid var(--line);
    }

    .preview-meta {
      color: var(--muted);
      font-size: 14px;
    }

    iframe {
      display: block;
      width: 100%;
      min-height: calc(100vh - 140px);
      border: 0;
      background: #0b1727;
    }

    @media (max-width: 980px) {
      .shell {
        grid-template-columns: 1fr;
      }

      iframe {
        min-height: 70vh;
      }
    }
  </style>
</head>
<body>
  <div class="shell">
    <aside class="panel">
      <p class="eyebrow">Email preview</p>
      <h1>Continental ID mailer</h1>
      <p class="copy">Open the actual rendered HTML for each account email and switch themes to see how it will look before sending anything.</p>

      <section class="group" aria-label="Email types">
        <div class="group-label">Email type</div>
        <div class="option-grid">
          ${typeOptions
            .map(
              ([value, label]) => `
                <a class="option-link ${selectedType === value ? 'active' : ''}" href="${previewBasePath}?type=${encodeURIComponent(value)}&theme=${encodeURIComponent(requestedTheme)}">
                  ${label}
                  <span class="option-note">Preview the ${label.toLowerCase()} template.</span>
                </a>
              `
            )
            .join('')}
        </div>
      </section>

      <section class="group" aria-label="Themes">
        <div class="group-label">Theme</div>
        <div class="option-grid">
          ${themeOptions
            .map(
              (value) => `
                <a class="option-link ${requestedTheme === value ? 'active' : ''}" href="${previewBasePath}?type=${encodeURIComponent(selectedType)}&theme=${encodeURIComponent(value)}">
                  ${value.charAt(0).toUpperCase()}${value.slice(1)}
                  <span class="option-note">Use the ${value} dashboard palette.</span>
                </a>
              `
            )
            .join('')}
        </div>
      </section>

      <div class="actions">
        <a class="button" href="${previewSrc}" target="_blank" rel="noreferrer">Open raw HTML</a>
        <a class="button secondary" href="${previewBasePath}">Reset preview</a>
      </div>
    </aside>

    <section class="preview">
      <div class="preview-head">
        <strong>${escapeHtml(typeOptions.find(([value]) => value === selectedType)?.[1] || 'Verification')}</strong>
        <span class="preview-meta">Theme: ${escapeHtml(requestedTheme)}</span>
      </div>
      <iframe title="Email preview" src="${previewSrc}"></iframe>
    </section>
  </div>
</body>
</html>`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(page);
};

const sanitizeAuditMeta = (value = {}) => {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return {};
  }

  const next = {};

  for (const [rawKey, rawValue] of Object.entries(value).slice(0, 10)) {
    const key = sanitizeText(rawKey, 40);
    if (!key) continue;
    if (rawValue === undefined || rawValue === null || rawValue === '') continue;

    if (typeof rawValue === 'number' || typeof rawValue === 'boolean') {
      next[key] = rawValue;
      continue;
    }

    next[key] = sanitizeText(rawValue, 160);
  }

  return next;
};

const serializeAuditEvent = (event = {}) => ({
  at: event?.at || null,
  type: sanitizeText(event?.type, 60),
  message: sanitizeText(event?.message, 240),
  ip: sanitizeText(event?.ip, 80),
  userAgent: sanitizeText(event?.userAgent, 300),
  meta: sanitizeAuditMeta(event?.meta),
});

const appendAuditEvent = (user, req, type, message, meta = {}) => {
  if (!user) return;

  const events = Array.isArray(user.auditEvents)
    ? user.auditEvents.map((event) => serializeAuditEvent(event)).filter((event) => event.type)
    : [];

  events.push(
    serializeAuditEvent({
      at: new Date(),
      type,
      message,
      ip: parseClientIp(req),
      userAgent: parseUserAgent(req),
      meta,
    })
  );

  user.auditEvents = events.slice(-MAX_AUDIT_EVENTS);
};

const normalizeDeviceFingerprintSource = (userAgent = '') =>
  sanitizeText(String(userAgent || '').toLowerCase().replace(/\/\d+(?:\.\d+)*/g, ''), 260) ||
  'unknown-device';

const sanitizeDeviceId = (value) => sanitizeText(value, 120);

const readPersistedDeviceId = (req) => {
  const token = sanitizeText(req.cookies?.[DEVICE_ID_COOKIE], 4000);
  if (!token) return '';

  try {
    const payload = verifyTypedJwt({
      token,
      secret: process.env.JWT_SECRET,
      audience: DEVICE_COOKIE_AUDIENCE,
      type: 'device_cookie',
    });
    const userAgentFamily = normalizeDeviceFingerprintSource(parseUserAgent(req));
    if (sanitizeText(payload?.ua, 260) !== userAgentFamily) {
      return '';
    }
    return sanitizeDeviceId(payload?.did);
  } catch {
    return '';
  }
};

const createDeviceId = () => crypto.randomUUID();

const buildDeviceFingerprint = (deviceId = '', userAgent = '') =>
  hashToken(`${sanitizeDeviceId(deviceId) || 'legacy-device'}:${normalizeDeviceFingerprintSource(userAgent)}`);

const rememberKnownDevice = (user, req, requestedLabel = '', deviceId = '') => {
  const userAgent = parseUserAgent(req);
  const fingerprint = buildDeviceFingerprint(deviceId, userAgent);
  const label = buildSessionLabel(requestedLabel, userAgent);
  const now = new Date();
  const ip = parseClientIp(req);
  const devices = Array.isArray(user.knownDevices) ? [...user.knownDevices] : [];
  const existingIndex = devices.findIndex(
    (device) => sanitizeText(device?.fingerprint, 128) === fingerprint
  );

  const nextDevice = {
    fingerprint,
    label,
    trusted: false,
    firstSeenAt: now,
    lastSeenAt: now,
    lastIp: ip,
    userAgent,
  };

  if (existingIndex >= 0) {
    const currentDevice = devices[existingIndex];
    devices[existingIndex] = {
      ...currentDevice,
      fingerprint,
      label: sanitizeText(currentDevice?.label || label, 60) || label,
      trusted: Boolean(currentDevice?.trusted),
      lastSeenAt: now,
      lastIp: ip,
      userAgent,
    };
  } else {
    devices.push(nextDevice);
  }

  devices.sort((left, right) => {
    const leftTime = new Date(left?.lastSeenAt || 0).getTime();
    const rightTime = new Date(right?.lastSeenAt || 0).getTime();
    return leftTime - rightTime;
  });

  while (devices.length > MAX_KNOWN_DEVICES) {
    devices.shift();
  }

  user.knownDevices = devices;

  return {
    fingerprint,
    isNewDevice: existingIndex < 0,
    device:
      devices.find((device) => sanitizeText(device?.fingerprint, 128) === fingerprint) || nextDevice,
  };
};

const normalizePublicProfilePreferences = (incoming = {}, current = DEFAULT_PUBLIC_PROFILE) => {
  const source = current || DEFAULT_PUBLIC_PROFILE;

  return {
    headline: hasOwn(incoming, 'headline') ? Boolean(incoming.headline) : Boolean(source.headline),
    role: hasOwn(incoming, 'role') ? Boolean(incoming.role) : Boolean(source.role),
    organization: hasOwn(incoming, 'organization')
      ? Boolean(incoming.organization)
      : Boolean(source.organization),
    bio: hasOwn(incoming, 'bio') ? Boolean(incoming.bio) : Boolean(source.bio),
    currentFocus: hasOwn(incoming, 'currentFocus')
      ? Boolean(incoming.currentFocus)
      : Boolean(source.currentFocus),
    focusAreas: hasOwn(incoming, 'focusAreas')
      ? Boolean(incoming.focusAreas)
      : Boolean(source.focusAreas),
    pronouns: hasOwn(incoming, 'pronouns') ? Boolean(incoming.pronouns) : Boolean(source.pronouns),
    location: hasOwn(incoming, 'location') ? Boolean(incoming.location) : Boolean(source.location),
    website: hasOwn(incoming, 'website') ? Boolean(incoming.website) : Boolean(source.website),
    timezone: hasOwn(incoming, 'timezone') ? Boolean(incoming.timezone) : Boolean(source.timezone),
    language: hasOwn(incoming, 'language') ? Boolean(incoming.language) : Boolean(source.language),
    linkedAccounts: hasOwn(incoming, 'linkedAccounts')
      ? Boolean(incoming.linkedAccounts)
      : Boolean(source.linkedAccounts),
    memberSince: hasOwn(incoming, 'memberSince') ? Boolean(incoming.memberSince) : Boolean(source.memberSince),
  };
};

const getMfaState = (user) => ({
  enabled: Boolean(user?.security?.mfa?.enabled && decryptMfaSecret(user?.security?.mfa?.secret)),
  hasPendingSetup: Boolean(user?.security?.mfa?.pendingSecret),
  enrolledAt: user?.security?.mfa?.enrolledAt || null,
  lastUsedAt: user?.security?.mfa?.lastUsedAt || null,
  backupCodesRemaining: Array.isArray(user?.security?.mfa?.backupCodes) ? user.security.mfa.backupCodes.length : 0,
});

const getStoredPasskeys = (user) =>
  Array.isArray(user?.security?.passkeys) ? user.security.passkeys : [];

const sanitizePasskeyName = (value, fallback = '') =>
  sanitizeText(value, 80) || sanitizeText(fallback, 80) || 'Passkey';

const buildDefaultPasskeyName = (req, existingCount = 0) => {
  const base = `${buildSessionLabel('', parseUserAgent(req))} passkey`;
  return existingCount > 0 ? `${base} ${existingCount + 1}` : base;
};

const serializePasskey = (passkey = {}) => ({
  credentialId: sanitizeText(passkey?.credentialId, 512),
  name: sanitizePasskeyName(passkey?.name, 'Passkey'),
  createdAt: passkey?.createdAt || null,
  lastUsedAt: passkey?.lastUsedAt || null,
  transports: Array.isArray(passkey?.transports)
    ? passkey.transports.map((transport) => sanitizeText(transport, 24)).filter(Boolean)
    : [],
  deviceType:
    sanitizeText(passkey?.deviceType, 40) === 'multiDevice' ? 'multiDevice' : 'singleDevice',
  backedUp: Boolean(passkey?.backedUp),
});

const getPasskeyState = (user) => {
  const passkeys = getStoredPasskeys(user)
    .map((passkey) => serializePasskey(passkey))
    .sort((left, right) => {
      const leftTs = new Date(left.lastUsedAt || left.createdAt || 0).getTime();
      const rightTs = new Date(right.lastUsedAt || right.createdAt || 0).getTime();
      return rightTs - leftTs;
    });

  return {
    count: passkeys.length,
    lastUsedAt: passkeys.reduce((latest, passkey) => {
      const timestamp = new Date(passkey.lastUsedAt || 0).getTime();
      if (Number.isNaN(timestamp) || timestamp <= latest) return latest;
      return timestamp;
    }, 0)
      ? new Date(
          passkeys.reduce((latest, passkey) => {
            const timestamp = new Date(passkey.lastUsedAt || 0).getTime();
            return Number.isNaN(timestamp) || timestamp <= latest ? latest : timestamp;
          }, 0)
        ).toISOString()
      : null,
    items: passkeys,
  };
};

const findStoredPasskey = (user, credentialId) =>
  getStoredPasskeys(user).find(
    (passkey) => sanitizeText(passkey?.credentialId, 512) === sanitizeText(credentialId, 512)
  ) || null;

const getWebAuthnUserId = (user) => `continental-id:${toObjectIdString(user?._id)}`;

const sanitizeMfaCode = (value) => String(value || '').replace(/\s+/g, '').slice(0, 8);
const sanitizeBackupCode = (value) =>
  String(value || '')
    .trim()
    .toUpperCase()
    .replace(/[^A-Z0-9-]/g, '')
    .slice(0, 24);

const hashBackupCodes = (codes = []) =>
  codes.map((code) => hashBackupCodeForStorage(sanitizeBackupCode(code))).filter(Boolean);

const getStoredMfaSecret = (user) => decryptMfaSecret(user?.security?.mfa?.secret);
const getPendingMfaSecret = (user) => decryptMfaSecret(user?.security?.mfa?.pendingSecret);
const isMfaEnabledForUser = (user) =>
  Boolean(user?.security?.mfa?.enabled && getStoredMfaSecret(user));

const buildMfaSetupPayload = async (user, secret, backupCodes) => {
  const otpAuthUrl = buildOtpAuthUrl({
    secret,
    accountName: sanitizeText(user?.email || user?.username || user?._id, 120) || 'user',
  });

  return {
    secret,
    otpAuthUrl,
    qrCodeDataUrl: await buildOtpAuthQrDataUrl(otpAuthUrl),
    backupCodes,
  };
};

const clearStoredMfaState = (user) => {
  if (!user?.security?.mfa) return;

  user.security.mfa.enabled = false;
  user.security.mfa.secret = '';
  user.security.mfa.backupCodes = [];
  user.security.mfa.pendingSecret = '';
  user.security.mfa.pendingBackupCodes = [];
  user.security.mfa.pendingCreatedAt = null;
  user.security.mfa.enrolledAt = null;
  user.security.mfa.lastUsedAt = null;
};

const verifyBackupCode = (user, backupCode) => {
  const normalized = sanitizeBackupCode(backupCode);
  if (!normalized) {
    return { ok: false };
  }

  const storedCodes = Array.isArray(user?.security?.mfa?.backupCodes) ? user.security.mfa.backupCodes : [];
  const matchIndex = storedCodes.findIndex((value) =>
    verifyStoredBackupCodeHash(value, normalized)
  );
  if (matchIndex < 0) {
    return { ok: false };
  }

  user.security.mfa.backupCodes.splice(matchIndex, 1);
  return { ok: true, usedBackupCode: normalized };
};

const verifyMfaAttempt = (user, { mfaCode = '', backupCode = '' } = {}) => {
  const secret = getStoredMfaSecret(user);
  const normalizedCode = sanitizeMfaCode(mfaCode);

  if (normalizedCode && verifyTotp({ secret, token: normalizedCode })) {
    return { ok: true, method: 'totp' };
  }

  const backupResult = verifyBackupCode(user, backupCode);
  if (backupResult.ok) {
    return { ok: true, method: 'backup_code', usedBackupCode: backupResult.usedBackupCode };
  }

  return { ok: false };
};

const buildSessionLabel = (requestedLabel, userAgent = '') => {
  const explicit = sanitizeText(requestedLabel, 60);
  if (explicit) return explicit;

  const ua = sanitizeText(userAgent, 260).toLowerCase();
  if (!ua) return 'Browser session';

  if (ua.includes('iphone') || ua.includes('ipad') || ua.includes('ios')) return 'iOS browser';
  if (ua.includes('android')) return 'Android browser';
  if (ua.includes('firefox')) return 'Firefox';
  if (ua.includes('edg/')) return 'Edge';
  if (ua.includes('chrome')) return 'Chrome';
  if (ua.includes('safari')) return 'Safari';
  return 'Browser session';
};

const sanitizeWebsite = (value, fallback = '') => {
  const raw = sanitizeText(value, 240);
  if (!raw) return '';

  const withProtocol = /^https?:\/\//i.test(raw) ? raw : `https://${raw}`;

  try {
    const parsed = new URL(withProtocol);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return fallback;
    }
    return parsed.toString();
  } catch {
    return fallback;
  }
};

const sanitizeAvatar = (value, fallback = '') => {
  const raw = String(value || '').trim();
  if (!raw) return '';

  if (raw.length <= AVATAR_DATA_URL_MAX_LENGTH && AVATAR_DATA_URL_PATTERN.test(raw)) {
    return raw;
  }

  const normalized = sanitizeText(raw, 2400);
  if (!normalized) return '';

  const withProtocol = /^https?:\/\//i.test(normalized) ? normalized : `https://${normalized}`;

  try {
    const parsed = new URL(withProtocol);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return fallback;
    }
    return parsed.toString();
  } catch {
    return fallback;
  }
};

const deriveAvatarKind = (avatar = '') => {
  const value = String(avatar || '').trim();
  if (!value) return '';
  return AVATAR_DATA_URL_PATTERN.test(value) ? 'upload' : 'url';
};

const sanitizeAvatarKind = (value, avatar = '') => {
  const normalized = sanitizeText(value, 24).toLowerCase();
  if (['upload', 'url', 'oauth'].includes(normalized)) {
    return normalized;
  }
  return deriveAvatarKind(avatar);
};

const sanitizeAvatarMimeType = (value) => {
  const normalized = sanitizeText(value, 40).toLowerCase();
  return /^image\/[-+.\w]+$/.test(normalized) ? normalized : '';
};

const sanitizeAvatarDimension = (value) =>
  Math.max(0, Math.min(4096, Math.round(Number(value) || 0)));

const sanitizeAvatarUpdatedAt = (value) => {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

const normalizeAvatarMeta = (value = {}, avatar = '') => {
  const source = value && typeof value === 'object' ? value : {};
  const kind = sanitizeAvatarKind(source.kind, avatar);
  return {
    kind: avatar ? kind : '',
    mimeType: avatar ? sanitizeAvatarMimeType(source.mimeType) : '',
    width: avatar ? sanitizeAvatarDimension(source.width) : 0,
    height: avatar ? sanitizeAvatarDimension(source.height) : 0,
    updatedAt: avatar ? sanitizeAvatarUpdatedAt(source.updatedAt) : null,
  };
};

const sanitizeHeadline = (value, fallback = '') => sanitizeText(value, 100) || fallback;
const sanitizeRole = (value, fallback = '') => sanitizeText(value, 100) || fallback;
const sanitizeOrganization = (value, fallback = '') => sanitizeText(value, 100) || fallback;
const sanitizeCurrentFocus = (value, fallback = '') => sanitizeText(value, 160) || fallback;
const sanitizePronouns = (value, fallback = '') => sanitizeText(value, 40) || fallback;
const sanitizeFocusAreas = (value = []) => {
  const rawValues = Array.isArray(value) ? value : String(value || '').split(/[,\n]/);
  const next = [];
  const seen = new Set();

  for (const entry of rawValues) {
    const cleaned = sanitizeText(entry, 32);
    if (!cleaned) continue;

    const dedupeKey = cleaned.toLowerCase();
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    next.push(cleaned);

    if (next.length >= MAX_FOCUS_AREAS) {
      break;
    }
  }

  return next;
};

const sanitizeLanguage = (value, fallback = 'en') => {
  const raw = sanitizeText(value, 32).replace('_', '-');
  if (!raw) return fallback;
  if (/^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$/.test(raw)) return raw;
  return fallback;
};

const sanitizeTimezone = (value, fallback = 'UTC') => {
  const candidate = sanitizeText(value, 80);
  if (!candidate) return fallback;

  try {
    Intl.DateTimeFormat(undefined, { timeZone: candidate });
    return candidate;
  } catch {
    return fallback;
  }
};

const normalizeProfile = (incoming = {}, current = {}) => {
  const currentProfile = current || {};
  const avatar = hasOwn(incoming, 'avatar')
    ? sanitizeAvatar(incoming.avatar, sanitizeAvatar(currentProfile.avatar, ''))
    : sanitizeAvatar(currentProfile.avatar, '');

  return {
    avatar,
    avatarMeta: hasOwn(incoming, 'avatarMeta')
      ? normalizeAvatarMeta(incoming.avatarMeta, avatar)
      : normalizeAvatarMeta(currentProfile.avatarMeta, avatar),
    headline: hasOwn(incoming, 'headline')
      ? sanitizeHeadline(incoming.headline, '')
      : sanitizeHeadline(currentProfile.headline, ''),
    role: hasOwn(incoming, 'role')
      ? sanitizeRole(incoming.role, '')
      : sanitizeRole(currentProfile.role, ''),
    organization: hasOwn(incoming, 'organization')
      ? sanitizeOrganization(incoming.organization, '')
      : sanitizeOrganization(currentProfile.organization, ''),
    currentFocus: hasOwn(incoming, 'currentFocus')
      ? sanitizeCurrentFocus(incoming.currentFocus, '')
      : sanitizeCurrentFocus(currentProfile.currentFocus, ''),
    focusAreas: hasOwn(incoming, 'focusAreas')
      ? sanitizeFocusAreas(incoming.focusAreas)
      : sanitizeFocusAreas(currentProfile.focusAreas),
    pronouns: hasOwn(incoming, 'pronouns')
      ? sanitizePronouns(incoming.pronouns, '')
      : sanitizePronouns(currentProfile.pronouns, ''),
    bio: hasOwn(incoming, 'bio') ? sanitizeText(incoming.bio, 320) : sanitizeText(currentProfile.bio, 320),
    location: hasOwn(incoming, 'location')
      ? sanitizeText(incoming.location, 120)
      : sanitizeText(currentProfile.location, 120),
    website: hasOwn(incoming, 'website')
      ? sanitizeWebsite(incoming.website, sanitizeText(currentProfile.website, 240))
      : sanitizeWebsite(currentProfile.website, ''),
    timezone: hasOwn(incoming, 'timezone')
      ? sanitizeTimezone(incoming.timezone, sanitizeTimezone(currentProfile.timezone, 'UTC'))
      : sanitizeTimezone(currentProfile.timezone, 'UTC'),
    language: hasOwn(incoming, 'language')
      ? sanitizeLanguage(incoming.language, sanitizeLanguage(currentProfile.language, 'en'))
      : sanitizeLanguage(currentProfile.language, 'en'),
  };
};

const normalizeLinkedAccounts = (input = {}, current = {}) => {
  const next = {};

  for (const provider of LINKED_PROVIDERS) {
    if (hasOwn(input, provider)) {
      next[provider] = sanitizeText(input[provider], 120);
      continue;
    }
    next[provider] = sanitizeText(current?.[provider], 120);
  }

  return next;
};

const normalizeTheme = (value, fallback = 'graphite') => {
  const candidate = sanitizeText(value, 20).toLowerCase();
  if (ALLOWED_THEMES.has(candidate)) return candidate;
  return fallback;
};

const normalizeDensity = (value, fallback = 'comfortable') => {
  const candidate = sanitizeText(value, 20).toLowerCase();
  if (ALLOWED_DENSITIES.has(candidate)) return candidate;
  return fallback;
};

const normalizeAppearance = (incoming = {}, current = {}) => {
  const source = current || {};
  const next = {
    theme: hasOwn(incoming, 'theme')
      ? normalizeTheme(incoming.theme, normalizeTheme(source.theme || DEFAULT_APPEARANCE.theme))
      : normalizeTheme(source.theme || DEFAULT_APPEARANCE.theme),
    compactMode: hasOwn(incoming, 'compactMode')
      ? Boolean(incoming.compactMode)
      : Boolean(hasOwn(source, 'compactMode') ? source.compactMode : DEFAULT_APPEARANCE.compactMode),
    reducedMotion: hasOwn(incoming, 'reducedMotion')
      ? Boolean(incoming.reducedMotion)
      : Boolean(hasOwn(source, 'reducedMotion') ? source.reducedMotion : DEFAULT_APPEARANCE.reducedMotion),
    highContrast: hasOwn(incoming, 'highContrast')
      ? Boolean(incoming.highContrast)
      : Boolean(hasOwn(source, 'highContrast') ? source.highContrast : DEFAULT_APPEARANCE.highContrast),
    dashboardDensity: hasOwn(incoming, 'dashboardDensity')
      ? normalizeDensity(
          incoming.dashboardDensity,
          normalizeDensity(source.dashboardDensity || DEFAULT_APPEARANCE.dashboardDensity)
        )
      : normalizeDensity(source.dashboardDensity || DEFAULT_APPEARANCE.dashboardDensity),
  };

  return next;
};

const normalizePreferences = (incoming = {}, current = {}) => {
  const source = current || {};
  const sourceNotifications = source.notifications || DEFAULT_NOTIFICATIONS;
  const incomingNotifications = incoming.notifications || {};

  return {
    profilePublic: hasOwn(incoming, 'profilePublic')
      ? Boolean(incoming.profilePublic)
      : Boolean(hasOwn(source, 'profilePublic') ? source.profilePublic : true),
    searchable: hasOwn(incoming, 'searchable')
      ? Boolean(incoming.searchable)
      : Boolean(hasOwn(source, 'searchable') ? source.searchable : true),
    notifications: {
      email: hasOwn(incomingNotifications, 'email')
        ? Boolean(incomingNotifications.email)
        : Boolean(hasOwn(sourceNotifications, 'email') ? sourceNotifications.email : DEFAULT_NOTIFICATIONS.email),
      sms: hasOwn(incomingNotifications, 'sms')
        ? Boolean(incomingNotifications.sms)
        : Boolean(hasOwn(sourceNotifications, 'sms') ? sourceNotifications.sms : DEFAULT_NOTIFICATIONS.sms),
      push: hasOwn(incomingNotifications, 'push')
        ? Boolean(incomingNotifications.push)
        : Boolean(hasOwn(sourceNotifications, 'push') ? sourceNotifications.push : DEFAULT_NOTIFICATIONS.push),
      weeklyDigest: hasOwn(incomingNotifications, 'weeklyDigest')
        ? Boolean(incomingNotifications.weeklyDigest)
        : Boolean(
            hasOwn(sourceNotifications, 'weeklyDigest')
              ? sourceNotifications.weeklyDigest
              : DEFAULT_NOTIFICATIONS.weeklyDigest
          ),
      security: hasOwn(incomingNotifications, 'security')
        ? Boolean(incomingNotifications.security)
        : Boolean(
            hasOwn(sourceNotifications, 'security')
              ? sourceNotifications.security
              : DEFAULT_NOTIFICATIONS.security
          ),
    },
    appearance: normalizeAppearance(incoming.appearance || {}, source.appearance || DEFAULT_APPEARANCE),
    publicProfile: normalizePublicProfilePreferences(
      incoming.publicProfile || {},
      source.publicProfile || DEFAULT_PUBLIC_PROFILE
    ),
  };
};

const resolveCookieDomain = (req) => {
  const configuredDomain = sanitizeText(process.env.COOKIE_DOMAIN, 255).replace(/^\.+/, '');
  if (configuredDomain) {
    return configuredDomain;
  }

  const requestOrigin = getRequestOrigin(req);
  if (!requestOrigin) return '';

  try {
    const hostname = new URL(requestOrigin).hostname.toLowerCase();
    if (hostname === 'continental-hub.com' || hostname.endsWith('.continental-hub.com')) {
      return 'continental-hub.com';
    }
  } catch {
    return '';
  }

  return '';
};

const buildCookieOptions = (req) => {
  const isSecure = getRequestOrigin(req).startsWith('https://');
  const isCrossSite = isSecure && !isSameSiteRequest(req);
  const domain = resolveCookieDomain(req);

  return {
    httpOnly: true,
    secure: isSecure,
    sameSite: isCrossSite ? 'None' : 'Lax',
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    ...(domain ? { domain } : {}),
  };
};

const buildDeviceCookieOptions = (req) => {
  const cookieOptions = buildCookieOptions(req);
  return {
    httpOnly: true,
    secure: cookieOptions.secure,
    sameSite: cookieOptions.sameSite,
    path: '/',
    maxAge: DEVICE_ID_TTL_MS,
  };
};

const clearRefreshCookie = (res, req) => {
  const cookieOptions = buildCookieOptions(req);
  res.clearCookie('refreshToken', {
    httpOnly: cookieOptions.httpOnly,
    secure: cookieOptions.secure,
    sameSite: cookieOptions.sameSite,
    path: cookieOptions.path,
  });
};

const persistDeviceCookie = (res, req, deviceId = '', userAgent = '') => {
  const did = sanitizeDeviceId(deviceId);
  if (!did) {
    return '';
  }

  const deviceToken = signTypedJwt({
    secret: process.env.JWT_SECRET,
    payload: {
      did,
      ua: normalizeDeviceFingerprintSource(userAgent),
    },
    expiresIn: Math.max(60, Math.floor(DEVICE_ID_TTL_MS / 1000)),
    audience: DEVICE_COOKIE_AUDIENCE,
    type: 'device_cookie',
  });

  res.cookie(DEVICE_ID_COOKIE, deviceToken, buildDeviceCookieOptions(req));
  return did;
};

const ensureDeviceCookie = (res, req) => {
  const userAgent = parseUserAgent(req);
  const existingDeviceId = readPersistedDeviceId(req);
  if (existingDeviceId) {
    persistDeviceCookie(res, req, existingDeviceId, userAgent);
    return existingDeviceId;
  }

  return persistDeviceCookie(res, req, createDeviceId(), userAgent);
};

const buildWebAuthnChallengeCookieOptions = (req) => {
  const cookieOptions = buildCookieOptions(req);
  return {
    httpOnly: true,
    secure: cookieOptions.secure,
    sameSite: cookieOptions.sameSite,
    path: '/api/auth/passkeys',
    maxAge: WEBAUTHN_CHALLENGE_TTL_MS,
  };
};

const clearWebAuthnChallengeCookie = (res, req) => {
  const cookieOptions = buildWebAuthnChallengeCookieOptions(req);
  res.clearCookie(WEBAUTHN_CHALLENGE_COOKIE, {
    httpOnly: cookieOptions.httpOnly,
    secure: cookieOptions.secure,
    sameSite: cookieOptions.sameSite,
    path: cookieOptions.path,
  });
};

const storeWebAuthnChallenge = (res, req, payload) => {
  const challengeToken = signTypedJwt({
    secret: process.env.JWT_SECRET,
    payload,
    expiresIn: Math.max(30, Math.floor(WEBAUTHN_CHALLENGE_TTL_MS / 1000)),
    audience: WEBAUTHN_CHALLENGE_AUDIENCE,
    type: 'webauthn_challenge',
  });

  res.cookie(
    WEBAUTHN_CHALLENGE_COOKIE,
    challengeToken,
    buildWebAuthnChallengeCookieOptions(req)
  );
};

const readWebAuthnChallenge = (req, expectedFlow = '') => {
  const token = sanitizeText(req.cookies?.[WEBAUTHN_CHALLENGE_COOKIE], 4000);
  if (!token) {
    throw createHttpError(400, 'This passkey request expired. Start again.');
  }

  let payload;
  try {
    payload = verifyTypedJwt({
      token,
      secret: process.env.JWT_SECRET,
      audience: WEBAUTHN_CHALLENGE_AUDIENCE,
      type: 'webauthn_challenge',
    });
  } catch {
    throw createHttpError(400, 'This passkey request expired. Start again.');
  }

  if (expectedFlow && payload?.flow !== expectedFlow) {
    throw createHttpError(400, 'This passkey request does not match the expected step.');
  }

  return payload;
};

const signToken = (user, sid) =>
  signTypedJwt({
    secret: process.env.JWT_SECRET,
    payload: {
      userId: toObjectIdString(user._id),
      tokenVersion: user.refreshTokenVersion,
      sid: sanitizeText(sid, 120) || undefined,
    },
    audience: ACCESS_TOKEN_AUDIENCE,
    expiresIn: ACCESS_TOKEN_TTL,
    subject: toObjectIdString(user._id),
    type: 'access_token',
  });

const signRefreshToken = (user, sid, refreshTokenId) =>
  signTypedJwt({
    secret: process.env.REFRESH_TOKEN_SECRET,
    payload: {
      userId: toObjectIdString(user._id),
      tokenVersion: user.refreshTokenVersion,
      sid: sanitizeText(sid, 120) || undefined,
      jti: sanitizeText(refreshTokenId, 120) || undefined,
    },
    audience: REFRESH_TOKEN_AUDIENCE,
    expiresIn: REFRESH_TOKEN_TTL,
    subject: toObjectIdString(user._id),
    type: 'refresh_token',
  });

const appendRecentLogin = (user, req) => {
  const entry = {
    at: new Date(),
    ip: parseClientIp(req),
    userAgent: parseUserAgent(req),
  };
  const cutoffMs = Date.now() - LOGIN_ACTIVITY_RETENTION_DAYS * DAY_MS;
  const day = buildActivityDay(entry.at);

  user.lastLoginAt = entry.at;
  user.lastLoginIp = entry.ip;

  const list = Array.isArray(user.recentLogins)
    ? user.recentLogins.filter((item) => {
        const timestamp = new Date(item?.at || '').getTime();
        return !Number.isNaN(timestamp) && timestamp >= cutoffMs;
      })
    : [];
  list.push(entry);

  user.recentLogins = list.slice(-MAX_RECENT_LOGIN_EVENTS);

  const loginDayCounts = Array.isArray(user.loginDayCounts)
    ? user.loginDayCounts
        .map((item) => ({
          day: buildActivityDay(item?.day),
          count: Math.max(0, Math.trunc(Number(item?.count || 0))),
        }))
        .filter((item) => {
          const dayStart = parseActivityDayStart(item.day);
          return item.day && item.count > 0 && !Number.isNaN(dayStart) && dayStart >= cutoffMs;
        })
    : [];

  const existingDayIndex = loginDayCounts.findIndex((item) => item.day === day);
  if (existingDayIndex >= 0) {
    loginDayCounts[existingDayIndex].count += 1;
  } else if (day) {
    loginDayCounts.push({ day, count: 1 });
  }

  loginDayCounts.sort((a, b) => a.day.localeCompare(b.day));
  user.loginDayCounts = loginDayCounts;
};

const createSessionId = () => crypto.randomUUID();
const createRefreshTokenId = () => crypto.randomUUID();

const upsertRefreshSession = (user, req, sid = '', requestedLabel = '', options = {}) => {
  const sessions = Array.isArray(user.refreshSessions) ? [...user.refreshSessions] : [];
  const sessionId = sanitizeText(sid, 120) || createSessionId();
  const now = new Date();
  const ip = parseClientIp(req);
  const userAgent = parseUserAgent(req);
  const label = buildSessionLabel(requestedLabel, userAgent);
  const deviceFingerprint = sanitizeText(options.deviceFingerprint, 128);
  const currentRefreshTokenId = sanitizeText(options.currentRefreshTokenId, 120);
  const previousRefreshTokenId = sanitizeText(options.previousRefreshTokenId, 120);
  const hasDeviceFingerprint = hasOwn(options, 'deviceFingerprint');
  const hasCurrentRefreshTokenId = hasOwn(options, 'currentRefreshTokenId');
  const hasPreviousRefreshTokenId = hasOwn(options, 'previousRefreshTokenId');
  const hasPreviousRefreshTokenGraceUntil = hasOwn(options, 'previousRefreshTokenGraceUntil');
  const previousRefreshTokenGraceUntil =
    options.previousRefreshTokenGraceUntil instanceof Date
      ? options.previousRefreshTokenGraceUntil
      : options.previousRefreshTokenGraceUntil
        ? new Date(options.previousRefreshTokenGraceUntil)
        : null;

  const existingIndex = sessions.findIndex(
    (session) => sanitizeText(session.sid, 120) === sessionId
  );

  if (existingIndex >= 0) {
    const nextSession = {
      ...sessions[existingIndex],
      sid: sessionId,
      label: label || sessions[existingIndex].label || 'Browser session',
      createdAt: sessions[existingIndex].createdAt || now,
      lastUsedAt: now,
      ip,
      userAgent,
    };

    if (hasDeviceFingerprint) {
      nextSession.deviceFingerprint = deviceFingerprint;
    }
    if (hasCurrentRefreshTokenId) {
      nextSession.currentRefreshTokenId = currentRefreshTokenId;
    }
    if (hasPreviousRefreshTokenId) {
      nextSession.previousRefreshTokenId = previousRefreshTokenId;
    }
    if (hasPreviousRefreshTokenGraceUntil) {
      nextSession.previousRefreshTokenGraceUntil = previousRefreshTokenGraceUntil;
    }

    sessions[existingIndex] = nextSession;
  } else {
    sessions.push({
      sid: sessionId,
      label,
      createdAt: now,
      lastUsedAt: now,
      ip,
      userAgent,
      deviceFingerprint,
      currentRefreshTokenId,
      previousRefreshTokenId,
      previousRefreshTokenGraceUntil,
    });
  }

  sessions.sort((a, b) => {
    const aTime = new Date(a.lastUsedAt || a.createdAt || 0).getTime();
    const bTime = new Date(b.lastUsedAt || b.createdAt || 0).getTime();
    return aTime - bTime;
  });

  while (sessions.length > MAX_ACTIVE_SESSIONS) {
    sessions.shift();
  }

  user.refreshSessions = sessions;
  return sessionId;
};

const findRefreshSession = (user, sid) => {
  const sessionId = sanitizeText(sid, 120);
  if (!sessionId) return null;

  const sessions = Array.isArray(user.refreshSessions) ? user.refreshSessions : [];
  return (
    sessions.find((session) => sanitizeText(session?.sid, 120) === sessionId) || null
  );
};

const buildTokenPair = (user, sid, refreshTokenId) => {
  const accessToken = signToken(user, sid);
  const refreshToken = signRefreshToken(user, sid, refreshTokenId);

  return {
    accessToken,
    refreshToken,
    refreshTokenId: sanitizeText(refreshTokenId, 120),
  };
};

const createTrackedRefreshSession = (user, req, requestedLabel = '', deviceFingerprint = '') => {
  const sid = createSessionId();
  const refreshTokenId = createRefreshTokenId();
  upsertRefreshSession(user, req, sid, requestedLabel, {
    deviceFingerprint,
    currentRefreshTokenId: refreshTokenId,
    previousRefreshTokenId: '',
    previousRefreshTokenGraceUntil: null,
  });

  return {
    sid,
    ...buildTokenPair(user, sid, refreshTokenId),
  };
};

const rotateRefreshSessionToken = (user, req, sid, session, requestedLabel = '') => {
  const nextRefreshTokenId = createRefreshTokenId();
  const currentRefreshTokenId = sanitizeText(session?.currentRefreshTokenId, 120);

  upsertRefreshSession(user, req, sid, requestedLabel, {
    deviceFingerprint: sanitizeText(session?.deviceFingerprint, 128),
    currentRefreshTokenId: nextRefreshTokenId,
    previousRefreshTokenId: currentRefreshTokenId,
    previousRefreshTokenGraceUntil: currentRefreshTokenId
      ? new Date(Date.now() + REFRESH_TOKEN_REPLAY_GRACE_MS)
      : null,
  });

  return buildTokenPair(user, sid, nextRefreshTokenId);
};

const reissueCurrentRefreshSession = (user, req, sid, session, requestedLabel = '') => {
  const currentRefreshTokenId =
    sanitizeText(session?.currentRefreshTokenId, 120) || createRefreshTokenId();

  upsertRefreshSession(user, req, sid, requestedLabel, {
    deviceFingerprint: sanitizeText(session?.deviceFingerprint, 128),
    currentRefreshTokenId,
  });

  return buildTokenPair(user, sid, currentRefreshTokenId);
};

const issueInteractiveSession = async (req, res, user, options = {}) => {
  const {
    deviceLabel = '',
    auditType = 'login',
    auditMessage = '',
    auditMeta = {},
    alertTitle = 'New device sign-in to Continental ID',
    alertHeading = 'New device sign-in detected',
    alertCopy = 'A sign-in from a device we had not seen before was detected on your account.',
    alertDetails = null,
  } = options;

  const deviceId = ensureDeviceCookie(res, req);
  const device = rememberKnownDevice(user, req, deviceLabel, deviceId);
  appendRecentLogin(user, req);
  appendAuditEvent(
    user,
    req,
    auditType,
    auditMessage || (device.isNewDevice ? 'Signed in from a new device.' : 'Signed in.'),
    {
      newDevice: device.isNewDevice,
      ...auditMeta,
    }
  );
  const sessionTokens = createTrackedRefreshSession(user, req, deviceLabel, device.fingerprint);
  await user.save();

  if (device.isNewDevice && shouldSendLoginAlertForDevice(user, device.fingerprint)) {
    await sendSecurityAlertEmail(
      user,
      alertTitle,
      alertHeading,
      alertCopy,
      Array.isArray(alertDetails) && alertDetails.length
        ? alertDetails
        : [
            `Time: ${new Date().toUTCString()}`,
            `IP address: ${parseClientIp(req) || 'Unknown'}`,
            `Device: ${buildSessionLabel(deviceLabel, parseUserAgent(req))}`,
          ],
      {
        trackLoginAlert: true,
        deviceFingerprint: device.fingerprint,
      }
    );
  }

  return {
    user,
    device,
    sessionTokens,
  };
};

const completeInteractiveSignIn = async (res, req, user, options = {}) => {
  const { sessionTokens } = await issueInteractiveSession(req, res, user, options);

  res.cookie('refreshToken', sessionTokens.refreshToken, buildCookieOptions(req));

  return sendUserResponse(res, 200, 'Login successful.', user, {
    ...buildAuthSuccessMeta(req, {
      popup: {
        source: AUTH_POPUP_MESSAGE_SOURCE,
        type: AUTH_POPUP_MESSAGE_TYPE,
      },
      sessionEstablished: true,
    }),
    token: sessionTokens.accessToken,
    accessToken: sessionTokens.accessToken,
    authenticated: true,
  });
};

const removeRefreshSession = (user, sid) => {
  const sessionId = sanitizeText(sid, 120);
  if (!sessionId) return false;

  const sessions = Array.isArray(user.refreshSessions) ? user.refreshSessions : [];
  const next = sessions.filter((session) => sanitizeText(session.sid, 120) !== sessionId);

  if (next.length === sessions.length) {
    return false;
  }

  user.refreshSessions = next;
  return true;
};

const revokeAllSessions = (user, currentSid, exceptCurrent = false) => {
  const sessions = Array.isArray(user.refreshSessions) ? user.refreshSessions : [];

  if (exceptCurrent && currentSid) {
    user.refreshSessions = sessions.filter(
      (session) => sanitizeText(session.sid, 120) === sanitizeText(currentSid, 120)
    );
    return;
  }

  user.refreshSessions = [];
};

const getKnownDeviceMap = (user) =>
  new Map(
    (Array.isArray(user?.knownDevices) ? user.knownDevices : [])
      .map((device) => [sanitizeText(device?.fingerprint, 128), device])
      .filter(([fingerprint]) => fingerprint)
  );

const serializeSession = (session, currentSid = '', knownDevice = null) => {
  const sid = sanitizeText(session?.sid, 120);
  const deviceFirstSeenAt = knownDevice?.firstSeenAt ? new Date(knownDevice.firstSeenAt).getTime() : 0;
  const sessionCreatedAt = session?.createdAt ? new Date(session.createdAt).getTime() : 0;
  const newDevice =
    Boolean(deviceFirstSeenAt && sessionCreatedAt) &&
    Math.abs(deviceFirstSeenAt - sessionCreatedAt) <= NEW_DEVICE_SESSION_WINDOW_MS;
  return {
    sid,
    label: sanitizeText(session?.label, 60) || 'Browser session',
    createdAt: session?.createdAt || null,
    lastUsedAt: session?.lastUsedAt || null,
    ip: sanitizeText(session?.ip, 80),
    userAgent: sanitizeText(session?.userAgent, 300),
    recognized: Boolean(knownDevice),
    newDevice,
    deviceLabel: sanitizeText(knownDevice?.label, 60) || '',
    deviceTrusted: Boolean(knownDevice?.trusted),
    fingerprint: sanitizeText(session?.deviceFingerprint, 128),
    current: Boolean(sid && sid === sanitizeText(currentSid, 120)),
  };
};

const serializeDevice = (device, sessions = [], currentFingerprint = '') => {
  const fingerprint = sanitizeText(device?.fingerprint, 128);
  const relatedSessions = sessions.filter(
    (session) => sanitizeText(session?.deviceFingerprint, 128) === fingerprint
  );

  return {
    fingerprint,
    label: sanitizeText(device?.label, 60) || 'Browser device',
    trusted: Boolean(device?.trusted),
    firstSeenAt: device?.firstSeenAt || null,
    lastSeenAt: device?.lastSeenAt || null,
    lastIp: sanitizeText(device?.lastIp, 80),
    userAgent: sanitizeText(device?.userAgent, 300),
    activeSessions: relatedSessions.length,
    current: Boolean(fingerprint && fingerprint === sanitizeText(currentFingerprint, 128)),
  };
};

const isUsernameTaken = async (username, userId) => {
  const candidate = normalizeUsername(username);
  if (!candidate) return false;

  const query = { username: candidate };
  if (userId) {
    query._id = { $ne: userId };
  }

  return Boolean(await User.exists(query));
};

const assignAvailableUsername = async (user, ...candidates) => {
  for (const candidate of candidates) {
    const normalized = normalizeUsername(candidate);
    if (!normalized || !isValidUsername(normalized) || containsBlockedNameTerm(normalized)) {
      continue;
    }

    if (!(await isUsernameTaken(normalized, user?._id))) {
      user.username = normalized;
      return normalized;
    }
  }

  await ensureStoredUsername(user);
  return getDisplayableUsername(user);
};

const getOauthIdentityUsernameCandidates = (provider, identityProfile = {}) => {
  const normalizedProvider = sanitizeText(provider, 40).toLowerCase();
  const emailLocalPart = sanitizeText(
    normalizeEmail(identityProfile.email).split('@')[0],
    60
  );

  return [
    sanitizeText(identityProfile.username, 120),
    emailLocalPart,
    sanitizeText(identityProfile.displayName, 60),
    `${normalizedProvider}${String(identityProfile.providerUserId || '').slice(-6)}`,
    `user${crypto.randomBytes(3).toString('hex')}`,
  ];
};

const getOauthLinkedAccountAutofillValue = (provider, identityProfile = {}) => {
  const normalizedProvider = sanitizeText(provider, 40).toLowerCase();
  if (
    normalizedProvider === OAUTH_PROVIDER_GITHUB ||
    normalizedProvider === OAUTH_PROVIDER_DISCORD
  ) {
    return sanitizeText(identityProfile.username, 120);
  }

  return '';
};

const applyUsernameChange = async (user, username) => {
  const normalized = normalizeUsername(username);

  if (!normalized) {
    return ensureStoredUsername(user);
  }

  if (!isValidUsername(normalized)) {
    throw createHttpError(400, USERNAME_VALIDATION_MESSAGE);
  }

  if (containsBlockedNameTerm(normalized)) {
    throw createHttpError(400, USERNAME_MODERATION_MESSAGE);
  }

  const taken = await isUsernameTaken(normalized, user?._id);
  if (taken) {
    throw createHttpError(409, 'Username is already in use.');
  }

  if (user.username !== normalized) {
    user.username = normalized;
    return true;
  }

  return false;
};

const profileCompletion = (user) => {
  const focusAreas = sanitizeFocusAreas(user?.profile?.focusAreas);
  const fields = [
    getDisplayableUsername(user),
    sanitizeText(user.displayName, 60),
    sanitizeText(user.email, 120),
    sanitizeAvatar(user.profile?.avatar, ''),
    sanitizeHeadline(user.profile?.headline, ''),
    sanitizeRole(user.profile?.role, '') || sanitizeOrganization(user.profile?.organization, ''),
    sanitizeText(user.profile?.bio, 320),
    sanitizeCurrentFocus(user.profile?.currentFocus, '') || (focusAreas.length ? 'focus-areas' : ''),
    sanitizeText(user.profile?.location, 120),
    sanitizeText(user.profile?.website, 240),
    sanitizeText(user.profile?.timezone, 80),
    sanitizeText(user.profile?.language, 32),
  ];

  const filled = fields.filter(Boolean).length;
  return Math.round((filled / fields.length) * 100);
};

const getDaysSince = (value) => {
  const timestamp = new Date(value || 0).getTime();
  if (!timestamp) return null;

  const diff = Date.now() - timestamp;
  if (Number.isNaN(diff) || diff < 0) return 0;
  return Math.floor(diff / DAY_MS);
};

const buildMigrationPayload = (user) => {
  const accountAgeDays = getDaysSince(user?.createdAt) || 0;
  const inactiveDays = getDaysSince(user?.lastLoginAt);
  const passwordAgeDays = getDaysSince(user?.security?.passwordChangedAt);
  const activeSessions = Array.isArray(user?.refreshSessions) ? user.refreshSessions.length : 0;
  const hasMfa = Boolean(user?.security?.mfa?.enabled);
  const passkeyCount = Number(user?.security?.passkeys?.length || 0);
  const knownDevices = Array.isArray(user?.knownDevices) ? user.knownDevices.length : 0;
  const isReturningAccount =
    accountAgeDays >= RETURNING_ACCOUNT_INACTIVE_DAYS &&
    (
      inactiveDays === null ||
      inactiveDays >= RETURNING_ACCOUNT_INACTIVE_DAYS ||
      (!passwordAgeDays && knownDevices === 0)
    );
  const shouldResetPassword =
    isReturningAccount &&
    (passwordAgeDays === null || passwordAgeDays >= RETURNING_ACCOUNT_PASSWORD_REVIEW_DAYS);

  return {
    suggested: isReturningAccount,
    inactiveDays,
    accountAgeDays,
    shouldReviewProfile: profileCompletion(user) < 80,
    shouldVerifyEmail: !user?.isVerified,
    shouldResetPassword,
    shouldEnableMfa: !hasMfa,
    shouldAddPasskey: passkeyCount === 0,
    shouldReviewSessions: activeSessions > 1,
  };
};

const buildUserPayload = (user) => {
  const linkedAccounts = {};
  for (const provider of LINKED_PROVIDERS) {
    linkedAccounts[provider] = sanitizeText(user.linkedAccounts?.[provider] || '', 120);
  }
  const oauthProviders = buildOauthProvidersState(user);
  const activitySummary = buildActivitySummary(
    Array.isArray(user.recentLogins) ? user.recentLogins : [],
    Array.isArray(user.loginDayCounts) ? user.loginDayCounts : []
  );
  const authority = buildAuthorityPayload(user);

  return {
    userId: toObjectIdString(user._id),
    continentalId: toObjectIdString(user._id),
    email: user.email,
    username: getDisplayableUsername(user),
    handle: `@${getDisplayableUsername(user)}`,
    displayName: user.displayName || 'User',
    isVerified: Boolean(user.isVerified),
    createdAt: user.createdAt || null,
    updatedAt: user.updatedAt || null,
    lastLoginAt: user.lastLoginAt || null,
    lastLoginIp: user.lastLoginIp || null,
    recentLogins: Array.isArray(user.recentLogins)
      ? user.recentLogins.slice(-RECENT_LOGIN_RESPONSE_LIMIT).reverse()
      : [],
    auditEvents: Array.isArray(user.auditEvents)
      ? user.auditEvents.slice(-MAX_AUDIT_EVENTS).reverse().map((event) => serializeAuditEvent(event))
      : [],
    activitySummary,
    profile: {
      avatar: sanitizeAvatar(user.profile?.avatar, ''),
      avatarMeta: normalizeAvatarMeta(user.profile?.avatarMeta, user.profile?.avatar),
      headline: sanitizeHeadline(user.profile?.headline, ''),
      role: sanitizeRole(user.profile?.role, ''),
      organization: sanitizeOrganization(user.profile?.organization, ''),
      currentFocus: sanitizeCurrentFocus(user.profile?.currentFocus, ''),
      focusAreas: sanitizeFocusAreas(user.profile?.focusAreas),
      pronouns: sanitizePronouns(user.profile?.pronouns, ''),
      bio: sanitizeText(user.profile?.bio, 320),
      location: sanitizeText(user.profile?.location, 120),
      website: sanitizeText(user.profile?.website, 240),
      timezone: sanitizeTimezone(user.profile?.timezone, 'UTC'),
      language: sanitizeLanguage(user.profile?.language, 'en'),
      completion: profileCompletion(user),
    },
    linkedAccounts,
    oauthProviders,
    vanguard: buildVanguardAccountState(user),
    authority,
    preferences: {
      profilePublic: Boolean(
        hasOwn(user.preferences || {}, 'profilePublic') ? user.preferences?.profilePublic : true
      ),
      searchable: Boolean(hasOwn(user.preferences || {}, 'searchable') ? user.preferences?.searchable : true),
      notifications: {
        email: Boolean(
          hasOwn(user.preferences?.notifications || {}, 'email')
            ? user.preferences?.notifications?.email
            : DEFAULT_NOTIFICATIONS.email
        ),
        sms: Boolean(
          hasOwn(user.preferences?.notifications || {}, 'sms')
            ? user.preferences?.notifications?.sms
            : DEFAULT_NOTIFICATIONS.sms
        ),
        push: Boolean(
          hasOwn(user.preferences?.notifications || {}, 'push')
            ? user.preferences?.notifications?.push
            : DEFAULT_NOTIFICATIONS.push
        ),
        weeklyDigest: Boolean(
          hasOwn(user.preferences?.notifications || {}, 'weeklyDigest')
            ? user.preferences?.notifications?.weeklyDigest
            : DEFAULT_NOTIFICATIONS.weeklyDigest
        ),
        security: Boolean(
          hasOwn(user.preferences?.notifications || {}, 'security')
            ? user.preferences?.notifications?.security
            : DEFAULT_NOTIFICATIONS.security
        ),
      },
      appearance: {
        theme: normalizeTheme(user.preferences?.appearance?.theme || DEFAULT_APPEARANCE.theme),
        compactMode: Boolean(
          hasOwn(user.preferences?.appearance || {}, 'compactMode')
            ? user.preferences?.appearance?.compactMode
            : DEFAULT_APPEARANCE.compactMode
        ),
        reducedMotion: Boolean(
          hasOwn(user.preferences?.appearance || {}, 'reducedMotion')
            ? user.preferences?.appearance?.reducedMotion
            : DEFAULT_APPEARANCE.reducedMotion
        ),
        highContrast: Boolean(
          hasOwn(user.preferences?.appearance || {}, 'highContrast')
            ? user.preferences?.appearance?.highContrast
            : DEFAULT_APPEARANCE.highContrast
        ),
        dashboardDensity: normalizeDensity(
          user.preferences?.appearance?.dashboardDensity || DEFAULT_APPEARANCE.dashboardDensity
        ),
      },
      publicProfile: normalizePublicProfilePreferences(
        user.preferences?.publicProfile || {},
        DEFAULT_PUBLIC_PROFILE
      ),
    },
    security: {
      loginAlerts: Boolean(hasOwn(user.security || {}, 'loginAlerts') ? user.security?.loginAlerts : true),
      passwordChangedAt: user.security?.passwordChangedAt || null,
      activeSessions: Array.isArray(user.refreshSessions) ? user.refreshSessions.length : 0,
      knownDevices: Array.isArray(user.knownDevices) ? user.knownDevices.length : 0,
      mfa: getMfaState(user),
      passkeys: getPasskeyState(user),
    },
    migration: buildMigrationPayload(user),
  };
};

const buildOwnerUserSummary = (user) => {
  const authority = buildAuthorityPayload(user);
  const passkeys = getPasskeyState(user);
  const mfa = getMfaState(user);

  return {
    userId: toObjectIdString(user?._id),
    continentalId: toObjectIdString(user?._id),
    email: sanitizeText(user?.email, 320),
    username: getDisplayableUsername(user),
    handle: `@${getDisplayableUsername(user)}`,
    displayName: sanitizeDisplayName(user?.displayName, user?.email),
    isVerified: Boolean(user?.isVerified),
    createdAt: user?.createdAt || null,
    updatedAt: user?.updatedAt || null,
    lastLoginAt: user?.lastLoginAt || null,
    lastLoginIp: sanitizeText(user?.lastLoginIp, 80),
    authority,
    profile: {
      headline: sanitizeHeadline(user?.profile?.headline, ''),
      role: sanitizeRole(user?.profile?.role, ''),
      organization: sanitizeOrganization(user?.profile?.organization, ''),
      location: sanitizeText(user?.profile?.location, 120),
      completion: profileCompletion(user),
    },
    preferences: {
      profilePublic: Boolean(user?.preferences?.profilePublic),
      searchable: Boolean(user?.preferences?.searchable),
    },
    security: {
      activeSessions: Array.isArray(user?.refreshSessions) ? user.refreshSessions.length : 0,
      knownDevices: Array.isArray(user?.knownDevices) ? user.knownDevices.length : 0,
      mfaEnabled: Boolean(mfa.enabled),
      passkeyCount: passkeys.count,
      passwordChangedAt: user?.security?.passwordChangedAt || null,
    },
    vanguard: buildVanguardAccountState(user),
  };
};

const buildOwnerSummary = (users = []) => {
  let verified = 0;
  let owners = 0;
  let suspended = 0;
  let flagged = 0;
  let mfaEnabled = 0;
  let passkeysEnabled = 0;
  let publicProfiles = 0;
  let recentLogins7d = 0;
  const cutoff = Date.now() - 7 * DAY_MS;

  for (const user of users) {
    const authority = buildAuthorityPayload(user);
    const vanguard = buildVanguardAccountState(user);
    const passkeys = getPasskeyState(user);
    const mfa = getMfaState(user);
    const lastLoginAt = new Date(user?.lastLoginAt || 0).getTime();

    if (user?.isVerified) verified += 1;
    if (authority.isOwner) owners += 1;
    if (authority.status === ACCOUNT_STATUS_SUSPENDED) suspended += 1;
    if (vanguard.flagged || vanguard.bannedFromAi) flagged += 1;
    if (mfa.enabled) mfaEnabled += 1;
    if (passkeys.count > 0) passkeysEnabled += 1;
    if (user?.preferences?.profilePublic) publicProfiles += 1;
    if (!Number.isNaN(lastLoginAt) && lastLoginAt >= cutoff) recentLogins7d += 1;
  }

  return {
    totalUsers: users.length,
    owners,
    verified,
    suspended,
    flagged,
    mfaEnabled,
    passkeysEnabled,
    publicProfiles,
    recentLogins7d,
  };
};

const buildPublicLinkedAccounts = (linkedAccounts = {}) => {
  const next = {};

  for (const provider of LINKED_PROVIDERS) {
    const value = sanitizeText(linkedAccounts?.[provider], 120);
    if (value) {
      next[provider] = value;
    }
  }

  return next;
};

const buildPublicProfilePayload = (user) => {
  const visibility = normalizePublicProfilePreferences(
    user?.preferences?.publicProfile || {},
    DEFAULT_PUBLIC_PROFILE
  );

  return {
    username: getDisplayableUsername(user),
    handle: `@${getDisplayableUsername(user)}`,
    displayName: sanitizeText(user?.displayName, 60) || 'User',
    createdAt: visibility.memberSince ? user?.createdAt || null : null,
    updatedAt: user?.updatedAt || null,
    profile: {
      avatar: sanitizeAvatar(user?.profile?.avatar, ''),
      avatarMeta: normalizeAvatarMeta(user?.profile?.avatarMeta, user?.profile?.avatar),
      headline: visibility.headline ? sanitizeHeadline(user?.profile?.headline, '') : '',
      role: visibility.role ? sanitizeRole(user?.profile?.role, '') : '',
      organization: visibility.organization ? sanitizeOrganization(user?.profile?.organization, '') : '',
      currentFocus: visibility.currentFocus ? sanitizeCurrentFocus(user?.profile?.currentFocus, '') : '',
      focusAreas: visibility.focusAreas ? sanitizeFocusAreas(user?.profile?.focusAreas) : [],
      pronouns: visibility.pronouns ? sanitizePronouns(user?.profile?.pronouns, '') : '',
      bio: visibility.bio ? sanitizeText(user?.profile?.bio, 320) : '',
      location: visibility.location ? sanitizeText(user?.profile?.location, 120) : '',
      website: visibility.website ? sanitizeText(user?.profile?.website, 240) : '',
      timezone: visibility.timezone ? sanitizeTimezone(user?.profile?.timezone, 'UTC') : '',
      language: visibility.language ? sanitizeLanguage(user?.profile?.language, 'en') : '',
    },
    linkedAccounts: visibility.linkedAccounts ? buildPublicLinkedAccounts(user?.linkedAccounts) : {},
  };
};

const buildPublicSearchFields = (user) => {
  const visibility = normalizePublicProfilePreferences(
    user?.preferences?.publicProfile || {},
    DEFAULT_PUBLIC_PROFILE
  );

  return {
    username: sanitizeText(getDisplayableUsername(user), 60).toLowerCase(),
    displayName: sanitizeText(user?.displayName, 60).toLowerCase(),
    headline: visibility.headline ? sanitizeHeadline(user?.profile?.headline, '').toLowerCase() : '',
    role: visibility.role ? sanitizeRole(user?.profile?.role, '').toLowerCase() : '',
    organization: visibility.organization ? sanitizeOrganization(user?.profile?.organization, '').toLowerCase() : '',
    currentFocus: visibility.currentFocus ? sanitizeCurrentFocus(user?.profile?.currentFocus, '').toLowerCase() : '',
    focusAreas: visibility.focusAreas
      ? sanitizeFocusAreas(user?.profile?.focusAreas).map((entry) => entry.toLowerCase())
      : [],
    bio: visibility.bio ? sanitizeText(user?.profile?.bio, 320).toLowerCase() : '',
    location: visibility.location ? sanitizeText(user?.profile?.location, 120).toLowerCase() : '',
    linkedAccounts: visibility.linkedAccounts
      ? Object.values(buildPublicLinkedAccounts(user?.linkedAccounts)).map((entry) =>
          sanitizeText(entry, 120).toLowerCase()
        )
      : [],
  };
};

const scoreTextField = (value, query, weights) => {
  const text = sanitizeText(value, 320).toLowerCase();
  if (!text || !query) return 0;
  if (text === query) return weights.exact;
  if (text.startsWith(query)) return weights.prefix;
  if (text.includes(query)) return weights.contains;
  return 0;
};

const scoreTextCollection = (values, query, weights) =>
  values.reduce((best, value) => Math.max(best, scoreTextField(value, query, weights)), 0);

const scorePublicProfileMatch = (user, rawQuery) => {
  const query = sanitizeText(rawQuery, 60).toLowerCase();
  if (query.length < 2) return 0;

  const fields = buildPublicSearchFields(user);

  let score = 0;
  score += scoreTextField(fields.username, query, { exact: 160, prefix: 110, contains: 78 });
  score += scoreTextField(fields.displayName, query, { exact: 120, prefix: 82, contains: 56 });
  score += scoreTextField(fields.role, query, { exact: 88, prefix: 62, contains: 42 });
  score += scoreTextField(fields.organization, query, { exact: 84, prefix: 58, contains: 40 });
  score += scoreTextField(fields.headline, query, { exact: 72, prefix: 48, contains: 34 });
  score += scoreTextField(fields.currentFocus, query, { exact: 68, prefix: 44, contains: 30 });
  score += scoreTextCollection(fields.focusAreas, query, { exact: 64, prefix: 40, contains: 28 });
  score += scoreTextField(fields.location, query, { exact: 32, prefix: 24, contains: 18 });
  score += scoreTextCollection(fields.linkedAccounts, query, { exact: 28, prefix: 20, contains: 16 });
  score += scoreTextField(fields.bio, query, { exact: 22, prefix: 16, contains: 12 });

  return score;
};

const buildPublicSearchQuery = (regex) => {
  const linkedClauses = LINKED_PROVIDERS.map((provider) => ({
    [`linkedAccounts.${provider}`]: regex,
  }));

  return {
    'preferences.profilePublic': true,
    'preferences.searchable': true,
    $or: [
      { username: regex },
      { displayName: regex },
      {
        $and: [{ 'preferences.publicProfile.headline': true }, { 'profile.headline': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.role': true }, { 'profile.role': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.organization': true }, { 'profile.organization': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.currentFocus': true }, { 'profile.currentFocus': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.focusAreas': true }, { 'profile.focusAreas': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.bio': true }, { 'profile.bio': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.location': true }, { 'profile.location': regex }],
      },
      {
        $and: [{ 'preferences.publicProfile.linkedAccounts': true }, { $or: linkedClauses }],
      },
    ],
  };
};

const sendUserResponse = (res, status, message, user, extra = {}) => {
  const payload = buildUserPayload(user);

  return res.status(status).json({
    message,
    ...extra,
    ...payload,
    user: payload,
  });
};

const buildAuthSuccessMeta = (req, extra = {}) => ({
  auth: {
    code: 'auth/ok',
    correlationId: sanitizeText(req?.requestId, 120),
    ...extra,
  },
  correlationId: sanitizeText(req?.requestId, 120),
  requestId: sanitizeText(req?.requestId, 120),
});

const buildAuthErrorPayload = (
  req,
  {
    authenticated = false,
    code = AUTH_ERROR_CODE.unavailable,
    message = 'Authentication failed.',
    retryable = false,
    ...extra
  } = {}
) => ({
  authenticated: Boolean(authenticated),
  correlationId: sanitizeText(req?.requestId, 120),
  error: {
    code: sanitizeText(code, 120) || AUTH_ERROR_CODE.unavailable,
    correlationId: sanitizeText(req?.requestId, 120),
    message: sanitizeText(message, 400) || 'Authentication failed.',
    retryable: Boolean(retryable),
  },
  message: sanitizeText(message, 400) || 'Authentication failed.',
  requestId: sanitizeText(req?.requestId, 120),
  ...extra,
});

const buildActivitySummary = (recentLogins = [], dailyCounts = []) => {
  const now = Date.now();
  const sevenDaysAgo = now - 7 * DAY_MS;
  const thirtyDaysAgo = now - 30 * DAY_MS;

  const uniqueIps = new Set();

  for (const entry of recentLogins) {
    const timestamp = new Date(entry?.at || '').getTime();
    if (Number.isNaN(timestamp)) continue;

    const ip = sanitizeText(entry?.ip, 80);
    if (ip) uniqueIps.add(ip);
  }

  const normalizedDailyCounts = Array.isArray(dailyCounts)
    ? dailyCounts
        .map((entry) => ({
          day: buildActivityDay(entry?.day),
          count: Math.max(0, Math.trunc(Number(entry?.count || 0))),
        }))
        .filter((entry) => entry.day && entry.count > 0 && !Number.isNaN(parseActivityDayStart(entry.day)))
        .sort((a, b) => a.day.localeCompare(b.day))
    : [];

  if (normalizedDailyCounts.length > 0) {
    let last7Days = 0;
    let last30Days = 0;

    for (const entry of normalizedDailyCounts) {
      const dayStart = parseActivityDayStart(entry.day);
      if (dayStart >= sevenDaysAgo) last7Days += entry.count;
      if (dayStart >= thirtyDaysAgo) last30Days += entry.count;
    }

    return {
      last7Days,
      last30Days,
      uniqueIps: uniqueIps.size,
      recentDays: normalizedDailyCounts.slice(-7),
    };
  }

  let last7Days = 0;
  let last30Days = 0;
  const byDay = new Map();

  for (const entry of recentLogins) {
    const timestamp = new Date(entry?.at || '').getTime();
    if (Number.isNaN(timestamp)) continue;

    if (timestamp >= sevenDaysAgo) last7Days += 1;
    if (timestamp >= thirtyDaysAgo) last30Days += 1;

    const day = new Date(timestamp).toISOString().slice(0, 10);
    byDay.set(day, (byDay.get(day) || 0) + 1);
  }

  const recentDays = Array.from(byDay.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .slice(-7)
    .map(([day, count]) => ({ day, count }));

  return {
    last7Days,
    last30Days,
    uniqueIps: uniqueIps.size,
    recentDays,
  };
};

const FULL_USER_SELECT_FIELDS =
  'email username displayName accountRole accountStatus accountStatusReason isVerified verificationToken verificationTokenExpires emailDelivery passwordResetToken passwordResetTokenExpires passwordResetRequestedAt lastLoginAt lastLoginIp recentLogins loginDayCounts knownDevices auditEvents profile linkedAccounts oauthIdentities integrations preferences security refreshTokenVersion refreshSessions createdAt updatedAt password';

const syncConfiguredOwnerAccess = (user) => {
  if (!user) return false;

  let changed = false;
  const normalizedRole = normalizeAccountRole(user.accountRole);
  const normalizedStatus = normalizeAccountStatus(user.accountStatus);
  const normalizedReason = sanitizeOwnerStatusReason(user.accountStatusReason, '');

  if (user.accountRole !== normalizedRole) {
    user.accountRole = normalizedRole;
    changed = true;
  }
  if (user.accountStatus !== normalizedStatus) {
    user.accountStatus = normalizedStatus;
    changed = true;
  }
  if ((user.accountStatusReason || '') !== normalizedReason) {
    user.accountStatusReason = normalizedReason;
    changed = true;
  }
  if (shouldAutoGrantOwnerRole(user.email) && !isOwnerRole(user.accountRole)) {
    user.accountRole = ACCOUNT_ROLE_OWNER;
    changed = true;
  }

  return changed;
};

const maybeAssignBootstrapOwner = async (user) => {
  if (!user || isOwnerRole(user.accountRole)) return false;
  if (shouldAutoGrantOwnerRole(user.email)) {
    user.accountRole = ACCOUNT_ROLE_OWNER;
    return true;
  }

  const hasOwner = await User.exists({ accountRole: ACCOUNT_ROLE_OWNER });
  if (hasOwner) {
    return false;
  }

  user.accountRole = ACCOUNT_ROLE_OWNER;
  return true;
};

const ensureUserState = async (user, { ensureIdentity = true } = {}) => {
  if (!user) {
    return null;
  }

  let changed = false;

  if (syncConfiguredOwnerAccess(user)) {
    changed = true;
  }

  if (ensureIdentity && (await ensureUserIdentityFields(user))) {
    changed = true;
  }

  if (normalizeUserSecurityState(user)) {
    changed = true;
  }

  if (changed) {
    await user.save();
  }

  return user;
};

const getUserById = async (id, { ensureIdentity = true } = {}) => {
  const user = await User.findById(id).select(FULL_USER_SELECT_FIELDS);
  return ensureUserState(user, { ensureIdentity });
};

const getOwnerUserById = async (id) => {
  const userId = normalizeOwnerUserId(id);
  if (!userId || !mongoose.isValidObjectId(userId)) {
    throw createHttpError(404, 'User not found.');
  }

  const user = await getUserById(userId);
  if (!user) {
    throw createHttpError(404, 'User not found.');
  }

  return user;
};

const countRemainingOwners = async (excludeUserId) => {
  const filter = { accountRole: ACCOUNT_ROLE_OWNER };
  if (excludeUserId && mongoose.isValidObjectId(excludeUserId)) {
    filter._id = { $ne: excludeUserId };
  }
  return User.countDocuments(filter);
};

const assertOwnerRetention = async (user, { nextRole, nextStatus, deleting = false } = {}) => {
  if (!user || !isOwnerRole(user.accountRole)) return;

  const roleAfterChange = nextRole ? normalizeAccountRole(nextRole) : normalizeAccountRole(user.accountRole);
  const statusAfterChange = nextStatus
    ? normalizeAccountStatus(nextStatus)
    : normalizeAccountStatus(user.accountStatus);
  const removesOwnerAccess =
    deleting || roleAfterChange !== ACCOUNT_ROLE_OWNER || statusAfterChange === ACCOUNT_STATUS_SUSPENDED;

  if (!removesOwnerAccess) return;

  const remainingOwners = await countRemainingOwners(user._id);
  if (remainingOwners <= 0) {
    throw createHttpError(400, 'At least one active owner account must remain.');
  }
};

const buildOwnerUserQuery = ({ query = '', role = '', status = '' } = {}) => {
  const filters = [];
  const normalizedQuery = normalizeOwnerSearchQuery(query);
  const normalizedRole = normalizeAccountRole(role);
  const normalizedStatus = normalizeAccountStatus(status);

  if (normalizedQuery) {
    const regex = new RegExp(escapeRegex(normalizedQuery), 'i');
    filters.push({
      $or: [
        { email: regex },
        { username: regex },
        { displayName: regex },
        { 'profile.headline': regex },
        { 'profile.role': regex },
        { 'profile.organization': regex },
      ],
    });
  }

  if (String(role || '').trim()) {
    filters.push({ accountRole: normalizedRole });
  }
  if (String(status || '').trim()) {
    filters.push({ accountStatus: normalizedStatus });
  }

  if (!filters.length) {
    return {};
  }

  return filters.length === 1 ? filters[0] : { $and: filters };
};

const normalizeOwnerAuthorityInput = (incoming = {}, currentUser) => {
  const nextRole = hasOwn(incoming, 'role')
    ? normalizeAccountRole(incoming.role)
    : normalizeAccountRole(currentUser?.accountRole);
  const nextStatus = hasOwn(incoming, 'status')
    ? normalizeAccountStatus(incoming.status)
    : normalizeAccountStatus(currentUser?.accountStatus);
  const statusReason =
    nextStatus === ACCOUNT_STATUS_SUSPENDED
      ? sanitizeOwnerStatusReason(
          hasOwn(incoming, 'statusReason') ? incoming.statusReason : currentUser?.accountStatusReason,
          ''
        )
      : '';

  return {
    role: nextRole,
    status: nextStatus,
    statusReason,
  };
};

const uniqThrottleKeys = (keys = []) =>
  Array.from(
    new Set(
      (Array.isArray(keys) ? keys : [])
        .map((value) => String(value || '').trim())
        .filter(Boolean)
    )
  );

const buildLoginThrottleKeys = ({ identifier = '', req, user = null } = {}) => {
  const normalizedIdentifier = normalizeLoginIdentifier(identifier);
  const ip = parseClientIp(req);
  const userId = toObjectIdString(user?._id);

  return uniqThrottleKeys([
    ip ? `login:ip:${ip}` : '',
    normalizedIdentifier ? `login:identifier:${normalizedIdentifier}` : '',
    normalizedIdentifier && ip ? `login:identifier-ip:${normalizedIdentifier}|${ip}` : '',
    userId ? `login:user:${userId}` : '',
    userId && ip ? `login:user-ip:${userId}|${ip}` : '',
  ]);
};

const buildPublicActionThrottleKeys = (action, { identifier = '', req, user = null } = {}) => {
  const prefix = sanitizeText(action, 40).toLowerCase();
  const normalizedIdentifier = normalizeLoginIdentifier(identifier);
  const ip = parseClientIp(req);
  const userId = toObjectIdString(user?._id);

  return uniqThrottleKeys([
    prefix && ip ? `${prefix}:ip:${ip}` : '',
    prefix && normalizedIdentifier ? `${prefix}:identifier:${normalizedIdentifier}` : '',
    prefix && normalizedIdentifier && ip ? `${prefix}:identifier-ip:${normalizedIdentifier}|${ip}` : '',
    prefix && userId ? `${prefix}:user:${userId}` : '',
    prefix && userId && ip ? `${prefix}:user-ip:${userId}|${ip}` : '',
  ]);
};

const findUserByLoginIdentifier = async (identifier) => {
  const normalized = normalizeLoginIdentifier(identifier);
  if (!normalized) return null;

  if (isValidEmail(normalized)) {
    return ensureUserState(await User.findOne({ email: normalized }));
  }

  if (isValidUsername(normalized)) {
    return ensureUserState(await User.findOne({ username: normalized }));
  }

  return null;
};

const buildThrottleExpiry = (windowMs, blockMs, now = Date.now()) =>
  new Date(now + Math.max(windowMs, blockMs) + 60_000);

const getThrottleState = async (key, windowMs) => {
  const now = Date.now();
  const entry = await LoginThrottle.findOne({ key }).select('windowStartedAt blockedUntil');

  if (!entry) {
    return { blocked: false, retryAfterSec: 0 };
  }

  const blockedUntil = entry.blockedUntil ? new Date(entry.blockedUntil).getTime() : 0;
  if (blockedUntil > now) {
    return {
      blocked: true,
      retryAfterSec: Math.max(1, Math.ceil((blockedUntil - now) / 1000)),
    };
  }

  const windowStartedAt = entry.windowStartedAt ? new Date(entry.windowStartedAt).getTime() : 0;
  if (!windowStartedAt || now - windowStartedAt > windowMs) {
    await LoginThrottle.deleteOne({ key });
  }

  return { blocked: false, retryAfterSec: 0 };
};

const registerThrottleFailure = async (key, { windowMs, maxAttempts, blockMs }) => {
  const now = Date.now();
  const current = await LoginThrottle.findOne({ key });

  if (
    !current ||
    !current.windowStartedAt ||
    now - new Date(current.windowStartedAt).getTime() > windowMs
  ) {
    try {
      await LoginThrottle.findOneAndUpdate(
        { key },
        {
          key,
          windowStartedAt: new Date(now),
          count: 1,
          blockedUntil: null,
          expiresAt: buildThrottleExpiry(windowMs, blockMs, now),
        },
        {
          new: true,
          upsert: true,
          setDefaultsOnInsert: true,
        }
      );
    } catch (err) {
      if (!isDuplicateKeyError(err)) {
        throw err;
      }

      const retry = await LoginThrottle.findOne({ key });
      if (!retry) {
        throw err;
      }

      retry.count += 1;
      retry.expiresAt = buildThrottleExpiry(windowMs, blockMs, now);
      if (retry.count >= maxAttempts) {
        retry.blockedUntil = new Date(now + blockMs);
      }
      await retry.save();
    }
    return;
  }

  current.count += 1;
  current.expiresAt = buildThrottleExpiry(windowMs, blockMs, now);

  if (current.count >= maxAttempts) {
    current.blockedUntil = new Date(now + blockMs);
  }

  await current.save();
};

const clearThrottleFailures = async (key) => {
  await LoginThrottle.deleteOne({ key });
};

const getAggregateThrottleState = async (keys, windowMs) => {
  const uniqueKeys = uniqThrottleKeys(keys);

  for (const key of uniqueKeys) {
    const state = await getThrottleState(key, windowMs);
    if (state.blocked) {
      return state;
    }
  }

  return { blocked: false, retryAfterSec: 0 };
};

const registerThrottleFailures = async (keys, options) => {
  const uniqueKeys = uniqThrottleKeys(keys);
  await Promise.all(uniqueKeys.map((key) => registerThrottleFailure(key, options)));
};

const clearThrottleFailuresForKeys = async (keys) => {
  const uniqueKeys = uniqThrottleKeys(keys);
  await Promise.all(uniqueKeys.map((key) => clearThrottleFailures(key)));
};

const getLoginThrottleState = async (keys) => getAggregateThrottleState(keys, LOGIN_RATE_WINDOW_MS);

const registerLoginFailure = async (keys) =>
  registerThrottleFailures(keys, {
    windowMs: LOGIN_RATE_WINDOW_MS,
    maxAttempts: LOGIN_RATE_MAX_ATTEMPTS,
    blockMs: LOGIN_BLOCK_MS,
  });

const clearLoginFailures = async (keys) => {
  await clearThrottleFailuresForKeys(keys);
};

const consumePublicActionThrottle = async (keys, { windowMs, maxAttempts, blockMs }) =>
  registerThrottleFailures(keys, {
    windowMs,
    maxAttempts,
    blockMs,
  });

const buildMfaThrottleKey = (user) => `mfa:${toObjectIdString(user?._id)}`;
const getMfaThrottleState = async (user) =>
  getThrottleState(buildMfaThrottleKey(user), MFA_RATE_WINDOW_MS);
const registerMfaFailure = async (user) =>
  registerThrottleFailure(buildMfaThrottleKey(user), {
    windowMs: MFA_RATE_WINDOW_MS,
    maxAttempts: MFA_RATE_MAX_ATTEMPTS,
    blockMs: MFA_BLOCK_MS,
  });
const clearMfaFailures = async (user) => clearThrottleFailures(buildMfaThrottleKey(user));

const verifyMfaChallenge = async (user, req, { mfaCode = '', backupCode = '' } = {}) => {
  if (!isMfaEnabledForUser(user)) {
    return { ok: true, skipped: true };
  }

  const throttle = await getMfaThrottleState(user);
  if (throttle.blocked) {
    appendAuditEvent(user, req, 'mfa_throttled', 'MFA challenge blocked after repeated failures.', {
      retryAfterSec: throttle.retryAfterSec,
    });
    return { ok: false, reason: 'blocked', retryAfterSec: throttle.retryAfterSec };
  }

  if (!mfaCode && !backupCode) {
    return { ok: false, reason: 'missing' };
  }

  const result = verifyMfaAttempt(user, { mfaCode, backupCode });
  if (!result.ok) {
    await registerMfaFailure(user);
    appendAuditEvent(user, req, 'mfa_failed', 'An invalid MFA code was submitted.', {});
    const updatedThrottle = await getMfaThrottleState(user);
    if (updatedThrottle.blocked) {
      appendAuditEvent(user, req, 'mfa_throttled', 'MFA challenge blocked after repeated failures.', {
        retryAfterSec: updatedThrottle.retryAfterSec,
      });
      return { ok: false, reason: 'blocked', retryAfterSec: updatedThrottle.retryAfterSec };
    }
    return { ok: false, reason: 'invalid' };
  }

  await clearMfaFailures(user);
  user.security.mfa.lastUsedAt = new Date();
  if (result.method === 'backup_code') {
    appendAuditEvent(user, req, 'mfa_backup_code_used', 'A backup code was used for verification.');
  }

  return { ok: true, ...result };
};

const sendProtectedActionMfaError = (res, mfaResult, missingMessage = 'Enter your MFA code to continue.') => {
  if (mfaResult.reason === 'blocked') {
    return res.status(429).json({
      message: `Too many invalid MFA attempts. Try again in ${mfaResult.retryAfterSec} seconds.`,
      retryAfterSec: mfaResult.retryAfterSec,
      mfaRequired: true,
    });
  }

  return res.status(403).json({
    message: mfaResult.reason === 'invalid' ? 'Invalid MFA code.' : missingMessage,
    mfaRequired: true,
  });
};

const revokeAllTrackedSessions = (user) => {
  if (!user) return;
  user.refreshTokenVersion += 1;
  user.refreshSessions = [];
};

const getPasswordResetCooldownRemainingMs = (user) => {
  const requestedAt = user?.passwordResetRequestedAt
    ? new Date(user.passwordResetRequestedAt).getTime()
    : 0;
  if (!requestedAt) return 0;
  return Math.max(0, requestedAt + PASSWORD_RESET_EMAIL_COOLDOWN_MS - Date.now());
};

const applyEmailChange = async (user, email, currentPassword) => {
  const nextEmail = normalizeEmail(email);
  const currentEmail = normalizeEmail(user?.email);

  if (!nextEmail || nextEmail === currentEmail) {
    return false;
  }

  if (!isValidEmail(nextEmail)) {
    throw createHttpError(400, 'Please provide a valid email address.');
  }

  if (typeof currentPassword !== 'string' || currentPassword.length === 0) {
    throw createHttpError(400, 'Current password is required to change your email.');
  }

  const matches = await user.comparePassword(currentPassword);
  if (!matches) {
    throw createHttpError(400, 'Current password is incorrect.');
  }

  const existing = await User.findOne({ email: nextEmail }).select('_id');
  if (existing && toObjectIdString(existing._id) !== toObjectIdString(user._id)) {
    throw createHttpError(409, 'Email is already in use.');
  }

  user.email = nextEmail;
  return true;
};

const buildEmailChangeSecurityDetails = (req, previousEmail = '', nextEmail = '') =>
  [
    previousEmail ? `Previous email: ${previousEmail}` : '',
    nextEmail ? `New email: ${nextEmail}` : '',
    `Time: ${new Date().toUTCString()}`,
    `IP address: ${parseClientIp(req) || 'Unknown'}`,
  ].filter(Boolean);

const revokeRefreshSessionForReplay = async (user, sid) => {
  if (!user || !sid) return;
  if (!removeRefreshSession(user, sid)) return;
  await user.save();
};

const resolveRefreshSessionFromCookie = async (req, res) => {
  const token = req.cookies.refreshToken;
  if (!token) return null;

  let payload;
  try {
    payload = verifyTypedJwt({
      token,
      secret: process.env.REFRESH_TOKEN_SECRET,
      audience: REFRESH_TOKEN_AUDIENCE,
      type: 'refresh_token',
      allowLegacy: true,
    });
  } catch {
    clearRefreshCookie(res, req);
    return null;
  }

  const userId = sanitizeText(payload?.userId || payload?.sub, 120);
  const user = await getUserById(userId);
  if (!user) {
    clearRefreshCookie(res, req);
    return null;
  }

  if (user.refreshTokenVersion !== payload.tokenVersion) {
    clearRefreshCookie(res, req);
    return null;
  }

  const sidFromToken = sanitizeText(payload.sid, 120);
  const refreshTokenId = sanitizeText(payload.jti, 120);

  if (sidFromToken) {
    const session = findRefreshSession(user, sidFromToken);
    if (!session) {
      clearRefreshCookie(res, req);
      return null;
    }

    const currentRefreshTokenId = sanitizeText(session.currentRefreshTokenId, 120);
    const previousRefreshTokenId = sanitizeText(session.previousRefreshTokenId, 120);
    const previousRefreshTokenGraceUntil = session.previousRefreshTokenGraceUntil
      ? new Date(session.previousRefreshTokenGraceUntil).getTime()
      : 0;

    if (currentRefreshTokenId) {
      if (refreshTokenId === currentRefreshTokenId) {
        return { user, sid: sidFromToken, session, tokenState: 'current' };
      }

      if (
        refreshTokenId &&
        previousRefreshTokenId &&
        refreshTokenId === previousRefreshTokenId &&
        previousRefreshTokenGraceUntil > Date.now()
      ) {
        return { user, sid: sidFromToken, session, tokenState: 'grace' };
      }

      if (refreshTokenId) {
        await revokeRefreshSessionForReplay(user, sidFromToken);
        clearRefreshCookie(res, req);
        return { replayDetected: true };
      }

      clearRefreshCookie(res, req);
      return null;
    }

    if (refreshTokenId) {
      upsertRefreshSession(user, req, sidFromToken, '', {
        currentRefreshTokenId: refreshTokenId,
        previousRefreshTokenId: '',
        previousRefreshTokenGraceUntil: null,
      });
      return {
        user,
        sid: sidFromToken,
        session: findRefreshSession(user, sidFromToken),
        tokenState: 'current',
      };
    }

    return { user, sid: sidFromToken, session, tokenState: 'legacy' };
  }

  return { user, sid: '', session: null, tokenState: 'legacy' };
};

exports.register = async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const password = req.body?.password;
  const displayName = sanitizeDisplayName(req.body?.displayName, email);
  const requestedUsername = req.body?.username;

  try {
    if (!isValidEmail(email)) {
      return res.status(400).json(
        buildAuthErrorPayload(req, {
          code: AUTH_ERROR_CODE.registrationFailed,
          message: 'Please provide a valid email address.',
        })
      );
    }

    if (!isStrongPassword(password)) {
      return res.status(400).json(
        buildAuthErrorPayload(req, {
          code: AUTH_ERROR_CODE.registrationFailed,
          message:
            'Password must be at least 8 characters and include uppercase, lowercase, and a number.',
        })
      );
    }

    if (hasOwn(req.body || {}, 'username') && !normalizeUsername(requestedUsername)) {
      return res
        .status(400)
        .json(buildAuthErrorPayload(req, { code: AUTH_ERROR_CODE.registrationFailed, message: USERNAME_VALIDATION_MESSAGE }));
    }

    if (containsBlockedNameTerm(requestedUsername)) {
      return res
        .status(400)
        .json(buildAuthErrorPayload(req, { code: AUTH_ERROR_CODE.registrationFailed, message: USERNAME_MODERATION_MESSAGE }));
    }

    if (hasOwn(req.body || {}, 'displayName') && containsBlockedNameTerm(req.body?.displayName)) {
      return res
        .status(400)
        .json(buildAuthErrorPayload(req, { code: AUTH_ERROR_CODE.registrationFailed, message: DISPLAY_NAME_MODERATION_MESSAGE }));
    }

    const existingUser = await User.findOne({ email }).select('_id');
    if (existingUser) {
      return res.status(409).json(
        buildAuthErrorPayload(req, {
          code: AUTH_ERROR_CODE.identityConflict,
          message: 'A user with that email already exists.',
        })
      );
    }

    const user = new User({
      email,
      password,
      displayName,
      profile: normalizeProfile(req.body || {}, {}),
      preferences: normalizePreferences(req.body?.preferences || {}, {}),
    });

    await applyUsernameChange(user, requestedUsername);
    const grantedBootstrapOwner = await maybeAssignBootstrapOwner(user);
    const verification = prepareEmailVerification(user);
    appendAuditEvent(user, req, 'register', 'Account created. Email verification required before sign-in.', {
      username: getDisplayableUsername(user),
    });
    if (grantedBootstrapOwner) {
      appendAuditEvent(
        user,
        req,
        'owner_granted',
        'Owner access granted during account bootstrap.',
        { reason: shouldAutoGrantOwnerRole(user.email) ? 'configured_email' : 'first_owner_bootstrap' }
      );
    }
    await user.save();
    const verificationDelivery = await sendVerificationEmail(user, req, verification);

    return res.status(201).json({
      message: getVerificationDeliveryMessage(
        'Registration successful. Check your inbox to verify your email before signing in.',
        'Registration successful. Check your inbox for the verification email that was already sent.',
        'Registration successful, but the verification email could not be sent right now. Try signing in later to request another verification email.',
        verificationDelivery
      ),
      authenticated: false,
      ...buildAuthSuccessMeta(req, {
        code: AUTH_ERROR_CODE.emailUnverified,
        sessionEstablished: false,
      }),
      requiresVerification: true,
      verificationEmail: serializeVerificationDelivery(verificationDelivery),
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json(
        buildAuthErrorPayload(req, {
          code: AUTH_ERROR_CODE.registrationFailed,
          message: err.message,
          retryable: err.statusCode >= 500,
        })
      );
    }
    if (isDuplicateKeyError(err)) {
      return res.status(409).json(
        buildAuthErrorPayload(req, {
          code: AUTH_ERROR_CODE.identityConflict,
          message: getDuplicateUserFieldMessage(err),
        })
      );
    }
    console.error('Register error:', err);
    return res.status(500).json(
      buildAuthErrorPayload(req, {
        code: AUTH_ERROR_CODE.registrationFailed,
        message: 'Registration failed.',
        retryable: true,
      })
    );
  }
};

exports.login = async (req, res) => {
  const identifier = normalizeLoginIdentifier(
    req.body?.identifier || req.body?.email || req.body?.username
  );
  const password = req.body?.password;
  const mfaCode = sanitizeMfaCode(req.body?.mfaCode);
  const backupCode = sanitizeBackupCode(req.body?.backupCode);

  let throttleKeys = buildLoginThrottleKeys({ identifier, req });
  let throttle = await getLoginThrottleState(throttleKeys);
  if (throttle.blocked) {
    return res.status(429).json(
      buildAuthErrorPayload(req, {
        code: AUTH_ERROR_CODE.authorizationDenied,
        message: `Too many failed login attempts. Try again in ${throttle.retryAfterSec} seconds.`,
        retryAfterSec: throttle.retryAfterSec,
      })
    );
  }

  try {
    if ((!isValidEmail(identifier) && !isValidUsername(identifier)) || typeof password !== 'string') {
      await registerLoginFailure(throttleKeys);
      return res.status(400).json(
        buildAuthErrorPayload(req, {
          code: AUTH_ERROR_CODE.invalidCredentials,
          message: 'Invalid credentials.',
        })
      );
    }

    const user = await findUserByLoginIdentifier(identifier);
    if (user) {
      throttleKeys = buildLoginThrottleKeys({ identifier, req, user });
      throttle = await getLoginThrottleState(throttleKeys);
      if (throttle.blocked) {
        return res.status(429).json(
          buildAuthErrorPayload(req, {
            code: AUTH_ERROR_CODE.authorizationDenied,
            message: `Too many failed login attempts. Try again in ${throttle.retryAfterSec} seconds.`,
            retryAfterSec: throttle.retryAfterSec,
          })
        );
      }
    }

    if (!user) {
      await registerLoginFailure(throttleKeys);
      return res.status(400).json(
        buildAuthErrorPayload(req, {
          code: AUTH_ERROR_CODE.invalidCredentials,
          message: 'Invalid credentials.',
        })
      );
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      await registerLoginFailure(throttleKeys);
      return res.status(400).json(
        buildAuthErrorPayload(req, {
          code: AUTH_ERROR_CODE.invalidCredentials,
          message: 'Invalid credentials.',
        })
      );
    }

    await ensureUserIdentityFields(user);

    if (isSuspendedAccount(user.accountStatus)) {
      await clearLoginFailures(throttleKeys);
      appendAuditEvent(user, req, 'login_blocked_suspended', 'Sign-in blocked because the account is suspended.');
      await user.save();
      return res.status(403).json(
        buildAuthErrorPayload(req, {
          code: AUTH_ERROR_CODE.suspended,
          message: 'This account is suspended.',
        })
      );
    }

    if (!user.isVerified) {
      await clearLoginFailures(throttleKeys);

      let verificationDelivery = { sent: false, reason: 'cooldown' };
      if (!(hasPendingEmailVerification(user) && getVerificationEmailCooldownRemainingMs(user) > 0)) {
        const verification = prepareEmailVerification(user);
        revokeAllTrackedSessions(user);
        appendAuditEvent(
          user,
          req,
          'login_blocked_unverified',
          'Sign-in blocked until email verification is completed.',
          { identifier }
        );
        await user.save();
        verificationDelivery = await sendVerificationEmail(user, req, verification);
      }

      clearRefreshCookie(res, req);

      return res.status(403).json({
        message: getVerificationDeliveryMessage(
          'Verify your email before signing in. A fresh verification link has been sent.',
          'Verify your email before signing in. Check your inbox for the verification link that was already sent recently.',
          'Verify your email before signing in. We could not send a new verification email right now.',
          verificationDelivery
        ),
        authenticated: false,
        ...buildAuthSuccessMeta(req, {
          code: AUTH_ERROR_CODE.emailUnverified,
          sessionEstablished: false,
        }),
        requiresVerification: true,
        verificationEmail: serializeVerificationDelivery(verificationDelivery),
      });
    }

    if (isMfaEnabledForUser(user)) {
      const mfaResult = await verifyMfaChallenge(user, req, { mfaCode, backupCode });
      if (!mfaResult.ok) {
        appendAuditEvent(user, req, 'mfa_challenge', 'Additional verification required for sign-in.', {
          identifier,
          reason: mfaResult.reason,
        });
        await user.save();
        if (mfaResult.reason === 'blocked') {
          return res.status(429).json(
            buildAuthErrorPayload(req, {
              code: AUTH_ERROR_CODE.mfaBlocked,
              message: `Too many invalid MFA attempts. Try again in ${mfaResult.retryAfterSec} seconds.`,
              mfaRequired: true,
              retryAfterSec: mfaResult.retryAfterSec,
            })
          );
        }
        return res.status(401).json(
          buildAuthErrorPayload(req, {
            code: AUTH_ERROR_CODE.mfaRequired,
            message: mfaResult.reason === 'invalid' ? 'Invalid MFA code.' : 'Enter your MFA code to continue.',
            mfaRequired: true,
          })
        );
      }

    }

    await clearLoginFailures(throttleKeys);
    return completeInteractiveSignIn(res, req, user, {
      deviceLabel: req.body?.deviceLabel,
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json(
      buildAuthErrorPayload(req, {
        code: AUTH_ERROR_CODE.unavailable,
        message: 'Login failed.',
        retryable: true,
      })
    );
  }
};

exports.logout = async (req, res) => {
  try {
    const session = await resolveRefreshSessionFromCookie(req, res);
    if (session?.user) {
      if (session.sid) {
        removeRefreshSession(session.user, session.sid);
      } else {
        session.user.refreshTokenVersion += 1;
        session.user.refreshSessions = [];
      }
      appendAuditEvent(
        session.user,
        req,
        'logout',
        session.sid ? 'Signed out of the current session.' : 'Signed out of all sessions.'
      );
      await session.user.save();
    }

    clearRefreshCookie(res, req);
    return res.status(200).json({ message: 'Logged out successfully.' });
  } catch (err) {
    console.error('Logout error:', err);
    clearRefreshCookie(res, req);
    return res.status(200).json({ message: 'Logged out.' });
  }
};

exports.requestPasswordReset = async (req, res) => {
  const identifier = normalizeLoginIdentifier(
    req.body?.identifier || req.body?.email || req.body?.username
  );
  const genericMessage =
    'If an account matches that sign-in, a password reset link will be sent shortly.';
  let throttleKeys = buildPublicActionThrottleKeys('password-reset', { identifier, req });

  try {
    let throttle = await getAggregateThrottleState(throttleKeys, PASSWORD_RESET_RATE_WINDOW_MS);
    if (throttle.blocked) {
      return res.status(200).json({ message: genericMessage });
    }

    if (!identifier || (!isValidEmail(identifier) && !isValidUsername(identifier))) {
      await consumePublicActionThrottle(throttleKeys, {
        windowMs: PASSWORD_RESET_RATE_WINDOW_MS,
        maxAttempts: PASSWORD_RESET_RATE_MAX_ATTEMPTS,
        blockMs: PASSWORD_RESET_BLOCK_MS,
      });
      return res.status(200).json({ message: genericMessage });
    }

    const user = await findUserByLoginIdentifier(identifier);
    if (user) {
      throttleKeys = buildPublicActionThrottleKeys('password-reset', { identifier, req, user });
      throttle = await getAggregateThrottleState(throttleKeys, PASSWORD_RESET_RATE_WINDOW_MS);
      if (throttle.blocked) {
        return res.status(200).json({ message: genericMessage });
      }
    }

    await consumePublicActionThrottle(throttleKeys, {
      windowMs: PASSWORD_RESET_RATE_WINDOW_MS,
      maxAttempts: PASSWORD_RESET_RATE_MAX_ATTEMPTS,
      blockMs: PASSWORD_RESET_BLOCK_MS,
    });
    throttle = await getAggregateThrottleState(throttleKeys, PASSWORD_RESET_RATE_WINDOW_MS);
    if (throttle.blocked) {
      return res.status(200).json({ message: genericMessage });
    }

    if (!user) {
      return res.status(200).json({ message: genericMessage });
    }

    await ensureUserIdentityFields(user);
    if (getPasswordResetCooldownRemainingMs(user) > 0) {
      return res.status(200).json({ message: genericMessage });
    }

    const reset = preparePasswordReset(user);
    appendAuditEvent(user, req, 'password_reset_requested', 'Password reset requested.');
    await user.save();
    await sendPasswordResetEmail(user, req, reset);

    return res.status(200).json({ message: genericMessage });
  } catch (err) {
    console.error('Password reset request error:', err);
    return res.status(200).json({ message: genericMessage });
  }
};

exports.publicResendVerificationEmail = async (req, res) => {
  const identifier = normalizeLoginIdentifier(
    req.body?.identifier || req.body?.email || req.body?.username
  );
  const genericMessage =
    'If that sign-in belongs to an unverified account, a verification link will be sent shortly.';
  let throttleKeys = buildPublicActionThrottleKeys('verification-resend', { identifier, req });

  try {
    let throttle = await getAggregateThrottleState(
      throttleKeys,
      VERIFICATION_RESEND_RATE_WINDOW_MS
    );
    if (throttle.blocked) {
      return res.status(200).json({ message: genericMessage });
    }

    if (!identifier || (!isValidEmail(identifier) && !isValidUsername(identifier))) {
      await consumePublicActionThrottle(throttleKeys, {
        windowMs: VERIFICATION_RESEND_RATE_WINDOW_MS,
        maxAttempts: VERIFICATION_RESEND_RATE_MAX_ATTEMPTS,
        blockMs: VERIFICATION_RESEND_BLOCK_MS,
      });
      return res.status(200).json({ message: genericMessage });
    }

    const user = await findUserByLoginIdentifier(identifier);
    if (user) {
      throttleKeys = buildPublicActionThrottleKeys('verification-resend', { identifier, req, user });
      throttle = await getAggregateThrottleState(
        throttleKeys,
        VERIFICATION_RESEND_RATE_WINDOW_MS
      );
      if (throttle.blocked) {
        return res.status(200).json({ message: genericMessage });
      }
    }

    await consumePublicActionThrottle(throttleKeys, {
      windowMs: VERIFICATION_RESEND_RATE_WINDOW_MS,
      maxAttempts: VERIFICATION_RESEND_RATE_MAX_ATTEMPTS,
      blockMs: VERIFICATION_RESEND_BLOCK_MS,
    });
    throttle = await getAggregateThrottleState(
      throttleKeys,
      VERIFICATION_RESEND_RATE_WINDOW_MS
    );
    if (throttle.blocked) {
      return res.status(200).json({ message: genericMessage });
    }

    if (!user || user.isVerified) {
      return res.status(200).json({ message: genericMessage });
    }

    await ensureUserIdentityFields(user);
    if (!(hasPendingEmailVerification(user) && getVerificationEmailCooldownRemainingMs(user) > 0)) {
      const verification = prepareEmailVerification(user);
      revokeAllTrackedSessions(user);
      appendAuditEvent(
        user,
        req,
        'verification_resent_public',
        'Verification email resent from the public sign-in flow.'
      );
      await user.save();
      await sendVerificationEmail(user, req, verification);
    }

    clearRefreshCookie(res, req);

    return res.status(200).json({ message: genericMessage });
  } catch (err) {
    console.error('Public resend verification email error:', err);
    return res.status(200).json({ message: genericMessage });
  }
};

exports.resetPassword = async (req, res) => {
  const token = sanitizeText(req.body?.token, 200);
  const newPassword = req.body?.newPassword || '';

  if (!token) {
    return res.status(400).json({ message: 'Password reset token is required.' });
  }

  if (!isStrongPassword(newPassword)) {
    return res.status(400).json({
      message:
        'New password must be at least 8 characters and include uppercase, lowercase, and a number.',
    });
  }

  try {
    const user = await User.findOne({
      passwordResetToken: hashToken(token),
      passwordResetTokenExpires: { $gt: Date.now() },
    }).select(FULL_USER_SELECT_FIELDS);

    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired password reset link.' });
    }

    clearPasswordReset(user);
    user.password = newPassword;
    user.refreshTokenVersion += 1;
    user.refreshSessions = [];
    appendAuditEvent(user, req, 'password_reset_completed', 'Password reset completed.');
    await user.save();

    await sendSecurityAlertEmail(
      user,
      'Your Continental ID password was reset',
      'Password reset completed',
      'Your Continental ID password was just reset.',
      [
        `Time: ${new Date().toUTCString()}`,
        `IP address: ${parseClientIp(req) || 'Unknown'}`,
      ]
    );

    return res.status(200).json({
      message: 'Password reset successful. You can now sign in with your new password.',
    });
  } catch (err) {
    console.error('Password reset completion error:', err);
    return res.status(500).json({ message: 'Failed to reset password.' });
  }
};

exports.searchPublicProfiles = async (req, res) => {
  const query = sanitizeText(req.query?.q, 60);

  try {
    if (query.length < 2) {
      const users = await User.find({
        'preferences.profilePublic': true,
        'preferences.searchable': true,
      })
        .select('username displayName profile linkedAccounts preferences createdAt updatedAt')
        .sort({ updatedAt: -1, _id: -1 })
        .limit(12)
        .lean();

      return res.json({
        message: 'Directory loaded.',
        query: '',
        isDirectory: true,
        results: users.map((user) => buildPublicProfilePayload(user)),
      });
    }

    const regex = new RegExp(escapeRegex(query), 'i');
    const users = await User.find(buildPublicSearchQuery(regex))
      .select('username displayName profile linkedAccounts preferences createdAt updatedAt')
      .sort({ updatedAt: -1, _id: -1 })
      .limit(48)
      .lean();

    const rankedUsers = users
      .map((user) => ({
        user,
        score: scorePublicProfileMatch(user, query),
        updatedAt: new Date(user?.updatedAt || user?.createdAt || 0).getTime(),
      }))
      .filter((entry) => entry.score > 0)
      .sort((left, right) => right.score - left.score || right.updatedAt - left.updatedAt)
      .slice(0, 12)
      .map((entry) => entry.user);

    return res.json({
      message: 'Search loaded.',
      query,
      isDirectory: false,
      results: rankedUsers.map((user) => buildPublicProfilePayload(user)),
    });
  } catch (err) {
    console.error('Public profile search error:', err);
    return res.status(500).json({ message: 'Failed to search public profiles.' });
  }
};

exports.getPublicProfile = async (req, res) => {
  const username = normalizeUsername(req.params?.username);

  try {
    if (!username) {
      return res.status(404).json({ message: 'Profile not found.' });
    }

    const user = await User.findOne({
      username,
      'preferences.profilePublic': true,
    })
      .select('username displayName profile linkedAccounts preferences createdAt updatedAt')
      .lean();

    if (!user) {
      return res.status(404).json({ message: 'Profile not found.' });
    }

    return res.json({
      message: 'Profile loaded.',
      profile: buildPublicProfilePayload(user),
    });
  } catch (err) {
    console.error('Get public profile error:', err);
    return res.status(500).json({ message: 'Failed to load public profile.' });
  }
};

exports.me = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json(
        buildAuthErrorPayload(req, {
          code: AUTH_ERROR_CODE.userNotFound,
          message: 'User not found.',
        })
      );
    }

    return sendUserResponse(res, 200, 'User loaded.', user, buildAuthSuccessMeta(req));
  } catch (err) {
    console.error('Fetch me error:', err);
    return res.status(500).json(
      buildAuthErrorPayload(req, {
        code: AUTH_ERROR_CODE.unavailable,
        message: 'Failed to fetch user profile.',
        retryable: true,
      })
    );
  }
};

exports.getOwnerSummary = async (req, res) => {
  try {
    const users = await User.find({})
      .select(
        'isVerified accountRole accountStatus lastLoginAt preferences integrations security refreshSessions knownDevices'
      )
      .lean();

    return res.json({
      message: 'Owner summary loaded.',
      summary: buildOwnerSummary(users),
    });
  } catch (err) {
    console.error('Owner summary error:', err);
    return res.status(500).json({ message: 'Failed to load owner summary.' });
  }
};

exports.listOwnerUsers = async (req, res) => {
  const query = normalizeOwnerSearchQuery(req.query?.q);
  const role = sanitizeText(req.query?.role, 24).toLowerCase();
  const status = sanitizeText(req.query?.status, 24).toLowerCase();
  const limit = normalizeOwnerUserListLimit(req.query?.limit);

  try {
    const users = await User.find(buildOwnerUserQuery({ query, role, status }))
      .select(FULL_USER_SELECT_FIELDS)
      .sort({ lastLoginAt: -1, createdAt: -1, _id: -1 })
      .limit(limit);

    const hydratedUsers = [];
    for (const user of users) {
      hydratedUsers.push(await ensureUserState(user));
    }

    return res.json({
      message: 'Owner user list loaded.',
      filters: {
        query,
        role,
        status,
        limit,
      },
      summary: buildOwnerSummary(hydratedUsers),
      users: hydratedUsers.map((user) => buildOwnerUserSummary(user)),
    });
  } catch (err) {
    console.error('Owner user list error:', err);
    return res.status(500).json({ message: 'Failed to load users.' });
  }
};

exports.getOwnerUser = async (req, res) => {
  try {
    const user = await getOwnerUserById(req.params.userId);

    return res.json({
      message: 'Owner user loaded.',
      ownerUser: buildOwnerUserSummary(user),
      auditEvents: Array.isArray(user.auditEvents)
        ? user.auditEvents.slice(-20).reverse().map((event) => serializeAuditEvent(event))
        : [],
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    console.error('Owner user lookup error:', err);
    return res.status(500).json({ message: 'Failed to load user.' });
  }
};

exports.updateOwnerUser = async (req, res) => {
  const incoming = req.body || {};

  try {
    const actor = await getUserById(req.user.id);
    const targetUser = await getOwnerUserById(req.params.userId);
    const changedFields = [];

    if (hasOwn(incoming, 'displayName')) {
      if (containsBlockedNameTerm(incoming.displayName)) {
        return res.status(400).json({ message: DISPLAY_NAME_MODERATION_MESSAGE });
      }
      targetUser.displayName = sanitizeDisplayName(incoming.displayName, targetUser.email);
      changedFields.push('displayName');
    }

    if (hasOwn(incoming, 'username')) {
      if (containsBlockedNameTerm(incoming.username)) {
        return res.status(400).json({ message: USERNAME_MODERATION_MESSAGE });
      }
      await applyUsernameChange(targetUser, incoming.username);
      changedFields.push('username');
    }

    if (incoming.profile && typeof incoming.profile === 'object') {
      targetUser.profile = normalizeProfile(incoming.profile, targetUser.profile || {});
      changedFields.push('profile');
    }

    if (hasOwn(incoming, 'isVerified')) {
      targetUser.isVerified = Boolean(incoming.isVerified);
      if (targetUser.isVerified) {
        targetUser.verificationToken = '';
        targetUser.verificationTokenExpires = null;
      }
      changedFields.push('verification');
    }

    if (incoming.authority && typeof incoming.authority === 'object') {
      const nextAuthority = normalizeOwnerAuthorityInput(incoming.authority, targetUser);
      await assertOwnerRetention(targetUser, {
        nextRole: nextAuthority.role,
        nextStatus: nextAuthority.status,
      });

      const previousStatus = normalizeAccountStatus(targetUser.accountStatus);
      targetUser.accountRole = nextAuthority.role;
      targetUser.accountStatus = nextAuthority.status;
      targetUser.accountStatusReason = nextAuthority.statusReason;
      if (
        previousStatus !== ACCOUNT_STATUS_SUSPENDED &&
        nextAuthority.status === ACCOUNT_STATUS_SUSPENDED
      ) {
        revokeAllTrackedSessions(targetUser);
      }
      changedFields.push('authority');
    }

    if (incoming.preferences && typeof incoming.preferences === 'object') {
      targetUser.preferences = {
        ...(targetUser.preferences || {}),
        profilePublic: hasOwn(incoming.preferences, 'profilePublic')
          ? Boolean(incoming.preferences.profilePublic)
          : Boolean(targetUser.preferences?.profilePublic),
        searchable: hasOwn(incoming.preferences, 'searchable')
          ? Boolean(incoming.preferences.searchable)
          : Boolean(targetUser.preferences?.searchable),
      };
      changedFields.push('preferences');
    }

    if (incoming.vanguard && typeof incoming.vanguard === 'object') {
      targetUser.integrations = targetUser.integrations || {};
      targetUser.integrations.vanguard = targetUser.integrations.vanguard || {};
      if (hasOwn(incoming.vanguard, 'trusted')) {
        targetUser.integrations.vanguard.trusted = Boolean(incoming.vanguard.trusted);
      }
      if (hasOwn(incoming.vanguard, 'staff')) {
        targetUser.integrations.vanguard.staff = Boolean(incoming.vanguard.staff);
      }
      if (hasOwn(incoming.vanguard, 'bannedFromAi')) {
        targetUser.integrations.vanguard.aiDenied = Boolean(incoming.vanguard.bannedFromAi);
      }
      if (hasOwn(incoming.vanguard, 'flagged')) {
        targetUser.integrations.vanguard.flagged = Boolean(incoming.vanguard.flagged);
        targetUser.integrations.vanguard.flaggedAt = targetUser.integrations.vanguard.flagged
          ? new Date()
          : null;
      }
      if (
        targetUser.integrations.vanguard.flagged ||
        hasOwn(incoming.vanguard, 'flagReason')
      ) {
        targetUser.integrations.vanguard.flagReason = targetUser.integrations.vanguard.flagged
          ? sanitizeText(
              hasOwn(incoming.vanguard, 'flagReason')
                ? incoming.vanguard.flagReason
                : targetUser.integrations.vanguard.flagReason,
              240
            )
          : '';
      }
      changedFields.push('vanguard');
    }

    if (!changedFields.length) {
      return res.status(400).json({ message: 'No owner updates were provided.' });
    }

    appendAuditEvent(targetUser, req, 'owner_account_updated', 'Owner updated this account.', {
      actorUserId: toObjectIdString(actor?._id),
      changedFields,
    });
    if (actor && toObjectIdString(actor._id) !== toObjectIdString(targetUser._id)) {
      appendAuditEvent(actor, req, 'owner_user_updated', 'Owner updated another account.', {
        targetUserId: toObjectIdString(targetUser._id),
        changedFields,
      });
    }

    await targetUser.save();
    if (actor && toObjectIdString(actor._id) !== toObjectIdString(targetUser._id)) {
      await actor.save();
    }

    return res.json({
      message: 'Owner account changes saved.',
      ownerUser: buildOwnerUserSummary(targetUser),
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    if (isDuplicateKeyError(err)) {
      return res.status(409).json({ message: getDuplicateUserFieldMessage(err) });
    }
    console.error('Owner user update error:', err);
    return res.status(500).json({ message: 'Failed to update user.' });
  }
};

exports.revokeOwnerUserSessions = async (req, res) => {
  try {
    const actor = await getUserById(req.user.id);
    const targetUser = await getOwnerUserById(req.params.userId);

    revokeAllTrackedSessions(targetUser);
    appendAuditEvent(targetUser, req, 'owner_sessions_revoked', 'Owner revoked all sessions for this account.', {
      actorUserId: toObjectIdString(actor?._id),
    });
    if (actor && toObjectIdString(actor._id) !== toObjectIdString(targetUser._id)) {
      appendAuditEvent(actor, req, 'owner_user_sessions_revoked', 'Owner revoked another account session set.', {
        targetUserId: toObjectIdString(targetUser._id),
      });
    }

    await targetUser.save();
    if (actor && toObjectIdString(actor._id) !== toObjectIdString(targetUser._id)) {
      await actor.save();
    }

    return res.json({
      message: 'All sessions revoked for that account.',
      ownerUser: buildOwnerUserSummary(targetUser),
      forceRelogin: true,
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    console.error('Owner revoke sessions error:', err);
    return res.status(500).json({ message: 'Failed to revoke sessions.' });
  }
};

exports.resetOwnerUserMfa = async (req, res) => {
  try {
    const actor = await getUserById(req.user.id);
    const targetUser = await getOwnerUserById(req.params.userId);

    clearStoredMfaState(targetUser);
    revokeAllTrackedSessions(targetUser);
    appendAuditEvent(targetUser, req, 'owner_mfa_reset', 'Owner reset MFA and revoked all sessions for this account.', {
      actorUserId: toObjectIdString(actor?._id),
    });
    if (actor && toObjectIdString(actor._id) !== toObjectIdString(targetUser._id)) {
      appendAuditEvent(actor, req, 'owner_user_mfa_reset', 'Owner reset MFA for another account.', {
        targetUserId: toObjectIdString(targetUser._id),
      });
    }

    await targetUser.save();
    if (actor && toObjectIdString(actor._id) !== toObjectIdString(targetUser._id)) {
      await actor.save();
    }

    return res.json({
      message: 'MFA reset. The user must sign in again and enroll MFA from scratch.',
      ownerUser: buildOwnerUserSummary(targetUser),
      forceRelogin: true,
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    console.error('Owner reset MFA error:', err);
    return res.status(500).json({ message: 'Failed to reset MFA.' });
  }
};

exports.resendOwnerUserVerification = async (req, res) => {
  try {
    const actor = await getUserById(req.user.id);
    const targetUser = await getOwnerUserById(req.params.userId);

    if (targetUser.isVerified) {
      return res.status(400).json({ message: 'That account is already verified.' });
    }

    const verification = prepareEmailVerification(targetUser);
    appendAuditEvent(
      targetUser,
      req,
      'owner_verification_resent',
      'Owner resent the verification email for this account.',
      { actorUserId: toObjectIdString(actor?._id) }
    );
    if (actor && toObjectIdString(actor._id) !== toObjectIdString(targetUser._id)) {
      appendAuditEvent(actor, req, 'owner_user_verification_resent', 'Owner resent verification for another account.', {
        targetUserId: toObjectIdString(targetUser._id),
      });
    }

    await targetUser.save();
    const delivery = await sendVerificationEmail(targetUser, req, verification);
    if (actor && toObjectIdString(actor._id) !== toObjectIdString(targetUser._id)) {
      await actor.save();
    }

    return res.json({
      message: delivery?.sent
        ? 'Verification email sent.'
        : 'Verification email could not be sent right now.',
      ownerUser: buildOwnerUserSummary(targetUser),
      verificationEmail: serializeVerificationDelivery(delivery),
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    console.error('Owner resend verification error:', err);
    return res.status(500).json({ message: 'Failed to resend verification email.' });
  }
};

exports.sendOwnerUserPasswordReset = async (req, res) => {
  try {
    const actor = await getUserById(req.user.id);
    const targetUser = await getOwnerUserById(req.params.userId);

    const reset = preparePasswordReset(targetUser);
    appendAuditEvent(
      targetUser,
      req,
      'owner_password_reset_sent',
      'Owner sent a password reset email for this account.',
      { actorUserId: toObjectIdString(actor?._id) }
    );
    if (actor && toObjectIdString(actor._id) !== toObjectIdString(targetUser._id)) {
      appendAuditEvent(actor, req, 'owner_user_password_reset_sent', 'Owner sent a password reset email for another account.', {
        targetUserId: toObjectIdString(targetUser._id),
      });
    }

    await targetUser.save();
    await sendPasswordResetEmail(targetUser, req, reset);
    if (actor && toObjectIdString(actor._id) !== toObjectIdString(targetUser._id)) {
      await actor.save();
    }

    return res.json({
      message: 'Password reset email sent.',
      ownerUser: buildOwnerUserSummary(targetUser),
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    console.error('Owner password reset email error:', err);
    return res.status(500).json({ message: 'Failed to send password reset email.' });
  }
};

exports.deleteOwnerUser = async (req, res) => {
  try {
    const actor = await getUserById(req.user.id);
    const targetUser = await getOwnerUserById(req.params.userId);

    await assertOwnerRetention(targetUser, { deleting: true });

    await sendSecurityAlertEmail(
      targetUser,
      'Your Continental ID account was deleted',
      'Account deleted by an owner',
      'An owner permanently deleted your Continental ID account.',
      [`Time: ${new Date().toUTCString()}`]
    );

    if (actor && toObjectIdString(actor._id) !== toObjectIdString(targetUser._id)) {
      appendAuditEvent(actor, req, 'owner_user_deleted', 'Owner deleted another account.', {
        targetUserId: toObjectIdString(targetUser._id),
      });
      await actor.save();
    }

    await User.deleteOne({ _id: targetUser._id });

    return res.json({
      message: 'Account deleted permanently.',
      deletedUserId: toObjectIdString(targetUser._id),
      deletedOwnAccount: toObjectIdString(actor?._id) === toObjectIdString(targetUser._id),
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    console.error('Owner delete user error:', err);
    return res.status(500).json({ message: 'Failed to delete account.' });
  }
};

exports.refreshToken = async (req, res) => {
  try {
    const session = await resolveRefreshSessionFromCookie(req, res);
    if (!session?.user || session.replayDetected) {
      clearRefreshCookie(res, req);
      return res.status(200).json(
        buildAuthErrorPayload(req, {
          code: AUTH_ERROR_CODE.refreshSessionMissing,
          message: 'No active refresh session.',
        })
      );
    }

    if (!session.user.isVerified) {
      clearRefreshCookie(res, req);
      return res.status(200).json(
        buildAuthErrorPayload(req, {
          code: AUTH_ERROR_CODE.emailUnverified,
          message: 'Verify your email before signing in.',
          requiresVerification: true,
        })
      );
    }

    if (isSuspendedAccount(session.user.accountStatus)) {
      clearRefreshCookie(res, req);
      return res.status(200).json(
        buildAuthErrorPayload(req, {
          code: AUTH_ERROR_CODE.suspended,
          message: 'This account is suspended.',
        })
      );
    }

    let tokenPair;
    if (session.tokenState === 'grace') {
      tokenPair = reissueCurrentRefreshSession(session.user, req, session.sid, session.session);
    } else if (session.sid) {
      tokenPair = rotateRefreshSessionToken(session.user, req, session.sid, session.session);
    } else {
      tokenPair = createTrackedRefreshSession(session.user, req);
    }

    await session.user.save();

    res.cookie('refreshToken', tokenPair.refreshToken, buildCookieOptions(req));

    return res.json({
      ...buildAuthSuccessMeta(req, {
        sessionEstablished: true,
      }),
      message: 'Session refreshed.',
      authenticated: true,
      token: tokenPair.accessToken,
      accessToken: tokenPair.accessToken,
      userId: toObjectIdString(session.user._id),
      continentalId: toObjectIdString(session.user._id),
    });
  } catch (err) {
    console.error('Refresh token error:', err);
    clearRefreshCookie(res, req);
    return res.status(200).json(
      buildAuthErrorPayload(req, {
        code: AUTH_ERROR_CODE.invalidRefreshSession,
        message: 'Invalid refresh session.',
      })
    );
  }
};

exports.updateProfile = async (req, res) => {
  const incoming = req.body || {};
  const currentPassword = req.body?.currentPassword || '';
  const mfaCode = sanitizeMfaCode(req.body?.mfaCode);
  const backupCode = sanitizeBackupCode(req.body?.backupCode);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    let verification = null;
    let emailChanged = false;
    const previousEmail = sanitizeText(user.email, 320);
    const previousEmailWasVerified = Boolean(user.isVerified);

    if (hasOwn(incoming, 'username')) {
      if (!normalizeUsername(incoming.username)) {
        return res.status(400).json({ message: USERNAME_VALIDATION_MESSAGE });
      }
      if (containsBlockedNameTerm(incoming.username)) {
        return res.status(400).json({ message: USERNAME_MODERATION_MESSAGE });
      }
      await applyUsernameChange(user, incoming.username);
    }

    if (hasOwn(incoming, 'displayName')) {
      const displayName = sanitizeText(incoming.displayName, 60);
      if (displayName.length < 2) {
        return res.status(400).json({ message: 'Display name must be at least 2 characters.' });
      }
      if (containsBlockedNameTerm(displayName)) {
        return res.status(400).json({ message: DISPLAY_NAME_MODERATION_MESSAGE });
      }
      user.displayName = displayName;
    }

    if (hasOwn(incoming, 'email')) {
      emailChanged = await applyEmailChange(user, incoming.email, currentPassword);
      if (emailChanged) {
        const mfaResult = await verifyMfaChallenge(user, req, { mfaCode, backupCode });
        if (!mfaResult.ok) {
          user.email = previousEmail;
          await user.save();
          return sendProtectedActionMfaError(
            res,
            mfaResult,
            'Enter your MFA code to change your email.'
          );
        }
        verification = prepareEmailVerification(user);
        revokeAllTrackedSessions(user);
      }
    }

    user.profile = normalizeProfile(incoming, user.profile || {});
    appendAuditEvent(
      user,
      req,
      'profile_updated',
      emailChanged ? 'Profile updated and email changed.' : 'Profile updated.',
      { emailChanged }
    );
    await user.save();

    const verificationDelivery = verification
      ? await sendVerificationEmail(user, req, verification)
      : null;

    if (emailChanged) {
      if (previousEmailWasVerified && previousEmail && previousEmail !== user.email) {
        await sendSecurityAlertEmail(
          user,
          'Your Continental ID email was changed',
          'Email change detected',
          'The email address on your Continental ID account was changed. If this was not you, secure your account immediately.',
          buildEmailChangeSecurityDetails(req, previousEmail, user.email),
          { emailOverride: previousEmail }
        );
      }

      clearRefreshCookie(res, req);
    }

    const message = verification
      ? getVerificationDeliveryMessage(
          'Profile updated. Verify your new email before signing in again.',
          'Profile updated. Check your inbox for the verification email that was already sent.',
          'Profile updated, but the verification email could not be sent right now.',
          verificationDelivery
        )
      : 'Profile updated.';

    return sendUserResponse(res, 200, message, user, {
      verificationEmail: verification ? serializeVerificationDelivery(verificationDelivery) : undefined,
      forceRelogin: emailChanged,
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    if (isDuplicateKeyError(err)) {
      return res.status(409).json({ message: getDuplicateUserFieldMessage(err) });
    }
    console.error('Update profile error:', err);
    return res.status(500).json({ message: 'Failed to update profile.' });
  }
};

exports.updateEmail = async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const currentPassword = req.body?.currentPassword || '';
  const mfaCode = sanitizeMfaCode(req.body?.mfaCode);
  const backupCode = sanitizeBackupCode(req.body?.backupCode);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const previousEmail = sanitizeText(user.email, 320);
    const previousEmailWasVerified = Boolean(user.isVerified);
    const emailChanged = await applyEmailChange(user, email, currentPassword);
    let verification = null;
    if (emailChanged) {
      const mfaResult = await verifyMfaChallenge(user, req, { mfaCode, backupCode });
      if (!mfaResult.ok) {
        user.email = previousEmail;
        await user.save();
        return sendProtectedActionMfaError(
          res,
          mfaResult,
          'Enter your MFA code to change your email.'
        );
      }
      verification = prepareEmailVerification(user);
      revokeAllTrackedSessions(user);
    }

    appendAuditEvent(
      user,
      req,
      'email_updated',
      emailChanged ? 'Email updated.' : 'Email update checked.',
      { emailChanged }
    );
    await user.save();

    const verificationDelivery = verification
      ? await sendVerificationEmail(user, req, verification)
      : null;

    if (emailChanged) {
      if (previousEmailWasVerified && previousEmail && previousEmail !== user.email) {
        await sendSecurityAlertEmail(
          user,
          'Your Continental ID email was changed',
          'Email change detected',
          'The email address on your Continental ID account was changed. If this was not you, secure your account immediately.',
          buildEmailChangeSecurityDetails(req, previousEmail, user.email),
          { emailOverride: previousEmail }
        );
      }

      clearRefreshCookie(res, req);
    }

    const message = verification
      ? getVerificationDeliveryMessage(
          'Email updated. Verify your new email before signing in again.',
          'Email updated. Check your inbox for the verification email that was already sent.',
          'Email updated, but the verification email could not be sent right now.',
          verificationDelivery
        )
      : 'Email updated.';

    return sendUserResponse(res, 200, message, user, {
      verificationEmail: verification ? serializeVerificationDelivery(verificationDelivery) : undefined,
      forceRelogin: emailChanged,
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    if (isDuplicateKeyError(err)) {
      return res.status(409).json({ message: getDuplicateUserFieldMessage(err) });
    }
    console.error('Update email error:', err);
    return res.status(500).json({ message: 'Failed to update email.' });
  }
};

exports.resendVerificationEmail = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (user.isVerified) {
      return res.status(400).json({ message: 'Email is already verified.' });
    }

    let verificationDelivery = { sent: false, reason: 'cooldown' };
    if (!(hasPendingEmailVerification(user) && getVerificationEmailCooldownRemainingMs(user) > 0)) {
      const verification = prepareEmailVerification(user);
      appendAuditEvent(user, req, 'verification_resent', 'Verification email resent.');
      await user.save();
      verificationDelivery = await sendVerificationEmail(user, req, verification);
    }

    const message = getVerificationDeliveryMessage(
      'Verification email sent.',
      'A verification email was already sent recently. Check your inbox before requesting another one.',
      'Verification email could not be sent right now.',
      verificationDelivery
    );

    return sendUserResponse(res, 200, message, user, {
      verificationEmail: serializeVerificationDelivery(verificationDelivery),
    });
  } catch (err) {
    console.error('Resend verification email error:', err);
    return res.status(500).json({ message: 'Failed to resend verification email.' });
  }
};

exports.getPreferences = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    return res.json({
      message: 'Preferences loaded.',
      preferences: buildUserPayload(user).preferences,
    });
  } catch (err) {
    console.error('Get preferences error:', err);
    return res.status(500).json({ message: 'Failed to load preferences.' });
  }
};

exports.updatePreferences = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    user.preferences = normalizePreferences(req.body || {}, user.preferences || {});
    appendAuditEvent(user, req, 'preferences_updated', 'Preferences updated.');
    await user.save();

    return sendUserResponse(res, 200, 'Preferences updated.', user);
  } catch (err) {
    console.error('Update preferences error:', err);
    return res.status(500).json({ message: 'Failed to update preferences.' });
  }
};

exports.startOauthLogin = async (req, res) => {
  const providerLabel = getOauthProviderLabel(req.params.provider);

  try {
    const config = getOauthProviderConfig(req.params.provider, req);
    const targetOrigin = resolveTrustedOauthAppOrigin(req.query?.origin || DEFAULT_DASHBOARD_ORIGIN);
    if (!targetOrigin) {
      throw createHttpError(503, 'OAuth app origins are not configured on this server.');
    }
    const redirectUrl = resolveTrustedOauthRedirectUrl(req.query?.redirect, targetOrigin);
    const returnTo = resolveTrustedOauthRedirectUrl(
      req.query?.returnTo || req.query?.return_to || resolveLoginPopupPageUrl(req) || redirectUrl,
      targetOrigin
    );
    const state = buildOauthStateToken({
      flow: 'login',
      provider: config.provider,
      targetOrigin,
      redirectUrl,
      returnTo,
    });
    return res.redirect(buildOauthAuthorizeUrl(config, state));
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).send(
        renderOauthResultPage({
          title: `${providerLabel} sign-in unavailable`,
          message: err.message,
          redirectUrl: resolveTrustedOauthRedirectUrl(req.query?.returnTo || req.query?.redirect),
          targetOrigin: resolveTrustedOauthAppOrigin(req.query?.origin || ''),
          closeWindow: false,
        })
      );
    }
    console.error('Start OAuth login error:', err);
    return res.status(500).send(
      renderOauthResultPage({
        title: `${providerLabel} sign-in unavailable`,
        message: `Could not start ${providerLabel} sign-in.`,
        redirectUrl: resolveTrustedOauthRedirectUrl(req.query?.returnTo || req.query?.redirect),
        targetOrigin: resolveTrustedOauthAppOrigin(req.query?.origin || ''),
        closeWindow: false,
      })
    );
  }
};

exports.startOauthLink = async (req, res) => {
  const providerLabel = getOauthProviderLabel(req.params.provider);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const config = getOauthProviderConfig(req.params.provider, req);
    const browserOrigin = extractBrowserOrigin(req);
    const targetOrigin = resolveTrustedOauthAppOrigin(
      req.body?.origin || browserOrigin || DEFAULT_DASHBOARD_ORIGIN
    );
    if (!targetOrigin) {
      throw createHttpError(503, 'OAuth app origins are not configured on this server.');
    }
    const redirectUrl = resolveTrustedOauthRedirectUrl(req.body?.redirect, targetOrigin);
    const returnTo = resolveTrustedOauthRedirectUrl(req.body?.returnTo || redirectUrl, targetOrigin);
    const state = buildOauthStateToken({
      flow: 'link',
      provider: config.provider,
      userId: req.user.id,
      targetOrigin,
      redirectUrl,
      returnTo,
    });

    return res.json({
      message: `${providerLabel} linking ready.`,
      url: buildOauthAuthorizeUrl(config, state),
      provider: config.provider,
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    console.error('Start OAuth link error:', err);
    return res.status(500).json({ message: 'Failed to start identity linking.' });
  }
};

exports.finishOauthCallback = async (req, res) => {
  let statePayload = null;

  try {
    const code = sanitizeText(req.query?.code, 4000);
    if (!code) {
      throw createHttpError(400, 'OAuth callback did not include an authorization code.');
    }

    const config = getOauthProviderConfig(req.params.provider, req);
    statePayload = readOauthStateToken(req.query?.state);
    if (sanitizeText(statePayload.provider, 40).toLowerCase() !== config.provider) {
      throw createHttpError(400, 'OAuth callback provider mismatch.');
    }

    const providerLabel = getOauthProviderLabel(config.provider);
    const tokenPayload = await requestOauthAccessToken(config, code);
    const identityProfile = await requestOauthIdentityProfile(config, tokenPayload);
    const targetOrigin = resolveTrustedOauthAppOrigin(statePayload.targetOrigin || '');
    const redirectUrl = resolveTrustedOauthRedirectUrl(statePayload.redirectUrl, targetOrigin);
    const returnTo = resolveTrustedOauthRedirectUrl(statePayload.returnTo || redirectUrl, targetOrigin);

    if (statePayload.flow === 'link') {
      const targetUser = await getUserById(statePayload.userId);
      if (!targetUser) {
        throw createHttpError(404, 'The account for this link request could not be found.');
      }

      const existingUser = await findUserByOauthIdentity(
        config.provider,
        identityProfile.providerUserId
      );
      if (existingUser && toObjectIdString(existingUser._id) !== toObjectIdString(targetUser._id)) {
        throw createHttpError(
          409,
          `That ${providerLabel} account is already linked to another user.`
        );
      }

      upsertOauthIdentity(targetUser, {
        ...identityProfile,
        provider: config.provider,
        lastUsedAt: new Date(),
      });
      const linkedAccountAutofill = getOauthLinkedAccountAutofillValue(
        config.provider,
        identityProfile
      );
      if (
        linkedAccountAutofill &&
        !sanitizeText(targetUser.linkedAccounts?.[config.provider], 120)
      ) {
        targetUser.linkedAccounts[config.provider] = linkedAccountAutofill;
      }

      appendAuditEvent(targetUser, req, 'oauth_provider_linked', `${providerLabel} account linked.`, {
        provider: config.provider,
        username: identityProfile.username,
      });
      await targetUser.save();

      return res.send(
        renderOauthResultPage({
          title: `${providerLabel} linked`,
          message: `Your ${providerLabel} account is now linked to Continental ID.`,
          redirectUrl: returnTo,
          targetOrigin,
          messagePayload: buildAuthResultMessagePayload(req, {
            event: 'oauth_linked',
            message: `Your ${providerLabel} account is now linked to Continental ID.`,
            provider: config.provider,
          }),
        })
      );
    }

    let user = await findUserByOauthIdentity(config.provider, identityProfile.providerUserId);
    let createdAccount = false;

    if (!user) {
      if (!identityProfile.email || !identityProfile.emailVerified) {
        throw createHttpError(
          400,
          `${providerLabel} must provide a verified email address before it can create a Continental ID account.`
        );
      }

      const existingByEmail = await User.findOne({ email: identityProfile.email }).select(
        FULL_USER_SELECT_FIELDS
      );
      if (existingByEmail) {
        throw createHttpError(
          409,
          `That email already belongs to a Continental ID account. Sign in normally first, then link ${providerLabel} from the dashboard.`
        );
      }

      createdAccount = true;
      user = new User({
        email: identityProfile.email,
        password: `Aa1!${crypto.randomBytes(24).toString('hex')}`,
        displayName: sanitizeDisplayName(identityProfile.displayName, identityProfile.email),
        profile: normalizeProfile(
          {
            avatar: identityProfile.avatarUrl,
            website: identityProfile.profileUrl,
          },
          {}
        ),
        preferences: normalizePreferences({}, {}),
        isVerified: true,
        verificationToken: '',
        verificationTokenExpires: null,
      });

      await assignAvailableUsername(
        user,
        ...getOauthIdentityUsernameCandidates(config.provider, identityProfile)
      );
    }

    upsertOauthIdentity(user, {
      ...identityProfile,
      provider: config.provider,
      lastUsedAt: new Date(),
    });
    const linkedAccountAutofill = getOauthLinkedAccountAutofillValue(
      config.provider,
      identityProfile
    );
    if (linkedAccountAutofill && !sanitizeText(user.linkedAccounts?.[config.provider], 120)) {
      user.linkedAccounts[config.provider] = linkedAccountAutofill;
    }

    if (isMfaEnabledForUser(user)) {
      appendAuditEvent(
        user,
        req,
        'oauth_login_blocked_mfa',
        `${providerLabel} sign-in was blocked because MFA must be completed through the standard sign-in flow.`,
        {
          provider: config.provider,
        }
      );
      await user.save();

      return res.status(403).send(
        renderOauthResultPage({
          title: 'Additional verification required',
          message:
            'This account requires multi-factor authentication. Sign in with your password first, then complete MFA to continue.',
          redirectUrl: returnTo,
          targetOrigin,
          closeWindow: false,
          messagePayload: buildAuthResultMessagePayload(req, {
            code: AUTH_ERROR_CODE.mfaRequired,
            event: 'login_error',
            message:
              'This account requires multi-factor authentication. Sign in with your password first, then complete MFA to continue.',
            provider: config.provider,
          }),
        })
      );
    }

    if (createdAccount) {
      appendAuditEvent(user, req, 'oauth_register', `Account created with ${providerLabel} sign-in.`, {
        provider: config.provider,
      });
    }

    const { sessionTokens } = await issueInteractiveSession(req, res, user, {
      auditType: 'oauth_login',
      auditMessage: `Signed in with ${providerLabel}.`,
      auditMeta: {
        provider: config.provider,
      },
    });

    res.cookie('refreshToken', sessionTokens.refreshToken, buildCookieOptions(req));

    return res.send(
      renderOauthResultPage({
        title: `${providerLabel} sign-in complete`,
        message: 'Returning to your Continental ID session.',
        redirectUrl,
        targetOrigin,
        messagePayload: buildAuthResultMessagePayload(req, {
          accessToken: sessionTokens.accessToken,
          apiBaseUrl: getRequestOrigin(req),
          event: 'login_success',
          message: 'Returning to your Continental ID session.',
          provider: config.provider,
          user: buildUserPayload(user),
        }),
      })
    );
  } catch (err) {
    const targetOrigin = resolveTrustedOauthAppOrigin(statePayload?.targetOrigin || '');
    const returnTo = resolveTrustedOauthRedirectUrl(
      statePayload?.returnTo || statePayload?.redirectUrl,
      targetOrigin || DEFAULT_DASHBOARD_ORIGIN
    );
    const providerLabel = getOauthProviderLabel(statePayload?.provider || req.params.provider);
    const statusCode = err?.statusCode || 500;
    const message =
      err?.message || `Could not complete ${providerLabel} sign-in right now. Please try again later.`;

    if (statusCode >= 500) {
      console.error('Finish OAuth callback error:', err);
    }

    return res.status(statusCode).send(
      renderOauthResultPage({
        title:
          statusCode >= 500
            ? `${providerLabel} sign-in failed`
            : `${providerLabel} sign-in could not continue`,
        message,
        redirectUrl: returnTo,
        targetOrigin,
        closeWindow: false,
        messagePayload: buildAuthResultMessagePayload(req, {
          code:
            statusCode >= 500
              ? AUTH_ERROR_CODE.unavailable
              : err?.statusCode === 409
                ? AUTH_ERROR_CODE.identityConflict
                : AUTH_ERROR_CODE.authorizationDenied,
          event: 'login_error',
          message,
          provider: statePayload?.provider || req.params.provider,
        }),
      })
    );
  }
};

exports.getLinkedAccounts = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    return res.json({
      message: 'Linked accounts loaded.',
      linkedAccounts: buildUserPayload(user).linkedAccounts,
      oauthProviders: buildUserPayload(user).oauthProviders,
    });
  } catch (err) {
    console.error('Get linked accounts error:', err);
    return res.status(500).json({ message: 'Failed to load linked accounts.' });
  }
};

exports.unlinkOauthProvider = async (req, res) => {
  const provider = sanitizeText(req.params.provider, 40).toLowerCase();

  try {
    if (!OAUTH_PROVIDERS.includes(provider)) {
      return res.status(404).json({ message: 'That identity provider is not supported yet.' });
    }

    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const removed = removeOauthIdentity(user, provider);
    if (!removed) {
      return res.status(404).json({ message: 'That provider is not linked to this account.' });
    }

    const linkedAccountAutofill = getOauthLinkedAccountAutofillValue(provider, {
      username: user.linkedAccounts?.[provider],
    });
    if (linkedAccountAutofill && sanitizeText(user.linkedAccounts?.[provider], 120) === linkedAccountAutofill) {
      user.linkedAccounts[provider] = '';
    }

    appendAuditEvent(
      user,
      req,
      'oauth_provider_unlinked',
      `${getOauthProviderLabel(provider)} account unlinked.`,
      {
      provider,
      }
    );
    await user.save();

    return sendUserResponse(
      res,
      200,
      `${getOauthProviderLabel(provider)} account unlinked.`,
      user
    );
  } catch (err) {
    console.error('Unlink OAuth provider error:', err);
    return res.status(500).json({ message: 'Failed to unlink the identity provider.' });
  }
};

exports.updateLinkedAccounts = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    user.linkedAccounts = normalizeLinkedAccounts(req.body || {}, user.linkedAccounts || {});
    appendAuditEvent(user, req, 'linked_accounts_updated', 'External profiles updated.');
    await user.save();

    return sendUserResponse(res, 200, 'Linked accounts updated.', user);
  } catch (err) {
    console.error('Update linked accounts error:', err);
    return res.status(500).json({ message: 'Failed to update linked accounts.' });
  }
};

exports.getActivity = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const payload = buildUserPayload(user);

    return res.json({
      message: 'Activity loaded.',
      recentLogins: payload.recentLogins,
      auditEvents: payload.auditEvents,
      lastLoginAt: payload.lastLoginAt,
      lastLoginIp: payload.lastLoginIp,
      summary: payload.activitySummary,
    });
  } catch (err) {
    console.error('Get activity error:', err);
    return res.status(500).json({ message: 'Failed to load activity.' });
  }
};

exports.beginPasskeyRegistration = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const mfaCode = sanitizeMfaCode(req.body?.mfaCode);
  const backupCode = sanitizeBackupCode(req.body?.backupCode);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (getStoredPasskeys(user).length >= MAX_PASSKEYS) {
      return res.status(400).json({ message: `You can store up to ${MAX_PASSKEYS} passkeys.` });
    }

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    const mfaResult = await verifyMfaChallenge(user, req, { mfaCode, backupCode });
    if (!mfaResult.ok) {
      await user.save();
      return sendProtectedActionMfaError(res, mfaResult, 'Enter your MFA code to add a passkey.');
    }

    const { origin, rpID } = resolveWebAuthnContext(req);
    const options = await generateRegistrationOptions({
      rpName: WEBAUTHN_RP_NAME,
      rpID,
      userName: sanitizeText(user.email || getDisplayableUsername(user), 120) || 'user',
      userDisplayName: sanitizeText(user.displayName || getDisplayableUsername(user), 60) || 'User',
      userID: isoUint8Array.fromUTF8String(getWebAuthnUserId(user)),
      attestationType: 'none',
      excludeCredentials: getStoredPasskeys(user).map((passkey) => ({
        id: sanitizeText(passkey?.credentialId, 512),
        transports: Array.isArray(passkey?.transports) ? passkey.transports : [],
      })),
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
    });

    storeWebAuthnChallenge(res, req, {
      flow: 'registration',
      challenge: options.challenge,
      origin,
      rpID,
      userId: toObjectIdString(user._id),
    });

    return res.json({
      message: 'Passkey registration ready.',
      options,
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    console.error('Begin passkey registration error:', err);
    return res.status(500).json({ message: 'Failed to start passkey registration.' });
  }
};

exports.finishPasskeyRegistration = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      clearWebAuthnChallengeCookie(res, req);
      return res.status(404).json({ message: 'User not found.' });
    }

    const challenge = readWebAuthnChallenge(req, 'registration');
    if (sanitizeText(challenge.userId, 120) !== toObjectIdString(user._id)) {
      clearWebAuthnChallengeCookie(res, req);
      return res.status(400).json({ message: 'This passkey setup request does not match your account.' });
    }

    if (getStoredPasskeys(user).length >= MAX_PASSKEYS) {
      clearWebAuthnChallengeCookie(res, req);
      return res.status(400).json({ message: `You can store up to ${MAX_PASSKEYS} passkeys.` });
    }

    const verification = await verifyRegistrationResponse({
      response: req.body?.credential || req.body,
      expectedChallenge: challenge.challenge,
      expectedOrigin: challenge.origin,
      expectedRPID: challenge.rpID,
      requireUserVerification: true,
    });

    if (!verification.verified || !verification.registrationInfo) {
      clearWebAuthnChallengeCookie(res, req);
      return res.status(400).json({ message: 'Passkey registration could not be verified.' });
    }

    const credentialId = sanitizeText(verification.registrationInfo.credential.id, 512);
    if (!credentialId) {
      clearWebAuthnChallengeCookie(res, req);
      return res.status(400).json({ message: 'Passkey registration returned an invalid credential.' });
    }

    if (findStoredPasskey(user, credentialId)) {
      clearWebAuthnChallengeCookie(res, req);
      return res.status(409).json({ message: 'That passkey is already registered on this account.' });
    }

    const credentialResponse = req.body?.credential?.response || req.body?.response || {};
    const nextName = sanitizePasskeyName(
      req.body?.name,
      buildDefaultPasskeyName(req, getStoredPasskeys(user).length)
    );

    user.security.passkeys.push({
      credentialId,
      publicKey: Buffer.from(verification.registrationInfo.credential.publicKey),
      counter: Number(verification.registrationInfo.credential.counter || 0),
      transports: Array.isArray(credentialResponse.transports)
        ? credentialResponse.transports.map((transport) => sanitizeText(transport, 24)).filter(Boolean)
        : [],
      deviceType:
        verification.registrationInfo.credentialDeviceType === 'multiDevice'
          ? 'multiDevice'
          : 'singleDevice',
      backedUp: Boolean(verification.registrationInfo.credentialBackedUp),
      aaguid: sanitizeText(verification.registrationInfo.aaguid, 64),
      name: nextName,
      createdAt: new Date(),
      lastUsedAt: null,
    });

    appendAuditEvent(user, req, 'passkey_registered', 'Passkey added.', {
      credentialId,
      passkeyName: nextName,
    });
    await user.save();
    clearWebAuthnChallengeCookie(res, req);

    return sendUserResponse(res, 200, 'Passkey added.', user, {
      security: buildUserPayload(user).security,
    });
  } catch (err) {
    clearWebAuthnChallengeCookie(res, req);
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    if (isDuplicateKeyError(err)) {
      return res.status(409).json({ message: 'That passkey is already linked to another account.' });
    }
    console.error('Finish passkey registration error:', err);
    return res.status(500).json({ message: 'Failed to save the new passkey.' });
  }
};

exports.beginPasskeyAuthentication = async (req, res) => {
  try {
    const { origin, rpID } = resolveWebAuthnContext(req);
    const options = await generateAuthenticationOptions({
      rpID,
      userVerification: 'required',
    });

    storeWebAuthnChallenge(res, req, {
      flow: 'authentication',
      challenge: options.challenge,
      origin,
      rpID,
    });

    return res.json({
      message: 'Passkey authentication ready.',
      options,
    });
  } catch (err) {
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    console.error('Begin passkey authentication error:', err);
    return res.status(500).json({ message: 'Failed to start passkey sign-in.' });
  }
};

exports.finishPasskeyAuthentication = async (req, res) => {
  try {
    const challenge = readWebAuthnChallenge(req, 'authentication');
    const credentialResponse = req.body?.credential || req.body || {};
    const credentialId = sanitizeText(credentialResponse.id, 512);
    if (!credentialId) {
      clearWebAuthnChallengeCookie(res, req);
      return res.status(400).json({ message: 'Passkey sign-in returned an invalid credential.' });
    }

    const user = await User.findOne({ 'security.passkeys.credentialId': credentialId }).select(
      FULL_USER_SELECT_FIELDS
    );
    if (!user) {
      clearWebAuthnChallengeCookie(res, req);
      return res.status(400).json({ message: 'That passkey is not recognized.' });
    }

    await ensureUserIdentityFields(user);

    if (!user.isVerified) {
      clearWebAuthnChallengeCookie(res, req);
      clearRefreshCookie(res, req);
      return res.status(403).json({
        authenticated: false,
        requiresVerification: true,
        message: 'Verify your email before signing in.',
      });
    }

    const passkey = findStoredPasskey(user, credentialId);
    if (!passkey) {
      clearWebAuthnChallengeCookie(res, req);
      return res.status(400).json({ message: 'That passkey is not recognized.' });
    }

    const verification = await verifyAuthenticationResponse({
      response: credentialResponse,
      expectedChallenge: challenge.challenge,
      expectedOrigin: challenge.origin,
      expectedRPID: challenge.rpID,
      credential: {
        id: sanitizeText(passkey.credentialId, 512),
        publicKey: new Uint8Array(passkey.publicKey),
        counter: Number(passkey.counter || 0),
        transports: Array.isArray(passkey.transports) ? passkey.transports : [],
      },
      requireUserVerification: true,
    });

    if (!verification.verified || !verification.authenticationInfo) {
      clearWebAuthnChallengeCookie(res, req);
      return res.status(400).json({ message: 'Passkey sign-in could not be verified.' });
    }

    passkey.counter = Number(verification.authenticationInfo.newCounter || passkey.counter || 0);
    passkey.deviceType =
      verification.authenticationInfo.credentialDeviceType === 'multiDevice'
        ? 'multiDevice'
        : 'singleDevice';
    passkey.backedUp = Boolean(verification.authenticationInfo.credentialBackedUp);
    passkey.lastUsedAt = new Date();
    clearWebAuthnChallengeCookie(res, req);

    return completeInteractiveSignIn(res, req, user, {
      auditType: 'passkey_login',
      auditMessage: 'Signed in with a passkey.',
      auditMeta: {
        credentialId,
        passkeyName: sanitizePasskeyName(passkey.name, 'Passkey'),
      },
      alertTitle: 'New device passkey sign-in to Continental ID',
      alertHeading: 'New device passkey sign-in detected',
      alertCopy: 'A passkey sign-in from a device we had not seen before was detected on your account.',
      alertDetails: [
        `Time: ${new Date().toUTCString()}`,
        `IP address: ${parseClientIp(req) || 'Unknown'}`,
        `Device: ${buildSessionLabel('', parseUserAgent(req))}`,
        `Passkey: ${sanitizePasskeyName(passkey.name, 'Passkey')}`,
      ],
    });
  } catch (err) {
    clearWebAuthnChallengeCookie(res, req);
    if (err?.statusCode) {
      return res.status(err.statusCode).json({ message: err.message });
    }
    console.error('Finish passkey authentication error:', err);
    return res.status(500).json({ message: 'Failed to complete passkey sign-in.' });
  }
};

exports.deletePasskey = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const mfaCode = sanitizeMfaCode(req.body?.mfaCode);
  const backupCode = sanitizeBackupCode(req.body?.backupCode);
  const credentialId = sanitizeText(req.params.credentialId, 512);

  try {
    if (!credentialId) {
      return res.status(400).json({ message: 'Passkey id is required.' });
    }

    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    const mfaResult = await verifyMfaChallenge(user, req, { mfaCode, backupCode });
    if (!mfaResult.ok) {
      await user.save();
      return sendProtectedActionMfaError(
        res,
        mfaResult,
        'Enter your MFA code to remove a passkey.'
      );
    }

    const nextPasskeys = getStoredPasskeys(user).filter(
      (passkey) => sanitizeText(passkey?.credentialId, 512) !== credentialId
    );
    if (nextPasskeys.length === getStoredPasskeys(user).length) {
      return res.status(404).json({ message: 'Passkey not found.' });
    }

    user.security.passkeys = nextPasskeys;
    appendAuditEvent(user, req, 'passkey_removed', 'Passkey removed.', {
      credentialId,
    });
    await user.save();

    return sendUserResponse(res, 200, 'Passkey removed.', user);
  } catch (err) {
    console.error('Delete passkey error:', err);
    return res.status(500).json({ message: 'Failed to remove the passkey.' });
  }
};

exports.getSecurity = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const payload = buildUserPayload(user);

    return res.json({
      message: 'Security settings loaded.',
      security: payload.security,
      sessionLimit: MAX_ACTIVE_SESSIONS,
      mfa: payload.security.mfa,
      passkeys: payload.security.passkeys,
      passkeyLimit: MAX_PASSKEYS,
    });
  } catch (err) {
    console.error('Get security error:', err);
    return res.status(500).json({ message: 'Failed to load security settings.' });
  }
};

exports.updateSecurity = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (typeof req.body?.loginAlerts === 'boolean') {
      user.security.loginAlerts = req.body.loginAlerts;
    }

    appendAuditEvent(user, req, 'security_updated', 'Security settings updated.');
    await user.save();

    return sendUserResponse(res, 200, 'Security settings updated.', user);
  } catch (err) {
    console.error('Update security error:', err);
    return res.status(500).json({ message: 'Failed to update security settings.' });
  }
};

exports.beginMfaSetup = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (isMfaEnabledForUser(user)) {
      return res.status(400).json({ message: 'MFA is already enabled on this account.' });
    }

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    const secret = generateMfaSecret();
    const backupCodes = generateBackupCodes(MFA_BACKUP_CODE_COUNT);

    user.security.mfa.pendingSecret = encryptMfaSecret(secret);
    user.security.mfa.pendingBackupCodes = hashBackupCodes(backupCodes);
    user.security.mfa.pendingCreatedAt = new Date();
    await user.save();

    return res.json({
      message: 'MFA setup ready.',
      setup: await buildMfaSetupPayload(user, secret, backupCodes),
      mfa: getMfaState(user),
    });
  } catch (err) {
    console.error('Begin MFA setup error:', err);
    return res.status(500).json({ message: 'Failed to start MFA setup.' });
  }
};

exports.enableMfa = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const code = sanitizeMfaCode(req.body?.code);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const pendingSecret = getPendingMfaSecret(user);
    if (!pendingSecret) {
      return res.status(400).json({ message: 'Start MFA setup before enabling it.' });
    }

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    if (!verifyTotp({ secret: pendingSecret, token: code })) {
      return res.status(400).json({ message: 'Invalid MFA code.' });
    }

    user.security.mfa.enabled = true;
    user.security.mfa.secret = encryptMfaSecret(pendingSecret);
    user.security.mfa.backupCodes = Array.isArray(user.security.mfa.pendingBackupCodes)
      ? [...user.security.mfa.pendingBackupCodes]
      : [];
    user.security.mfa.pendingSecret = '';
    user.security.mfa.pendingBackupCodes = [];
    user.security.mfa.pendingCreatedAt = null;
    user.security.mfa.enrolledAt = new Date();
    user.security.mfa.lastUsedAt = new Date();

    appendAuditEvent(user, req, 'mfa_enabled', 'Multi-factor authentication enabled.');
    await user.save();

    return sendUserResponse(res, 200, 'Multi-factor authentication enabled.', user);
  } catch (err) {
    console.error('Enable MFA error:', err);
    return res.status(500).json({ message: 'Failed to enable MFA.' });
  }
};

exports.disableMfa = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const code = sanitizeMfaCode(req.body?.code || req.body?.mfaCode);
  const backupCode = sanitizeBackupCode(req.body?.backupCode);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (!isMfaEnabledForUser(user)) {
      return res.status(400).json({ message: 'MFA is not enabled.' });
    }

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    const mfaResult = await verifyMfaChallenge(user, req, { mfaCode: code, backupCode });
    if (!mfaResult.ok) {
      await user.save();
      if (mfaResult.reason === 'blocked') {
        return res.status(429).json({
          message: `Too many invalid MFA attempts. Try again in ${mfaResult.retryAfterSec} seconds.`,
          retryAfterSec: mfaResult.retryAfterSec,
          mfaRequired: true,
        });
      }
      return res.status(403).json({
        message: mfaResult.reason === 'invalid' ? 'Invalid MFA code.' : 'Enter your MFA code to continue.',
        mfaRequired: true,
      });
    }

    clearStoredMfaState(user);

    appendAuditEvent(user, req, 'mfa_disabled', 'Multi-factor authentication disabled.');
    await user.save();

    return sendUserResponse(res, 200, 'Multi-factor authentication disabled.', user);
  } catch (err) {
    console.error('Disable MFA error:', err);
    return res.status(500).json({ message: 'Failed to disable MFA.' });
  }
};

exports.regenerateMfaBackupCodes = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const code = sanitizeMfaCode(req.body?.code || req.body?.mfaCode);
  const backupCode = sanitizeBackupCode(req.body?.backupCode);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    if (!isMfaEnabledForUser(user)) {
      return res.status(400).json({ message: 'MFA is not enabled.' });
    }

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    const mfaResult = await verifyMfaChallenge(user, req, { mfaCode: code, backupCode });
    if (!mfaResult.ok) {
      await user.save();
      if (mfaResult.reason === 'blocked') {
        return res.status(429).json({
          message: `Too many invalid MFA attempts. Try again in ${mfaResult.retryAfterSec} seconds.`,
          retryAfterSec: mfaResult.retryAfterSec,
          mfaRequired: true,
        });
      }
      return res.status(403).json({
        message: mfaResult.reason === 'invalid' ? 'Invalid MFA code.' : 'Enter your MFA code to continue.',
        mfaRequired: true,
      });
    }

    const backupCodes = generateBackupCodes(MFA_BACKUP_CODE_COUNT);
    user.security.mfa.backupCodes = hashBackupCodes(backupCodes);
    appendAuditEvent(user, req, 'mfa_backup_codes_regenerated', 'Backup codes regenerated.');
    await user.save();

    return res.json({
      message: 'Backup codes regenerated.',
      backupCodes,
      mfa: getMfaState(user),
    });
  } catch (err) {
    console.error('Regenerate MFA backup codes error:', err);
    return res.status(500).json({ message: 'Failed to regenerate backup codes.' });
  }
};

exports.getDevices = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const sessions = Array.isArray(user.refreshSessions) ? user.refreshSessions : [];
    const currentSession = findRefreshSession(user, req.user?.sid);
    const currentFingerprint = sanitizeText(currentSession?.deviceFingerprint, 128);
    const devices = (Array.isArray(user.knownDevices) ? user.knownDevices : [])
      .map((device) => serializeDevice(device, sessions, currentFingerprint))
      .sort((left, right) => {
        const leftTime = new Date(left.lastSeenAt || 0).getTime();
        const rightTime = new Date(right.lastSeenAt || 0).getTime();
        return rightTime - leftTime;
      });

    return res.json({
      message: 'Devices loaded.',
      devices,
    });
  } catch (err) {
    console.error('Get devices error:', err);
    return res.status(500).json({ message: 'Failed to load devices.' });
  }
};

exports.updateDevice = async (req, res) => {
  const fingerprint = sanitizeText(req.params?.fingerprint, 128);
  const nextLabel = sanitizeText(req.body?.label, 60);
  const nextTrusted = hasOwn(req.body || {}, 'trusted') ? Boolean(req.body.trusted) : null;

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const devices = Array.isArray(user.knownDevices) ? [...user.knownDevices] : [];
    const deviceIndex = devices.findIndex((device) => sanitizeText(device?.fingerprint, 128) === fingerprint);
    if (deviceIndex < 0) {
      return res.status(404).json({ message: 'Device not found.' });
    }

    const device = devices[deviceIndex];
    devices[deviceIndex] = {
      ...device,
      label: nextLabel || sanitizeText(device?.label, 60) || 'Browser device',
      trusted: nextTrusted === null ? Boolean(device?.trusted) : nextTrusted,
    };
    user.knownDevices = devices;

    if (nextLabel) {
      user.refreshSessions = (Array.isArray(user.refreshSessions) ? user.refreshSessions : []).map((session) =>
        sanitizeText(session?.deviceFingerprint, 128) === fingerprint
          ? { ...session, label: nextLabel }
          : session
      );
    }

    appendAuditEvent(user, req, 'device_updated', 'Device settings updated.', {
      trusted: devices[deviceIndex].trusted,
    });
    await user.save();

    return res.json({
      message: 'Device updated.',
      device: serializeDevice(
        devices[deviceIndex],
        Array.isArray(user.refreshSessions) ? user.refreshSessions : [],
        sanitizeText(findRefreshSession(user, req.user?.sid)?.deviceFingerprint, 128)
      ),
    });
  } catch (err) {
    console.error('Update device error:', err);
    return res.status(500).json({ message: 'Failed to update device.' });
  }
};

exports.deleteDevice = async (req, res) => {
  const fingerprint = sanitizeText(req.params?.fingerprint, 128);
  const revokeSessions = !hasOwn(req.body || {}, 'revokeSessions') || Boolean(req.body.revokeSessions);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const deviceExists = (Array.isArray(user.knownDevices) ? user.knownDevices : []).some(
      (device) => sanitizeText(device?.fingerprint, 128) === fingerprint
    );
    if (!deviceExists) {
      return res.status(404).json({ message: 'Device not found.' });
    }

    user.knownDevices = (Array.isArray(user.knownDevices) ? user.knownDevices : []).filter(
      (device) => sanitizeText(device?.fingerprint, 128) !== fingerprint
    );

    let forceRelogin = false;
    if (revokeSessions) {
      const currentSid = sanitizeText(req.user?.sid, 120);
      user.refreshSessions = (Array.isArray(user.refreshSessions) ? user.refreshSessions : []).filter((session) => {
        const isTarget = sanitizeText(session?.deviceFingerprint, 128) === fingerprint;
        if (isTarget && sanitizeText(session?.sid, 120) === currentSid) {
          forceRelogin = true;
        }
        return !isTarget;
      });
    }

    appendAuditEvent(user, req, 'device_removed', 'Device removed.', {
      revokeSessions,
    });
    await user.save();

    if (forceRelogin) {
      clearRefreshCookie(res, req);
    }

    return res.json({
      message: revokeSessions ? 'Device removed and sessions revoked.' : 'Device removed.',
      forceRelogin,
    });
  } catch (err) {
    console.error('Delete device error:', err);
    return res.status(500).json({ message: 'Failed to remove device.' });
  }
};

exports.getSessions = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const currentSid = sanitizeText(req.user?.sid, 120);
    const knownDeviceMap = getKnownDeviceMap(user);
    const sessions = Array.isArray(user.refreshSessions)
      ? [...user.refreshSessions]
          .map((session) =>
            serializeSession(
              session,
              currentSid,
              knownDeviceMap.get(sanitizeText(session?.deviceFingerprint, 128)) || null
            )
          )
          .sort((a, b) => {
            const aTime = new Date(a.lastUsedAt || a.createdAt || 0).getTime();
            const bTime = new Date(b.lastUsedAt || b.createdAt || 0).getTime();
            return bTime - aTime;
          })
      : [];

    return res.json({
      message: 'Sessions loaded.',
      sessions,
      sessionLimit: MAX_ACTIVE_SESSIONS,
    });
  } catch (err) {
    console.error('Get sessions error:', err);
    return res.status(500).json({ message: 'Failed to load sessions.' });
  }
};

exports.revokeSession = async (req, res) => {
  const targetSid = sanitizeText(req.params?.sessionId, 120);

  if (!targetSid) {
    return res.status(400).json({ message: 'A valid session id is required.' });
  }

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const removed = removeRefreshSession(user, targetSid);
    if (!removed) {
      return res.status(404).json({ message: 'Session not found.' });
    }

    const currentSid = sanitizeText(req.user?.sid, 120);
    const revokedCurrentSession = targetSid === currentSid;
    appendAuditEvent(
      user,
      req,
      'session_revoked',
      revokedCurrentSession ? 'Current session revoked.' : 'Session revoked.',
      { currentSession: revokedCurrentSession }
    );
    await user.save();

    if (revokedCurrentSession) {
      clearRefreshCookie(res, req);
    }

    return res.json({
      message: revokedCurrentSession
        ? 'Current session revoked. Please sign in again to refresh your session.'
        : 'Session revoked.',
      revokedCurrentSession,
      forceRelogin: revokedCurrentSession,
    });
  } catch (err) {
    console.error('Revoke session error:', err);
    return res.status(500).json({ message: 'Failed to revoke session.' });
  }
};

exports.revokeAllSessions = async (req, res) => {
  const exceptCurrent = Boolean(req.body?.exceptCurrent);

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const currentSid = sanitizeText(req.user?.sid, 120);
    revokeAllSessions(user, currentSid, exceptCurrent);

    if (!exceptCurrent || !currentSid) {
      user.refreshTokenVersion += 1;
      clearRefreshCookie(res, req);
    }

    appendAuditEvent(
      user,
      req,
      'sessions_revoked',
      exceptCurrent ? 'All other sessions were revoked.' : 'All sessions were revoked.',
      { exceptCurrent }
    );
    await user.save();

    return res.json({
      message: exceptCurrent
        ? 'All other sessions were revoked.'
        : 'All sessions were revoked. Please sign in again.',
      forceRelogin: !exceptCurrent || !currentSid,
    });
  } catch (err) {
    console.error('Revoke all sessions error:', err);
    return res.status(500).json({ message: 'Failed to revoke sessions.' });
  }
};

exports.updatePassword = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const newPassword = req.body?.newPassword || '';
  const mfaCode = sanitizeMfaCode(req.body?.mfaCode);
  const backupCode = sanitizeBackupCode(req.body?.backupCode);

  if (!isStrongPassword(newPassword)) {
    return res.status(400).json({
      message:
        'New password must be at least 8 characters and include uppercase, lowercase, and a number.',
    });
  }

  if (newPassword === currentPassword) {
    return res.status(400).json({ message: 'New password must be different from current password.' });
  }

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    await assertOwnerRetention(user, { deleting: true });

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    const mfaResult = await verifyMfaChallenge(user, req, { mfaCode, backupCode });
    if (!mfaResult.ok) {
      await user.save();
      return sendProtectedActionMfaError(
        res,
        mfaResult,
        'Enter your MFA code to update your password.'
      );
    }

    user.password = newPassword;
    clearPasswordReset(user);
    user.refreshTokenVersion += 1;
    user.refreshSessions = [];
    appendAuditEvent(user, req, 'password_updated', 'Password updated.');
    await user.save();

    await sendSecurityAlertEmail(
      user,
      'Your Continental ID password was changed',
      'Password changed',
      'Your Continental ID password was updated.',
      [
        `Time: ${new Date().toUTCString()}`,
        `IP address: ${parseClientIp(req) || 'Unknown'}`,
      ]
    );

    clearRefreshCookie(res, req);

    return res.json({
      message: 'Password updated. Please log in again.',
      forceRelogin: true,
    });
  } catch (err) {
    console.error('Update password error:', err);
    return res.status(500).json({ message: 'Failed to update password.' });
  }
};

exports.exportAccountData = async (req, res) => {
  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const payload = buildUserPayload(user);
    const knownDeviceMap = getKnownDeviceMap(user);
    const sessions = Array.isArray(user.refreshSessions)
      ? user.refreshSessions.map((session) =>
          serializeSession(
            session,
            req.user?.sid,
            knownDeviceMap.get(sanitizeText(session?.deviceFingerprint, 128)) || null
          )
        )
      : [];

    appendAuditEvent(user, req, 'account_exported', 'Account export generated.');
    await user.save();

    return res.json({
      message: 'Account export generated.',
      exportedAt: new Date().toISOString(),
      data: {
        account: payload,
        sessions,
        activitySummary: buildActivitySummary(
          Array.isArray(user.recentLogins) ? user.recentLogins : [],
          Array.isArray(user.loginDayCounts) ? user.loginDayCounts : []
        ),
      },
    });
  } catch (err) {
    console.error('Export account error:', err);
    return res.status(500).json({ message: 'Failed to export account data.' });
  }
};

exports.deleteAccount = async (req, res) => {
  const currentPassword = req.body?.currentPassword || '';
  const confirmText = sanitizeText(req.body?.confirmText || '', 20);
  const mfaCode = sanitizeMfaCode(req.body?.mfaCode);
  const backupCode = sanitizeBackupCode(req.body?.backupCode);

  if (confirmText !== 'DELETE') {
    return res.status(400).json({ message: 'Type DELETE to confirm account removal.' });
  }

  try {
    const user = await getUserById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found.' });
    }

    const matches = await user.comparePassword(currentPassword);
    if (!matches) {
      return res.status(400).json({ message: 'Current password is incorrect.' });
    }

    const mfaResult = await verifyMfaChallenge(user, req, { mfaCode, backupCode });
    if (!mfaResult.ok) {
      await user.save();
      return sendProtectedActionMfaError(
        res,
        mfaResult,
        'Enter your MFA code to delete your account.'
      );
    }

    await sendSecurityAlertEmail(
      user,
      'Your Continental ID account was deleted',
      'Account deleted',
      'Your Continental ID account was permanently deleted.',
      [`Time: ${new Date().toUTCString()}`]
    );

    await User.deleteOne({ _id: req.user.id });
    clearRefreshCookie(res, req);

    return res.json({ message: 'Account deleted permanently.' });
  } catch (err) {
    console.error('Delete account error:', err);
    return res.status(500).json({ message: 'Failed to delete account.' });
  }
};
