require('dotenv').config();

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');

const ApiRateLimitBucket = require('./models/ApiRateLimitBucket');
const LoginThrottle = require('./models/LoginThrottle');
const User = require('./models/User');
const authRoutes = require('./routes/authRoutes');
const grimoireRoutes = require('./routes/grimoireRoutes');
const vanguardRoutes = require('./routes/vanguardRoutes');
const { dedupePasskeysAcrossUsers } = require('./utils/passkeyHardening');
const { migrateUsersToLatestSecurityState } = require('./utils/securityHardening');
const { migrateUsersToLatestIdentity } = require('./utils/userIdentity');

const app = express();

const DEFAULT_ALLOWED_ORIGINS = [
  'https://blueprint.continental-hub.com',
  'https://charlemagne404.github.io',
  'https://dashboard.continental-hub.com',
  'https://grimoire.continental-hub.com',
  'https://login.continental-hub.com',
  'https://pulse.continental-hub.com',
  'https://stepcast.continental-hub.com',
  'https://vanguard.continental-hub.com',
  'https://mpmc.ddns.net',
];

const nodeEnv = process.env.NODE_ENV || 'development';
const isProduction = nodeEnv === 'production';
const allowedOriginsFromEnv = String(process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);

const resolveHttpsMode = (value) => {
  const normalized = String(value || '').trim().toLowerCase();
  if (!normalized || ['0', 'false', 'off', 'disabled'].includes(normalized)) {
    return 'off';
  }
  if (normalized === 'auto') {
    return 'auto';
  }
  if (['1', 'true', 'on', 'enabled', 'https'].includes(normalized)) {
    return 'on';
  }
  return 'off';
};

const selectServerTransport = (httpsMode, hasHttpsFiles) => {
  if (httpsMode === 'on') {
    return 'https';
  }
  if (httpsMode === 'auto' && hasHttpsFiles) {
    return 'https';
  }
  return 'http';
};

const config = {
  appName: process.env.APP_NAME || 'continental-id-auth',
  nodeEnv,
  host: process.env.HOST || (isProduction ? '0.0.0.0' : '127.0.0.1'),
  port: Number(process.env.PORT) || 5000,
  mongoUri: process.env.MONGO_URI,
  jwtSecret: process.env.JWT_SECRET,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET,
  allowedOrigins: [],
  rateLimitWindowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
  rateLimitMax: Number(process.env.RATE_LIMIT_MAX) || 180,
  httpsKeyPath:
    process.env.HTTPS_KEY_PATH || '/etc/letsencrypt/live/mpmc.ddns.net/privkey.pem',
  httpsCertPath:
    process.env.HTTPS_CERT_PATH || '/etc/letsencrypt/live/mpmc.ddns.net/fullchain.pem',
  httpsMode: resolveHttpsMode(process.env.HTTPS_MODE),
};
const allowDefaultTrustedOrigins =
  String(process.env.ALLOW_DEFAULT_TRUSTED_ORIGINS || 'true') !== 'false';
const allowLocalDevOrigins =
  !isProduction || String(process.env.ALLOW_LOCALHOST_ORIGINS || 'false') === 'true';

config.allowedOrigins = Array.from(
  new Set([
    ...(allowDefaultTrustedOrigins ? DEFAULT_ALLOWED_ORIGINS : []),
    ...allowedOriginsFromEnv,
  ])
);

const parseTrustProxy = (value, fallback = false) => {
  if (value === undefined) return fallback;

  const normalized = String(value).trim();
  if (!normalized) return fallback;
  if (normalized === 'true') return true;
  if (normalized === 'false') return false;

  const numeric = Number(normalized);
  if (Number.isInteger(numeric) && numeric >= 0) {
    return numeric;
  }

  return normalized;
};

const isDuplicateKeyError = (err) => err?.code === 11000;

const requiredEnv = ['MONGO_URI', 'JWT_SECRET', 'REFRESH_TOKEN_SECRET'];
const missingEnv = requiredEnv.filter((key) => !process.env[key]);
if (missingEnv.length > 0) {
  console.error(`Missing required env vars: ${missingEnv.join(', ')}`);
  process.exit(1);
}

const hasStrongSecret = (value) => {
  const secret = String(value || '').trim();
  if (secret.length < 32) return false;
  if (secret.includes('replace-with-a-long-random-secret')) return false;
  if (secret.includes('replace-with-a-second-long-random-secret')) return false;
  return true;
};

const allowedOriginsSet = new Set(config.allowedOrigins);

if (isProduction) {
  if (!hasStrongSecret(config.jwtSecret)) {
    console.error('JWT_SECRET must be set to a strong random value in production.');
    process.exit(1);
  }

  if (!hasStrongSecret(config.refreshTokenSecret)) {
    console.error('REFRESH_TOKEN_SECRET must be set to a strong random value in production.');
    process.exit(1);
  }

  if (allowedOriginsSet.size === 0) {
    console.error('ALLOWED_ORIGINS must include at least one trusted frontend origin in production.');
    process.exit(1);
  }
}
app.disable('x-powered-by');
app.set('trust proxy', parseTrustProxy(process.env.TRUST_PROXY, isProduction ? 1 : false));

app.use((req, res, next) => {
  const requestId = crypto.randomUUID();
  req.requestId = requestId;
  res.setHeader('X-Request-Id', requestId);
  return next();
});

app.use((req, res, next) => {
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '')
    .split(',')[0]
    .trim()
    .toLowerCase();
  const originLikeUrl = String(req.headers.origin || req.headers.referer || '').trim();
  let browserProtocol = '';
  if (originLikeUrl) {
    try {
      browserProtocol = new URL(originLikeUrl).protocol.replace(':', '').toLowerCase();
    } catch {
      browserProtocol = '';
    }
  }

  const isSecureRequest =
    req.secure || forwardedProto === 'https' || (!forwardedProto && browserProtocol === 'https');

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader('Pragma', 'no-cache');
  if (isSecureRequest) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: false, limit: '200kb' }));
app.use(cookieParser());

const normalizeOrigin = (origin) => String(origin || '').trim().replace(/\/+$/, '');

const isAllowedOrigin = (origin) => {
  if (!origin) return true;

  const normalizedOrigin = normalizeOrigin(origin);

  try {
    const url = new URL(normalizedOrigin);
    if (
      allowLocalDevOrigins &&
      (url.hostname === 'localhost' || url.hostname === '127.0.0.1')
    ) {
      return true;
    }
  } catch {
    return false;
  }

  return allowedOriginsSet.has(normalizedOrigin);
};

const getClientKey = (req) => String(req.ip || 'unknown').trim().slice(0, 80) || 'unknown';

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

const browserProtectedAuthRoutes = new Set([
  '/login',
  '/register',
  '/logout',
  '/refresh_token',
  '/request-password-reset',
  '/resend-verification-public',
  '/reset-password',
  '/passkeys/authenticate/options',
  '/passkeys/authenticate/verify',
  '/passkeys/register/options',
  '/passkeys/register/verify',
  '/oauth/github/link-start',
  '/oauth/google/link-start',
  '/oauth/discord/link-start',
  '/oauth/microsoft/link-start',
]);

const requireTrustedBrowserOrigin = (req, res, next) => {
  if (req.method === 'OPTIONS' || !browserProtectedAuthRoutes.has(req.path)) {
    return next();
  }

  const origin = extractBrowserOrigin(req);
  if (origin && isAllowedOrigin(origin)) {
    return next();
  }

  return res.status(403).json({
    message: 'Trusted browser origin required.',
    requestId: req.requestId,
  });
};

app.use(
  cors({
    origin(origin, callback) {
      if (isAllowedOrigin(origin)) {
        return callback(null, true);
      }
      console.warn(`CORS denied origin: ${origin || 'unknown'}`);
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Vanguard-Api-Key',
      'X-Vanguard-Instance-Id',
    ],
  })
);

const consumeApiRateLimit = async (key) => {
  const now = Date.now();
  const windowStartMs = Math.floor(now / config.rateLimitWindowMs) * config.rateLimitWindowMs;
  const windowStart = new Date(windowStartMs);
  const expiresAt = new Date(windowStartMs + config.rateLimitWindowMs * 2);
  let bucket;

  try {
    bucket = await ApiRateLimitBucket.findOneAndUpdate(
      { key, windowStart },
      {
        $inc: { count: 1 },
        $setOnInsert: { expiresAt },
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

    bucket = await ApiRateLimitBucket.findOneAndUpdate(
      { key, windowStart },
      {
        $inc: { count: 1 },
      },
      {
        new: true,
      }
    );
  }

  return {
    allowed: bucket.count <= config.rateLimitMax,
    retryAfterSec: Math.max(1, Math.ceil((windowStartMs + config.rateLimitWindowMs - now) / 1000)),
  };
};

const apiRateLimiter = async (req, res, next) => {
  if (req.path === '/health') {
    return next();
  }

  try {
    const result = await consumeApiRateLimit(`api:${getClientKey(req)}`);
    if (!result.allowed) {
      return res.status(429).json({
        message: 'Too many requests. Please try again later.',
        retryAfterSec: result.retryAfterSec,
        requestId: req.requestId,
      });
    }

    return next();
  } catch (err) {
    return next(err);
  }
};

mongoose.set('bufferCommands', false);

const connectToDatabase = async () => {
  await mongoose.connect(config.mongoUri, {
    maxPoolSize: 10,
    serverSelectionTimeoutMS: 5000,
  });
};

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

const startupMaintenanceState = {
  status: 'idle',
  activeTask: '',
  error: '',
  startedAt: null,
  completedAt: null,
};

let startupMaintenancePromise;

const buildStartupMaintenanceSnapshot = () => ({
  status: startupMaintenanceState.status,
  activeTask: startupMaintenanceState.activeTask,
  error: startupMaintenanceState.error,
  startedAt: startupMaintenanceState.startedAt
    ? new Date(startupMaintenanceState.startedAt).toISOString()
    : null,
  completedAt: startupMaintenanceState.completedAt
    ? new Date(startupMaintenanceState.completedAt).toISOString()
    : null,
});

const runMaintenanceTask = async (label, task, errors) => {
  startupMaintenanceState.activeTask = label;
  try {
    await task();
  } catch (err) {
    errors.push(`${label}: ${err.message || err}`);
    console.error(`Startup maintenance failed during ${label}:`, err);
  }
};

const runStartupMaintenance = async () => {
  if (startupMaintenancePromise) {
    return startupMaintenancePromise;
  }

  startupMaintenanceState.status = 'running';
  startupMaintenanceState.activeTask = '';
  startupMaintenanceState.error = '';
  startupMaintenanceState.startedAt = Date.now();
  startupMaintenanceState.completedAt = null;

  startupMaintenancePromise = (async () => {
    const errors = [];

    await runMaintenanceTask('user identity migration', () => migrateUsersToLatestIdentity({ logger: console }), errors);
    await runMaintenanceTask(
      'user security migration',
      () => migrateUsersToLatestSecurityState({ logger: console }),
      errors
    );
    await runMaintenanceTask(
      'passkey dedupe',
      () => dedupePasskeysAcrossUsers({ logger: console }),
      errors
    );
    await runMaintenanceTask('user index sync', () => User.syncIndexes(), errors);
    await runMaintenanceTask('login throttle index sync', () => LoginThrottle.syncIndexes(), errors);
    await runMaintenanceTask(
      'api rate limit bucket index sync',
      () => ApiRateLimitBucket.syncIndexes(),
      errors
    );

    startupMaintenanceState.activeTask = '';
    startupMaintenanceState.completedAt = Date.now();
    startupMaintenanceState.error = errors.join(' | ');
    startupMaintenanceState.status = errors.length ? 'error' : 'ok';

    if (errors.length) {
      console.error(
        'Startup maintenance completed with non-fatal errors:',
        startupMaintenanceState.error
      );
    }

    return buildStartupMaintenanceSnapshot();
  })().finally(() => {
    startupMaintenancePromise = undefined;
  });

  return startupMaintenancePromise;
};

app.get('/api/health', (req, res) => {
  const dbConnected = mongoose.connection.readyState === 1;
  const status = dbConnected ? 200 : 503;

  return res.status(status).json({
    service: config.appName,
    status: dbConnected ? 'ok' : 'degraded',
    timestamp: new Date().toISOString(),
    maintenance: buildStartupMaintenanceSnapshot(),
  });
});

app.use((req, res, next) => {
  if (req.path === '/api/health') {
    return next();
  }

  if (mongoose.connection.readyState !== 1) {
    return res.status(503).json({
      message: 'Database unavailable. Try again shortly.',
      requestId: req.requestId,
    });
  }

  return next();
});

app.use('/api', apiRateLimiter);

app.use('/api/auth', requireTrustedBrowserOrigin, authRoutes);
app.use('/api/grimoire', grimoireRoutes);
app.use('/api/vanguard', vanguardRoutes);

app.use('/api', (req, res) => {
  return res.status(404).json({
    message: 'API route not found.',
    requestId: req.requestId,
  });
});

app.use((err, req, res, next) => {
  if (err?.message === 'Not allowed by CORS') {
    return res.status(403).json({
      message: 'CORS origin denied.',
      requestId: req.requestId,
    });
  }

  console.error(`[${req.requestId}]`, err);
  return res.status(500).json({
    message: 'Internal server error.',
    requestId: req.requestId,
  });
});

let server;

const startServer = async () => {
  if (server?.listening) {
    return server;
  }

  try {
    await connectToDatabase();
    console.log('MongoDB connected');
  } catch (err) {
    console.error('Server startup failed:', err);
    process.exit(1);
  }

  const hasHttpsFiles = fs.existsSync(config.httpsKeyPath) && fs.existsSync(config.httpsCertPath);
  const transport = selectServerTransport(config.httpsMode, hasHttpsFiles);

  if (config.httpsMode === 'on' && !hasHttpsFiles) {
    console.error(
      `HTTPS_MODE=on requires readable cert files at ${config.httpsKeyPath} and ${config.httpsCertPath}.`
    );
    process.exit(1);
  }

  if (transport === 'https') {
    const privateKey = fs.readFileSync(config.httpsKeyPath, 'utf8');
    const certificate = fs.readFileSync(config.httpsCertPath, 'utf8');
    server = https.createServer({ key: privateKey, cert: certificate }, app);
    await new Promise((resolve) => {
      server.listen(config.port, config.host, resolve);
    });
    console.log(`Auth service HTTPS running on https://${config.host}:${config.port}`);
    void runStartupMaintenance();
    return server;
  }

  server = http.createServer(app);
  await new Promise((resolve) => {
    server.listen(config.port, config.host, resolve);
  });
  console.log(`Auth service HTTP running on http://${config.host}:${config.port}`);
  void runStartupMaintenance();
  return server;
};

const stopServer = async () => {
  const activeServer = server;
  server = undefined;

  if (activeServer) {
    await new Promise((resolve) => activeServer.close(resolve));
  }

  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
  }
};

const shutdown = async (signal) => {
  console.log(`Received ${signal}. Shutting down gracefully...`);

  try {
    await stopServer();
    process.exit(0);
  } catch (err) {
    console.error('Error during shutdown:', err);
    process.exit(1);
  }
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

module.exports = {
  app,
  config,
  connectToDatabase,
  resolveHttpsMode,
  runStartupMaintenance,
  selectServerTransport,
  startServer,
  startupMaintenanceState,
  stopServer,
};

if (require.main === module) {
  startServer();
}
