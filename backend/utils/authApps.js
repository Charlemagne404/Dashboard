const AuthApp = require('../models/AuthApp');

const DEFAULT_DASHBOARD_URL = 'https://dashboard.continental-hub.com/settings';
const DEFAULT_GRIMOIRE_ORIGIN = 'https://grimoire.continental-hub.com';
const DEFAULT_BLUEPRINT_ORIGIN = 'https://blueprint.continental-hub.com';
const DEFAULT_VANGUARD_ORIGIN = 'https://vanguard.continental-hub.com';

const sanitizeText = (value, maxLength = 2000) => String(value || '').trim().slice(0, maxLength);
const normalizeOrigin = (value) => sanitizeText(value, 2000).replace(/\/+$/, '');

const normalizeOrigins = (values = []) =>
  Array.from(
    new Set(
      (Array.isArray(values) ? values : [])
        .map((value) => normalizeOrigin(value))
        .filter(Boolean)
    )
  );

const normalizeProviders = (values = []) =>
  Array.from(
    new Set(
      (Array.isArray(values) ? values : [])
        .map((value) => sanitizeText(value, 80).toLowerCase())
        .filter(Boolean)
    )
  );

const DEFAULT_AUTH_APPS = Object.freeze([
  {
    appId: 'grimoire',
    displayName: 'Grimoire',
    status: 'active',
    allowedOrigins: [DEFAULT_GRIMOIRE_ORIGIN],
    allowedRedirectOrigins: [DEFAULT_GRIMOIRE_ORIGIN],
    requiredLinkedProviders: [],
    policyResolver: null,
    dashboardUrl: DEFAULT_DASHBOARD_URL,
    firstParty: true,
  },
  {
    appId: 'blueprint',
    displayName: 'Blueprint',
    status: 'active',
    allowedOrigins: [DEFAULT_BLUEPRINT_ORIGIN],
    allowedRedirectOrigins: [DEFAULT_BLUEPRINT_ORIGIN],
    requiredLinkedProviders: [],
    policyResolver: null,
    dashboardUrl: DEFAULT_DASHBOARD_URL,
    firstParty: true,
  },
  {
    appId: 'vanguard',
    displayName: 'Vanguard',
    status: 'active',
    allowedOrigins: [DEFAULT_VANGUARD_ORIGIN],
    allowedRedirectOrigins: [DEFAULT_VANGUARD_ORIGIN],
    requiredLinkedProviders: ['discord'],
    policyResolver: 'vanguard-control-center',
    dashboardUrl: `${DEFAULT_VANGUARD_ORIGIN}/control/`,
    firstParty: true,
  },
]);

const normalizeAuthAppRecord = (record = {}) => ({
  appId: sanitizeText(record.appId, 80).toLowerCase(),
  displayName: sanitizeText(record.displayName, 120) || 'Continental app',
  status: sanitizeText(record.status, 40).toLowerCase() === 'disabled' ? 'disabled' : 'active',
  allowedOrigins: normalizeOrigins(record.allowedOrigins),
  allowedRedirectOrigins: normalizeOrigins(record.allowedRedirectOrigins),
  requiredLinkedProviders: normalizeProviders(record.requiredLinkedProviders),
  policyResolver: sanitizeText(record.policyResolver, 120) || null,
  dashboardUrl: sanitizeText(record.dashboardUrl, 2000),
  firstParty: Boolean(record.firstParty),
});

const DEFAULT_AUTH_APP_MAP = new Map(
  DEFAULT_AUTH_APPS.map((record) => {
    const normalized = normalizeAuthAppRecord(record);
    return [normalized.appId, normalized];
  })
);

const getDefaultAuthApp = (appId = '') =>
  DEFAULT_AUTH_APP_MAP.get(sanitizeText(appId, 80).toLowerCase()) || null;

const getDefaultAuthApps = () =>
  DEFAULT_AUTH_APPS.map((record) => normalizeAuthAppRecord(record));

const findRegisteredAuthApp = async (appId = '') => {
  const normalizedAppId = sanitizeText(appId, 80).toLowerCase();
  if (!normalizedAppId) return null;

  const persisted = await AuthApp.findOne({ appId: normalizedAppId }).lean();
  if (persisted) {
    return normalizeAuthAppRecord(persisted);
  }

  return getDefaultAuthApp(normalizedAppId);
};

const seedDefaultAuthApps = async ({ logger = console } = {}) => {
  const operations = getDefaultAuthApps().map((record) => ({
    updateOne: {
      filter: { appId: record.appId },
      update: {
        $setOnInsert: record,
      },
      upsert: true,
    },
  }));

  if (!operations.length) {
    return { upsertedCount: 0 };
  }

  const result = await AuthApp.bulkWrite(operations, { ordered: false });
  if (result.upsertedCount) {
    logger.info?.(`Seeded ${result.upsertedCount} Continental auth app record(s).`);
  }
  return result;
};

module.exports = {
  AuthApp,
  DEFAULT_AUTH_APPS,
  findRegisteredAuthApp,
  getDefaultAuthApp,
  getDefaultAuthApps,
  normalizeAuthAppRecord,
  seedDefaultAuthApps,
};
