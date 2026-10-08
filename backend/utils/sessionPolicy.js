const SESSION_ABSOLUTE_TTL_MS = Number(process.env.SESSION_ABSOLUTE_TTL_MS) || 7 * 24 * 60 * 60 * 1000;
const SESSION_IDLE_TTL_MS = Number(process.env.SESSION_IDLE_TTL_MS) || 24 * 60 * 60 * 1000;

const isSessionActive = (session, now = Date.now()) => {
  const created = new Date(session?.createdAt || 0).getTime();
  const used = new Date(session?.lastUsedAt || session?.createdAt || 0).getTime();
  return Number.isFinite(created) && created > 0 && Number.isFinite(used) &&
    created + SESSION_ABSOLUTE_TTL_MS > now && used + SESSION_IDLE_TTL_MS > now;
};

module.exports = { SESSION_ABSOLUTE_TTL_MS, SESSION_IDLE_TTL_MS, isSessionActive };
