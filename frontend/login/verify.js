const AUTH_CONFIG = window.__AUTH_CONFIG__ || {};
const LOCAL_HOSTS = new Set(AUTH_CONFIG.localHosts || ['localhost', '127.0.0.1']);
const TRUSTED_APP_ORIGINS = new Set(AUTH_CONFIG.trustedAppOrigins || []);
const TRUSTED_API_ORIGINS = new Set(AUTH_CONFIG.trustedApiOrigins || []);
const PREFERRED_API_ORIGINS = Array.isArray(AUTH_CONFIG.preferredApiOrigins)
  ? AUTH_CONFIG.preferredApiOrigins
  : [];
const HOSTED_API_BASE_URL =
  AUTH_CONFIG.hostedApiBaseUrl || 'https://auth.continental-hub.com';
const API_BASE_STORAGE_KEY = 'continental.authApiBaseUrl';
const params = new URLSearchParams(window.location.search);
const token = String(params.get('token') || '').trim();
const HOSTED_APP_HOSTS = new Set(
  [...TRUSTED_APP_ORIGINS]
    .map((origin) => {
      try {
        return new URL(origin).hostname;
      } catch {
        return '';
      }
    })
    .filter(Boolean)
);

function trimTrailingSlash(value) {
  return String(value || '').replace(/\/+$/, '');
}

function isTrustedApiOrigin(origin) {
  if (!origin) return false;

  try {
    const parsed = new URL(origin);
    if (LOCAL_HOSTS.has(parsed.hostname)) return true;
    return TRUSTED_API_ORIGINS.has(parsed.origin);
  } catch {
    return false;
  }
}

function resolveTrustedApiBaseUrl(value) {
  if (!value) return '';

  try {
    const resolved = new URL(value, window.location.origin);
    return isTrustedApiOrigin(resolved.origin) ? trimTrailingSlash(resolved.origin) : '';
  } catch {
    return '';
  }
}

function readStoredApiBaseUrl() {
  try {
    return resolveTrustedApiBaseUrl(window.localStorage?.getItem(API_BASE_STORAGE_KEY));
  } catch {
    return '';
  }
}

function rememberApiBaseUrl(value) {
  try {
    if (value) {
      window.localStorage?.setItem(API_BASE_STORAGE_KEY, trimTrailingSlash(value));
    }
  } catch {
    // localStorage can be unavailable in some embedded contexts.
  }
}

function getApiBaseCandidates() {
  const rawCandidates = [
    params.get('apiBaseUrl'),
    window.__API_BASE_URL__,
    readStoredApiBaseUrl(),
  ];

  if (LOCAL_HOSTS.has(window.location.hostname)) {
    rawCandidates.push('http://localhost:5000', window.location.origin);
  } else {
    rawCandidates.push(window.location.origin);
    rawCandidates.push(...PREFERRED_API_ORIGINS);
    if (HOSTED_APP_HOSTS.has(window.location.hostname)) {
      rawCandidates.push(HOSTED_API_BASE_URL);
    }
  }

  const uniqueCandidates = [];
  for (const candidate of rawCandidates) {
    const resolved = resolveTrustedApiBaseUrl(candidate);
    if (resolved && !uniqueCandidates.includes(resolved)) {
      uniqueCandidates.push(resolved);
    }
  }

  return uniqueCandidates;
}

let API_BASE_URL = getApiBaseCandidates()[0] || '';
let apiBaseValidated = false;
let apiBaseResolutionPromise = null;
const getAuthApiBase = () => `${API_BASE_URL}/api/auth`;
const heading = document.getElementById('heading');
const description = document.getElementById('description');
const status = document.getElementById('status');
const loginLink = document.getElementById('login-link');

function looksLikeAuthHealthPayload(payload) {
  const status = String(payload?.status || '').trim().toLowerCase();
  const timestamp = String(payload?.timestamp || '').trim();
  if (!timestamp || !['ok'].includes(status)) {
    return false;
  }

  const service = String(payload?.service || '').trim().toLowerCase();
  return !service || service.includes('auth') || service.includes('continental') || service.includes('id');
}

async function probeApiBaseUrl(candidate) {
  try {
    const response = await fetch(`${candidate}/api/health`, {
      cache: 'no-store',
    });
    const payload = await response.json().catch(() => null);
    return looksLikeAuthHealthPayload(payload);
  } catch {
    return false;
  }
}

async function ensureApiBaseUrl() {
  if (apiBaseValidated && API_BASE_URL) {
    return API_BASE_URL;
  }

  if (apiBaseResolutionPromise) {
    return apiBaseResolutionPromise;
  }

  apiBaseResolutionPromise = (async () => {
    const candidates = getApiBaseCandidates();
    for (const candidate of candidates) {
      if (await probeApiBaseUrl(candidate)) {
        API_BASE_URL = candidate;
        apiBaseValidated = true;
        rememberApiBaseUrl(candidate);
        return candidate;
      }
    }

    throw new Error(
      candidates.length
        ? `No healthy Continental ID auth API was found. Checked: ${candidates.join(', ')}.`
        : 'No trusted API base URL was configured for Continental ID.'
    );
  })();

  try {
    return await apiBaseResolutionPromise;
  } catch (error) {
    apiBaseResolutionPromise = null;
    throw error;
  }
}

function setStatus(message, tone) {
  status.textContent = message;
  status.dataset.status = tone;
  status.classList.toggle('is-visible', Boolean(message));
}

function getRequestErrorMessage(error, fallback) {
  const message = String(error?.message || '').trim();
  if (message && message !== 'Failed to fetch') {
    return message;
  }

  if (API_BASE_URL) {
    return `Could not reach the verification service at ${API_BASE_URL}. Check that this origin is serving the Continental ID auth API.`;
  }

  return fallback || 'Could not determine a live Continental ID auth API.';
}

const popupUrl = new URL('popup.html', window.location.href);
if (params.get('origin')) popupUrl.searchParams.set('origin', params.get('origin'));
if (params.get('redirect')) popupUrl.searchParams.set('redirect', params.get('redirect'));
if (params.get('apiBaseUrl')) popupUrl.searchParams.set('apiBaseUrl', params.get('apiBaseUrl'));
loginLink.href = popupUrl.toString();

async function verify() {
  if (!token) {
    heading.textContent = 'Verification link missing';
    description.textContent = 'No verification token was found in the URL.';
    setStatus('Use the link from your verification email.', 'error');
    return;
  }

  setStatus('Checking your verification token...', 'info');

  try {
    await ensureApiBaseUrl();
    const verifyUrl = `${getAuthApiBase()}/verify-email?token=${encodeURIComponent(token)}`;
    const res = await fetch(verifyUrl, { method: 'GET', credentials: 'include' });
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      heading.textContent = 'Verification failed';
      description.textContent = 'The verification link could not be accepted.';
      setStatus(data.message || 'Invalid or expired verification token.', 'error');
      return;
    }

    heading.textContent = 'Email verified';
    description.textContent = 'Your email has been confirmed and the account is ready for sign-in.';
    setStatus('Verification successful. You can now log in.', 'success');
  } catch (error) {
    heading.textContent = 'Verification failed';
    description.textContent = 'The request could not be completed.';
    setStatus(
      getRequestErrorMessage(
        error,
        'Could not reach the verification service. Check that the API base URL points to a live backend.'
      ),
      'error'
    );
  }
}

verify();
