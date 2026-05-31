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
const USERNAME_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9._-]{1,28}[A-Za-z0-9])?$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const params = new URLSearchParams(window.location.search);
const token = safeText(params.get('token'));
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

function safeText(value) {
  return String(value || '').trim();
}

const heading = document.getElementById('heading');
const description = document.getElementById('description');
const status = document.getElementById('status');
const requestForm = document.getElementById('request-form');
const resetForm = document.getElementById('reset-form');
const requestIdentifier = document.getElementById('request-identifier');
const requestBtn = document.getElementById('request-btn');
const resetPassword = document.getElementById('reset-password');
const resetConfirm = document.getElementById('reset-confirm');
const resetBtn = document.getElementById('reset-btn');
const resetStrength = document.getElementById('reset-password-strength');
const resetStrengthFill = document.getElementById('reset-password-strength-fill');
const resetStrengthCopy = document.getElementById('reset-password-strength-copy');
const backLink = document.getElementById('back-link');
let apiBaseValidated = false;
let apiBaseResolutionPromise = null;

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
const getAuthApiBase = () => `${API_BASE_URL}/api/auth`;

function looksLikeAuthHealthPayload(payload) {
  const status = safeText(payload?.status).toLowerCase();
  const timestamp = safeText(payload?.timestamp);
  if (!timestamp || !['ok'].includes(status)) {
    return false;
  }

  const service = safeText(payload?.service).toLowerCase();
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

function setStatus(message, tone = 'error') {
  const text = safeText(message);
  status.textContent = text;
  status.dataset.status = tone;
  status.classList.toggle('is-visible', Boolean(text));
}

function setBusy(button, busy, idleLabel, busyLabel) {
  button.disabled = busy;
  button.textContent = busy ? busyLabel : idleLabel;
}

function getRequestErrorMessage(error, fallback) {
  const message = safeText(error?.message);
  if (message && message !== 'Failed to fetch') {
    return message;
  }

  if (API_BASE_URL) {
    return `Could not reach the password reset service at ${API_BASE_URL}. Check that this origin is serving the Continental ID auth API.`;
  }

  return fallback || 'Could not determine a live Continental ID auth API.';
}

function setFieldError(input, message) {
  const group = input.closest('.field-group');
  const errorEl = document.getElementById(`${input.id}-error`);
  if (group) group.classList.add('has-error');
  input.setAttribute('aria-invalid', 'true');
  if (errorEl) errorEl.textContent = message;
}

function clearFieldError(input) {
  const group = input.closest('.field-group');
  const errorEl = document.getElementById(`${input.id}-error`);
  if (group) group.classList.remove('has-error');
  input.removeAttribute('aria-invalid');
  if (errorEl) errorEl.textContent = '';
}

function updatePasswordStrength() {
  const password = resetPassword.value;
  let score = 0;
  if (password.length >= 8) score += 1;
  if (password.length >= 12) score += 1;
  if (/[A-Z]/.test(password)) score += 1;
  if (/[a-z]/.test(password)) score += 1;
  if (/\d/.test(password)) score += 1;
  if (/[^A-Za-z0-9]/.test(password)) score += 1;

  const clamped = Math.min(score, 5);
  resetStrength.dataset.score = String(clamped);
  resetStrengthFill.style.width = `${clamped === 0 ? 0 : 20 + clamped * 16}%`;
  resetStrengthCopy.textContent =
    clamped <= 1
      ? 'Very weak. Add length, uppercase, lowercase, and numbers.'
      : clamped === 2
        ? 'Weak. This still needs more variety.'
        : clamped === 3
          ? 'Decent. Add more length or symbols to strengthen it.'
          : clamped === 4
            ? 'Strong. This meets the current password requirements.'
            : 'Very strong. Good coverage and length.';
}

function togglePasswordVisibility(button) {
  const input = document.getElementById(button.getAttribute('data-target'));
  if (!input) return;
  const visible = input.type === 'password';
  input.type = visible ? 'text' : 'password';
  button.textContent = visible ? 'Hide' : 'Show';
  button.setAttribute('aria-pressed', visible ? 'true' : 'false');
}

function setCapsWarning(input, visible) {
  const warningEl = document.getElementById(`${input.id}-caps`);
  if (!warningEl) return;
  warningEl.classList.toggle('is-visible', Boolean(visible));
}

function handleCapsLockState(event) {
  if (!(event.target instanceof HTMLInputElement) || event.target.type !== 'password') return;
  setCapsWarning(event.target, event.getModifierState('CapsLock'));
}

async function parseJson(res) {
  const text = await res.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { message: text };
  }
}

const popupUrl = new URL('popup.html', window.location.href);
if (params.get('origin')) popupUrl.searchParams.set('origin', params.get('origin'));
if (params.get('redirect')) popupUrl.searchParams.set('redirect', params.get('redirect'));
if (params.get('apiBaseUrl')) popupUrl.searchParams.set('apiBaseUrl', params.get('apiBaseUrl'));
backLink.href = popupUrl.toString();

if (token) {
  heading.textContent = 'Choose a new password';
  description.textContent = 'Enter a strong new password to finish resetting your account.';
  requestForm.hidden = true;
  resetForm.hidden = false;
}

requestForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearFieldError(requestIdentifier);

  const identifier = safeText(requestIdentifier.value);
  if (!identifier) {
    setFieldError(requestIdentifier, 'Enter your email address or username.');
    setStatus('Check the highlighted field and try again.', 'error');
    return;
  }

  if (!identifier.includes('@') && !USERNAME_PATTERN.test(identifier)) {
    setFieldError(requestIdentifier, 'Enter a valid username or email address.');
    setStatus('Check the highlighted field and try again.', 'error');
    return;
  }

  if (identifier.includes('@') && !EMAIL_PATTERN.test(identifier)) {
    setFieldError(requestIdentifier, 'Enter a valid email address.');
    setStatus('Check the highlighted field and try again.', 'error');
    return;
  }

  setBusy(requestBtn, true, 'Send reset link', 'Sending...');
  setStatus('Preparing a password reset link...', 'info');

  try {
    await ensureApiBaseUrl();
    const response = await fetch(`${getAuthApiBase()}/request-password-reset`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier }),
    });
    const data = await parseJson(response);
    setStatus(
      data.message || 'If the account exists, a reset link will arrive shortly.',
      'success'
    );
  } catch (error) {
    setStatus(
      getRequestErrorMessage(
        error,
        'Could not reach the password reset service. Check that the API base URL points to a live backend.'
      ),
      'error'
    );
  } finally {
    setBusy(requestBtn, false, 'Send reset link', 'Sending...');
  }
});

resetForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearFieldError(resetPassword);
  clearFieldError(resetConfirm);

  if (!resetPassword.value) {
    setFieldError(resetPassword, 'Enter a new password.');
  } else if (
    resetPassword.value.length < 8 ||
    !/[A-Z]/.test(resetPassword.value) ||
    !/[a-z]/.test(resetPassword.value) ||
    !/\d/.test(resetPassword.value)
  ) {
    setFieldError(
      resetPassword,
      'Use at least 8 characters with uppercase, lowercase, and a number.'
    );
  }

  if (!resetConfirm.value) {
    setFieldError(resetConfirm, 'Repeat your new password.');
  } else if (resetPassword.value !== resetConfirm.value) {
    setFieldError(resetConfirm, 'Passwords do not match.');
  }

  if (resetPassword.getAttribute('aria-invalid') === 'true' || resetConfirm.getAttribute('aria-invalid') === 'true') {
    setStatus('Check the highlighted fields and try again.', 'error');
    return;
  }

  setBusy(resetBtn, true, 'Reset password', 'Resetting...');
  setStatus('Updating your password...', 'info');

  try {
    await ensureApiBaseUrl();
    const response = await fetch(`${getAuthApiBase()}/reset-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, newPassword: resetPassword.value }),
    });
    const data = await parseJson(response);

    if (!response.ok) {
      throw new Error(data.message || 'Could not reset your password.');
    }

    setStatus(data.message || 'Password reset complete. You can sign in now.', 'success');
  } catch (error) {
    setStatus(
      getRequestErrorMessage(
        error,
        'Could not reach the password reset service. Check that the API base URL points to a live backend.'
      ),
      'error'
    );
  } finally {
    setBusy(resetBtn, false, 'Reset password', 'Resetting...');
  }
});

for (const toggle of document.querySelectorAll('[data-password-toggle]')) {
  toggle.addEventListener('click', () => togglePasswordVisibility(toggle));
}

for (const input of [resetPassword, resetConfirm]) {
  input.addEventListener('input', () => clearFieldError(input));
  input.addEventListener('keydown', handleCapsLockState);
  input.addEventListener('keyup', handleCapsLockState);
  input.addEventListener('blur', () => setCapsWarning(input, false));
}

requestIdentifier.addEventListener('input', () => clearFieldError(requestIdentifier));
resetPassword.addEventListener('input', updatePasswordStrength);
updatePasswordStrength();
