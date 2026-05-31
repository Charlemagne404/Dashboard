(function initWebAuthnJson(global) {
  const base64UrlToUint8Array = (value) => {
    const normalized = String(value || '')
      .replace(/-/g, '+')
      .replace(/_/g, '/');
    const padding = normalized.length % 4 === 0 ? '' : '='.repeat(4 - (normalized.length % 4));
    const binary = global.atob(`${normalized}${padding}`);
    const bytes = new Uint8Array(binary.length);

    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }

    return bytes;
  };

  const toUint8Array = (value) => {
    if (value instanceof Uint8Array) return value;
    if (value instanceof ArrayBuffer) return new Uint8Array(value);
    if (ArrayBuffer.isView(value)) {
      return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
    }
    return new Uint8Array();
  };

  const uint8ArrayToBase64Url = (value) => {
    const bytes = toUint8Array(value);
    let binary = '';

    for (const byte of bytes) {
      binary += String.fromCharCode(byte);
    }

    return global.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  };

  const mapCreationOptions = (options) => ({
    ...options,
    challenge: base64UrlToUint8Array(options.challenge),
    user: {
      ...options.user,
      id: base64UrlToUint8Array(options.user.id),
    },
    excludeCredentials: Array.isArray(options.excludeCredentials)
      ? options.excludeCredentials.map((credential) => ({
          ...credential,
          id: base64UrlToUint8Array(credential.id),
        }))
      : options.excludeCredentials,
  });

  const mapRequestOptions = (options) => ({
    ...options,
    challenge: base64UrlToUint8Array(options.challenge),
    allowCredentials: Array.isArray(options.allowCredentials)
      ? options.allowCredentials.map((credential) => ({
          ...credential,
          id: base64UrlToUint8Array(credential.id),
        }))
      : options.allowCredentials,
  });

  const serializeCredential = (credential) => {
    if (credential && typeof credential.toJSON === 'function') {
      return credential.toJSON();
    }

    return {
      id: credential.id,
      rawId: uint8ArrayToBase64Url(credential.rawId),
      type: credential.type,
      authenticatorAttachment: credential.authenticatorAttachment || undefined,
      clientExtensionResults:
        typeof credential.getClientExtensionResults === 'function'
          ? credential.getClientExtensionResults()
          : {},
      response:
        credential.response instanceof AuthenticatorAttestationResponse
          ? {
              clientDataJSON: uint8ArrayToBase64Url(credential.response.clientDataJSON),
              attestationObject: uint8ArrayToBase64Url(credential.response.attestationObject),
              transports:
                typeof credential.response.getTransports === 'function'
                  ? credential.response.getTransports()
                  : undefined,
            }
          : {
              clientDataJSON: uint8ArrayToBase64Url(credential.response.clientDataJSON),
              authenticatorData: uint8ArrayToBase64Url(credential.response.authenticatorData),
              signature: uint8ArrayToBase64Url(credential.response.signature),
              userHandle: credential.response.userHandle
                ? uint8ArrayToBase64Url(credential.response.userHandle)
                : undefined,
            },
    };
  };

  const create = async (options) => {
    const publicKey =
      global.PublicKeyCredential &&
      typeof global.PublicKeyCredential.parseCreationOptionsFromJSON === 'function'
        ? global.PublicKeyCredential.parseCreationOptionsFromJSON(options)
        : mapCreationOptions(options);

    const credential = await global.navigator.credentials.create({ publicKey });
    if (!credential) {
      throw new Error('Passkey registration was cancelled.');
    }

    return serializeCredential(credential);
  };

  const get = async (options) => {
    const publicKey =
      global.PublicKeyCredential &&
      typeof global.PublicKeyCredential.parseRequestOptionsFromJSON === 'function'
        ? global.PublicKeyCredential.parseRequestOptionsFromJSON(options)
        : mapRequestOptions(options);

    const credential = await global.navigator.credentials.get({ publicKey });
    if (!credential) {
      throw new Error('Passkey sign-in was cancelled.');
    }

    return serializeCredential(credential);
  };

  global.WebAuthnJson = {
    isSupported() {
      return Boolean(global.PublicKeyCredential && global.navigator?.credentials);
    },
    async isConditionalMediationAvailable() {
      return Boolean(
        global.PublicKeyCredential &&
          typeof global.PublicKeyCredential.isConditionalMediationAvailable === 'function' &&
          (await global.PublicKeyCredential.isConditionalMediationAvailable())
      );
    },
    create,
    get,
  };
})(window);
