const fs = require('fs/promises');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const sodium = require('libsodium-wrappers');

// ============================================================================
// EXCEPCIONES PERSONALIZADAS
// ============================================================================
class CrafyException extends Error {
  constructor(message, statusCode = null, cause = null) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    if (cause) {
      this.cause = cause;
    }
  }
}
class CrafyNetworkException extends CrafyException { }
class CrafyCryptoException extends CrafyException { }
class CrafyValidationException extends CrafyException { }

// ============================================================================
// ESTRATEGIAS DE ALMACENAMIENTO (Storage Adapters)
// ============================================================================
class StorageAdapter {
  async init() { }
  async getCache(key) { return null; }
  async setCache(key, data, expiresAt) { }
  async deleteCache(key) { }
  async storeNonce(nonce, expiresAt) { }
  async consumeNonce(nonce) { return false; }
  async clearAllNonces() { return 0; }
  async gcNonces() { }
}

/**
 * Almacenamiento por defecto utilizando archivos temporales del sistema operativo.
 */
class FileStorage extends StorageAdapter {
  constructor(tempDir) {
    super();
    this.cacheDir = tempDir;
    this.nonceDir = path.join(tempDir, 'crafy_nonces');
  }

  async init() {
    try {
      // FIX de Seguridad: Permisos 0o700 para evitar que otros usuarios lean/borren en entornos compartidos
      await fs.mkdir(this.nonceDir, { recursive: true, mode: 0o700 });
    } catch (err) { }
  }

  async getCache(key) {
    const filePath = path.join(this.cacheDir, `${key}.json`);
    try {
      return await fs.readFile(filePath, 'utf8');
    } catch (err) {
      return null;
    }
  }

  async setCache(key, data, expiresAt) {
    const filePath = path.join(this.cacheDir, `${key}.json`);
    try {
      // mode: 0o600 para que solo tu proceso tenga acceso al archivo de credenciales
      await fs.writeFile(filePath, data, { mode: 0o600 });
    } catch (err) { }
  }

  async deleteCache(key) {
    const filePath = path.join(this.cacheDir, `${key}.json`);
    try {
      await fs.unlink(filePath);
    } catch (err) { }
  }

  async storeNonce(nonce, expiresAt) {
    const filePath = path.join(this.nonceDir, `nonce_${nonce}.lock`);
    try {
      await fs.writeFile(filePath, expiresAt.toString(), { mode: 0o600 });
    } catch (err) { }
  }

  async consumeNonce(nonce) {
    const filePath = path.join(this.nonceDir, `nonce_${nonce}.lock`);
    try {
      // La desvinculación (unlink) del sistema de archivos es atómica
      await fs.unlink(filePath);
      return true;
    } catch (err) {
      return false;
    }
  }

  async clearAllNonces() {
    let count = 0;
    try {
      const files = await fs.readdir(this.nonceDir);
      for (const file of files) {
        if (file.startsWith('nonce_') && file.endsWith('.lock')) {
          await fs.unlink(path.join(this.nonceDir, file));
          count++;
        }
      }
    } catch (err) { }
    return count;
  }

  async gcNonces() {
    try {
      const files = await fs.readdir(this.nonceDir);
      const lockFiles = files.filter(f => f.startsWith('nonce_') && f.endsWith('.lock'));

      if (lockFiles.length > 50 || Math.random() < 0.01) {
        const now = Date.now();
        for (const file of lockFiles) {
          const filePath = path.join(this.nonceDir, file);
          try {
            const stats = await fs.stat(filePath);
            if (now - stats.mtimeMs > 1200000) { // 20 min TTL
              await fs.unlink(filePath);
            }
          } catch (e) { }
        }
      }
    } catch (err) { }
  }
}

// ============================================================================
// CLIENTE PRINCIPAL
// ============================================================================
class CrafyCAPTCHA {
  constructor(publicKey, secretKey, baseUrl = 'https://captcha.crafy.net/api') {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
    this.baseUrl = baseUrl.replace(/\/$/, '');

    // Configuración del cliente HTTP
    this.timeout = 10000; // ms
    this.maxRetries = 3;
    this.baseDelayMs = 500;
    this.retryStatusCodes = [429, 500, 502, 503, 504];

    // Estado interno
    this.accessToken = null;
    this.publicToken = null;
    this.tokenExpiresAt = null; // FIX de Rendimiento: Persistencia en RAM
    this.lastFlowVerifyError = null;

    // Por defecto, inicializamos el almacenamiento basado en archivos
    this.storage = new FileStorage(os.tmpdir());
  }

  setStorage(storageAdapter) {
    this.storage = storageAdapter;
    return this;
  }

  setTempDir(dirPath) {
    this.storage = new FileStorage(dirPath);
    return this;
  }

  setMaxRetries(retries) {
    this.maxRetries = Math.max(0, retries);
    return this;
  }

  setBaseDelayMs(milliseconds) {
    this.baseDelayMs = Math.max(0, milliseconds);
    return this;
  }

  setRetryStatusCodes(codes) {
    this.retryStatusCodes = codes;
    return this;
  }

  _getCacheKey() {
    return 'crafy_token_' + crypto.createHash('md5').update(this.publicKey + this.secretKey).digest('hex');
  }

  async getPublicToken() {
    await this.ensureAuth();
    return this.publicToken;
  }

  async createFlow(options = {}) {
    if (typeof this.storage.init === 'function') {
      await this.storage.init();
    }

    let nonce;
    try {
      // FIX Criptográfico: Protección ante fallos de entropía del SO
      nonce = crypto.randomBytes(32).toString('hex');
    } catch (err) {
      throw new CrafyCryptoException("CrafyCAPTCHA: Error del sistema al generar entropía segura.", null, err);
    }

    const expiresAt = Date.now() + 1200000; // TTL 20 mins
    await this.storage.storeNonce(nonce, expiresAt);

    const flowData = { ...options, nonce };
    const jsonOptions = JSON.stringify(flowData);

    return await this._encrypt(jsonOptions);
  }

  async verifyFlow(base64Payload) {
    this.lastFlowVerifyError = null;

    if (typeof this.storage.init === 'function') {
      await this.storage.init();
    }

    if (!base64Payload) {
      this.lastFlowVerifyError = 'El token está vacío.';
      return false;
    }

    let envelope;
    try {
      const jsonEnvelope = Buffer.from(base64Payload, 'base64').toString('utf8');
      envelope = JSON.parse(jsonEnvelope);
    } catch (e) {
      this.lastFlowVerifyError = 'No se pudo decodificar el token.';
      return false;
    }

    if (!envelope.payload || !envelope.server_sign) {
      this.lastFlowVerifyError = 'Token malformado.';
      return false;
    }

    const payloadJson = envelope.payload;
    const signature = envelope.server_sign;

    const expectedSignature = crypto.createHmac('sha256', this.secretKey)
      .update(payloadJson)
      .digest('hex');

    if (!crypto.timingSafeEqual(Buffer.from(expectedSignature), Buffer.from(signature))) {
      this.lastFlowVerifyError = 'Firma de seguridad inválida.';
      return false;
    }

    let data;
    try {
      data = JSON.parse(payloadJson);
    } catch (e) {
      this.lastFlowVerifyError = 'No se pudo decodificar el payload interno.';
      return false;
    }

    if (data.status !== 'success') {
      this.lastFlowVerifyError = 'Estado de Flow inválido.';
      return false;
    }

    if (!data.expires_at) {
      this.lastFlowVerifyError = 'Fecha de expiración no definida.';
      return false;
    }

    const expiresAt = new Date(data.expires_at).getTime();
    const now = Date.now();

    if (isNaN(expiresAt) || now > expiresAt) {
      this.lastFlowVerifyError = 'Token expirado o fecha inválida.';
      return false;
    }

    if (!data.nonce) {
      this.lastFlowVerifyError = 'Nonce no encontrado.';
      return false;
    }

    const decryptedNonce = await this._decrypt(data.nonce);
    if (!decryptedNonce) {
      this.lastFlowVerifyError = 'No se pudo decodificar el nonce.';
      return false;
    }

    const cleanNonce = decryptedNonce.replace(/[^a-f0-9]/g, '');
    if (cleanNonce !== decryptedNonce) {
      this.lastFlowVerifyError = 'Nonce inválido.';
      return false;
    }

    const consumed = await this.storage.consumeNonce(cleanNonce);
    if (!consumed) {
      this.lastFlowVerifyError = 'Nonce ya utilizado (Replay Attack) o expirado.';
      return false;
    }

    // Limpieza asíncrona (no bloqueante)
    this.storage.gcNonces().catch(() => { });

    return true;
  }

  getLastFlowVerifyError() {
    return this.lastFlowVerifyError;
  }

  async clearAllNonces() {
    return await this.storage.clearAllNonces();
  }

  async call(action, data = {}) {
    await this.ensureAuth();

    try {
      return await this.sendRequest(action, data, true);
    } catch (err) {
      // Se reintenta solo frente a errores legítimos de autenticación
      if (err.statusCode === 401) {
        await this.clearCache();
        await this.ensureAuth(true);
        return await this.sendRequest(action, data, true);
      }
      throw err;
    }
  }

  async ensureAuth(forceRefresh = false) {
    // FIX de Rendimiento: Leemos directamente desde la RAM si es válido
    if (!forceRefresh && this.accessToken && this.publicToken && this.tokenExpiresAt) {
      if (Date.now() / 1000 < (this.tokenExpiresAt - 60)) return;
    }

    if (!forceRefresh) {
      const rawContent = await this.storage.getCache(this._getCacheKey());
      if (rawContent) {
        const decrypted = await this._decrypt(rawContent);
        if (decrypted) {
          try {
            const cached = JSON.parse(decrypted);
            if (cached.token && cached.public_token && cached.expires_at) {
              if (Date.now() / 1000 < (cached.expires_at - 60)) {
                this.accessToken = cached.token;
                this.publicToken = cached.public_token;
                // FIX Crítico (Amnesia de Caché): Llenamos la memoria RAM también para no volver a leer del disco
                this.tokenExpiresAt = parseInt(cached.expires_at, 10);
                return;
              }
            }
          } catch (e) { }
        }
      }
    }

    const authPayload = { public_key: this.publicKey, secret_key: this.secretKey };
    const response = await this.sendRequest('authenticate', authPayload, false);

    if (!response.token || !response.public_token) {
      throw new CrafyValidationException("CrafyCAPTCHA SDK: Error en la respuesta de autenticación.");
    }

    this.accessToken = response.token;
    this.publicToken = response.public_token;

    const expiresIn = parseInt(response.expires_in || 86400, 10);
    this.tokenExpiresAt = Math.floor(Date.now() / 1000) + expiresIn;

    await this._saveCache(this.accessToken, this.publicToken, this.tokenExpiresAt);
  }

  async _saveCache(token, publicToken, expiresAt) {
    const data = JSON.stringify({ token, public_token: publicToken, expires_at: expiresAt });
    const encryptedData = await this._encrypt(data);
    await this.storage.setCache(this._getCacheKey(), encryptedData, expiresAt);
  }

  async clearCache() {
    this.accessToken = null;
    this.publicToken = null;
    this.tokenExpiresAt = null;
    await this.storage.deleteCache(this._getCacheKey());
  }

  async sendRequest(action, data, useAuth) {
    const url = `${this.baseUrl}/?action=${encodeURIComponent(action)}`;

    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': 'CrafyCAPTCHA-Node-SDK/2.3'
    };

    if (useAuth && this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }

    let attempt = 0;
    const maxAttempts = this.maxRetries + 1;

    while (attempt < maxAttempts) {
      attempt++;
      let response;

      try {
        response = await fetch(url, {
          method: 'POST',
          headers,
          body: JSON.stringify(data),
          signal: AbortSignal.timeout(this.timeout)
        });
      } catch (networkErr) {
        if (attempt >= maxAttempts) {
          // FIX: Lanzamos la excepción de red personalizada
          throw new CrafyNetworkException(`CrafyCAPTCHA Network Error: ${networkErr.message}`, null, networkErr);
        }
        await this._delay(this._calculateBackoff(attempt));
        continue;
      }

      const httpCode = response.status;
      let shouldRetry = this.retryStatusCodes.includes(httpCode);

      if (shouldRetry && attempt < maxAttempts) {
        let delayUs = this._calculateBackoff(attempt) * 1000;
        const retryAfter = response.headers.get('retry-after');
        if (retryAfter) {
          if (!isNaN(retryAfter)) {
            delayUs = parseInt(retryAfter, 10) * 1000000;
          } else {
            const time = new Date(retryAfter).getTime();
            if (time > Date.now()) delayUs = (time - Date.now()) * 1000;
          }
        }
        await this._delay(delayUs / 1000);
        continue;
      }

      if (httpCode === 401) {
        throw new CrafyValidationException("Unauthorized (Invalid Keys)", 401);
      }

      let resultRaw = await response.text();
      let jsonResp;

      try {
        jsonResp = JSON.parse(resultRaw);
      } catch (e) {
        // FIX: Parseo estricto del JSON protegido bajo nuestras excepciones de red/validación
        if (httpCode >= 400) {
          throw new CrafyNetworkException(`CrafyCAPTCHA HTTP Error (${httpCode})`, httpCode, e);
        }
        throw new CrafyNetworkException(`CrafyCAPTCHA API Error: Respuesta inválida. HTTP Code: ${httpCode}. Detalles: ${e.message}`, httpCode, e);
      }

      if (jsonResp.status === 'error') {
        const msg = jsonResp.message || 'Error desconocido';
        throw new CrafyValidationException(msg, httpCode);
      }

      if (httpCode >= 400) {
        throw new CrafyNetworkException(`CrafyCAPTCHA HTTP Error (${httpCode})`, httpCode);
      }

      return jsonResp.data || {};
    }

    throw new CrafyNetworkException("CrafyCAPTCHA: Max retries exceeded.");
  }

  _calculateBackoff(attempt) {
    return this.baseDelayMs * Math.pow(2, attempt - 1);
  }

  _delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async _initSodiumKeys() {
    await sodium.ready;
    this.v1Key = crypto.createHash('sha256').update(this.secretKey).digest();
    this.v3Key = sodium.crypto_generichash(32, this.secretKey);
  }

  async _encrypt(plaintext, version = 3) {
    try {
      await this._initSodiumKeys();

      if (version === 3) {
        const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
          plaintext, null, null, nonce, this.v3Key
        );
        const combined = new Uint8Array(nonce.length + ciphertext.length);
        combined.set(nonce);
        combined.set(ciphertext, nonce.length);
        return ';v3_;' + Buffer.from(combined).toString('base64');
      } else if (version === 2) {
        const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
        const key = sodium.crypto_pwhash(
          sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
          this.secretKey, salt,
          sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
          sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
          sodium.crypto_pwhash_ALG_DEFAULT
        );
        const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
        const ciphertext = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
          plaintext, null, null, nonce, key
        );
        sodium.memzero(key);
        const combined = new Uint8Array(salt.length + nonce.length + ciphertext.length);
        combined.set(salt);
        combined.set(nonce, salt.length);
        combined.set(ciphertext, salt.length + nonce.length);
        return ';v2_;' + Buffer.from(combined).toString('base64');
      } else {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv('aes-256-cbc', this.v1Key, iv);
        let cipherText = cipher.update(plaintext);
        cipherText = Buffer.concat([cipherText, cipher.final()]);
        const hash = crypto.createHmac('sha256', this.v1Key).update(cipherText).digest();
        return Buffer.concat([iv, hash, cipherText]).toString('hex');
      }
    } catch (e) {
      // FIX Criptográfico: Manejo estricto si algún módulo de encriptación arroja un TypeError
      throw new CrafyCryptoException("Error interno: Fallo al encriptar el payload.", null, e);
    }
  }

  async _decrypt(input) {
    try {
      await this._initSodiumKeys();
      const firstChars = input.substring(0, 5);

      if (firstChars === ';v3_;') {
        const decoded = Buffer.from(input.substring(5), 'base64');
        const nonceLen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        if (decoded.length < nonceLen) return null;
        const nonce = new Uint8Array(decoded.subarray(0, nonceLen));
        const ciphertext = new Uint8Array(decoded.subarray(nonceLen));
        try {
          const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, ciphertext, null, nonce, this.v3Key
          );
          return Buffer.from(plaintext).toString('utf8');
        } catch (e) { return null; }
      } else if (firstChars === ';v2_;') {
        const decoded = Buffer.from(input.substring(5), 'base64');
        const saltLen = sodium.crypto_pwhash_SALTBYTES;
        const nonceLen = sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
        if (decoded.length < (saltLen + nonceLen + 1)) return null;
        const salt = new Uint8Array(decoded.subarray(0, saltLen));
        const nonce = new Uint8Array(decoded.subarray(saltLen, saltLen + nonceLen));
        const ciphertext = new Uint8Array(decoded.subarray(saltLen + nonceLen));
        const key = sodium.crypto_pwhash(
          sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
          this.secretKey, salt,
          sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
          sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
          sodium.crypto_pwhash_ALG_DEFAULT
        );
        try {
          const plaintext = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
            null, ciphertext, null, nonce, key
          );
          sodium.memzero(key);
          return Buffer.from(plaintext).toString('utf8');
        } catch (e) {
          sodium.memzero(key);
          return null;
        }
      } else {
        if (input.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(input)) return null;
        const binaryInput = Buffer.from(input, 'hex');
        if (binaryInput.length < 48) return null;
        const iv = binaryInput.subarray(0, 16);
        const hash = binaryInput.subarray(16, 48);
        const cipherText = binaryInput.subarray(48);
        const calculatedHash = crypto.createHmac('sha256', this.v1Key).update(cipherText).digest();
        if (!crypto.timingSafeEqual(hash, calculatedHash)) return null;
        try {
          const decipher = crypto.createDecipheriv('aes-256-cbc', this.v1Key, iv);
          let plaintext = decipher.update(cipherText);
          plaintext = Buffer.concat([plaintext, decipher.final()]);
          return plaintext.toString('utf8');
        } catch (e) { return null; }
      }
    } catch (e) {
      return null; // Si se inyecta contenido corrupto, fallamos silenciosamente retornando null
    }
  }
}

// Exportamos todo para uso externo
module.exports = {
  CrafyCAPTCHA,
  StorageAdapter,
  FileStorage,
  CrafyException,
  CrafyNetworkException,
  CrafyCryptoException,
  CrafyValidationException
};