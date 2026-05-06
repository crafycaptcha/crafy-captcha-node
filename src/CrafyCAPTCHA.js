const fs = require('fs/promises');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const sodium = require('libsodium-wrappers');

class CrafyCAPTCHA {
  /**
   * Constructor
   * @param {string} publicKey La llave pública (pk_...)
   * @param {string} secretKey La llave secreta (sk_...)
   * @param {string} baseUrl URL de la API (por defecto producción)
   */
  constructor(publicKey, secretKey, baseUrl = 'https://captcha.crafy.net/api') {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
    this.baseUrl = baseUrl.replace(/\/$/, '');

    // Configuración del cliente HTTP
    this.timeout = 10000; // ms

    // Configuración de Exponential Backoff
    this.maxRetries = 3;
    this.baseDelayMs = 500;
    this.retryStatusCodes = [429, 500, 502, 503, 504];

    // Estado interno
    this.accessToken = null;
    this.lastFlowVerifyError = null;

    // Configuración de rutas (Síncrono en el constructor)
    const hash = crypto.createHash('md5').update(this.publicKey + this.secretKey).digest('hex');
    this.tempDir = os.tmpdir();
    this.cacheFile = path.join(this.tempDir, `crafy_token_${hash}.json`);
    this.nonceDir = path.join(this.tempDir, 'crafy_nonces');
  }

  /**
   * Inicializa el directorio temporal (debe llamarse antes de usar si se cambia la ruta)
   */
  async init() {
    try {
      await fs.mkdir(this.nonceDir, { recursive: true });
    } catch (err) {
      // Ignorar si ya existe
    }
  }

  setTempDir(dirPath) {
    const hash = crypto.createHash('md5').update(this.publicKey + this.secretKey).digest('hex');
    this.tempDir = dirPath;
    this.cacheFile = path.join(this.tempDir, `crafy_token_${hash}.json`);
    this.nonceDir = path.join(this.tempDir, 'crafy_nonces');
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

  /**
   * Crea un nuevo Flow seguro para el cliente.
   * @param {object} options Opciones de personalización.
   * @returns {Promise<string>} Opciones encriptadas (Ciphertext Base64).
   */
  async createFlow(options = {}) {
    await this.init();

    const nonce = crypto.randomBytes(32).toString('hex');
    const nonceFile = path.join(this.nonceDir, `nonce_${nonce}.lock`);

    try {
      await fs.writeFile(nonceFile, Date.now().toString());
    } catch (err) {
      throw new Error("CrafyCAPTCHA: No se pudo escribir el archivo nonce temporal.");
    }

    const flowData = { ...options, nonce };
    const jsonOptions = JSON.stringify(flowData);

    return await this._encrypt(jsonOptions);
  }

  /**
   * Verifica un Flow completado sin llamar a la API externa.
   * @param {string} base64Payload El string base64 recibido del frontend.
   * @returns {Promise<boolean>} True si el desafío es válido y seguro.
   */
  async verifyFlow(base64Payload) {
    this.lastFlowVerifyError = null;
    await this.init();

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

    // Validar Firma (HMAC SHA256)
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

    const nonceFile = path.join(this.nonceDir, `nonce_${cleanNonce}.lock`);

    try {
      await fs.unlink(nonceFile);
    } catch (err) {
      this.lastFlowVerifyError = 'Nonce ya utilizado (Replay Attack).';
      return false;
    }

    // Garbage Collection (asíncrono, sin bloquear la respuesta)
    this._triggerGarbageCollection().catch(() => { });

    return true;
  }

  getLastFlowVerifyError() {
    return this.lastFlowVerifyError;
  }

  async _triggerGarbageCollection() {
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

  /**
   * Llamadas a la API
   */
  async call(action, data = {}) {
    await this.ensureAuth();

    try {
      return await this.sendRequest(action, data, true);
    } catch (err) {
      if (err.statusCode === 401) {
        await this.clearCache();
        await this.ensureAuth(true);
        return await this.sendRequest(action, data, true);
      }
      throw err;
    }
  }

  async ensureAuth(forceRefresh = false) {
    if (!forceRefresh && this.accessToken) return;

    if (!forceRefresh) {
      try {
        const cacheContent = await fs.readFile(this.cacheFile, 'utf8');
        const cached = JSON.parse(cacheContent);
        if (cached.token && cached.expires_at && Date.now() / 1000 < (cached.expires_at - 60)) {
          this.accessToken = cached.token;
          return;
        }
      } catch (err) { } // Archivo no existe o JSON inválido
    }

    const authPayload = { public_key: this.publicKey, secret_key: this.secretKey };
    const response = await this.sendRequest('authenticate', authPayload, false);

    if (!response.token) {
      throw new Error("CrafyCAPTCHA SDK: No se recibió token de autenticación.");
    }

    this.accessToken = response.token;
    const expiresIn = parseInt(response.expires_in || 3600, 10);
    await this._saveCache(this.accessToken, Math.floor(Date.now() / 1000) + expiresIn);
  }

  async _saveCache(token, expiresAt) {
    const data = JSON.stringify({ token, expires_at: expiresAt });
    try {
      await fs.writeFile(this.cacheFile, data, { mode: 0o600 });
    } catch (err) { }
  }

  async clearCache() {
    this.accessToken = null;
    try {
      await fs.unlink(this.cacheFile);
    } catch (err) { }
  }

  async sendRequest(action, data, useAuth) {
    const url = `${this.baseUrl}/?action=${encodeURIComponent(action)}`;

    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'User-Agent': 'CrafyCAPTCHA-Node-SDK/2.2'
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
        // Usamos la API global fetch (requiere Node 18+)
        response = await fetch(url, {
          method: 'POST',
          headers,
          body: JSON.stringify(data),
          signal: AbortSignal.timeout(this.timeout)
        });
      } catch (networkErr) {
        // Network error o timeout
        if (attempt >= maxAttempts) throw new Error(`CrafyCAPTCHA Network Error: ${networkErr.message}`);
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
            if (time > Date.now()) {
              delayUs = (time - Date.now()) * 1000;
            }
          }
        }
        await this._delay(delayUs / 1000);
        continue;
      }

      if (httpCode === 401) {
        const err = new Error("Unauthorized");
        err.statusCode = 401;
        throw err;
      }

      let resultRaw = await response.text();
      let jsonResp;

      try {
        jsonResp = JSON.parse(resultRaw);
      } catch (e) {
        if (httpCode >= 400) {
          const err = new Error(`CrafyCAPTCHA HTTP Error (${httpCode})`);
          err.statusCode = httpCode;
          throw err;
        }
        throw new Error(`CrafyCAPTCHA API Error: Respuesta inválida. HTTP Code: ${httpCode}`);
      }

      if (jsonResp.status === 'error') {
        const msg = jsonResp.message || 'Error desconocido';
        const err = new Error(msg);
        err.statusCode = httpCode;
        throw err;
      }

      if (httpCode >= 400) {
        const err = new Error(`CrafyCAPTCHA HTTP Error (${httpCode})`);
        err.statusCode = httpCode;
        throw err;
      }

      return jsonResp.data || {};
    }

    throw new Error("CrafyCAPTCHA: Max retries exceeded.");
  }

  _calculateBackoff(attempt) {
    return this.baseDelayMs * Math.pow(2, attempt - 1);
  }

  _delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * MÉTODOS CRIPTOGRÁFICOS (Equivalente a BitBookLiteCryptor en PHP)
   */
  async _initSodiumKeys() {
    await sodium.ready;
    this.v1Key = crypto.createHash('sha256').update(this.secretKey).digest();
    this.v3Key = sodium.crypto_generichash(32, this.secretKey);
  }

  async _encrypt(plaintext, version = 3) {
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
        this.secretKey,
        salt,
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
  }

  async _decrypt(input) {
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
      } catch (e) {
        return null;
      }

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
        this.secretKey,
        salt,
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
      } catch (e) {
        return null;
      }
    }
  }
}

module.exports = CrafyCAPTCHA;