/* global crypto, btoa, atob */

/* ========================================================================== *
 * From RFC-4492 (Appendix A) Equivalent Curves (Informative)                 *
 * ========================================================================== *
 *                                                                            *
 * +------------------------------------------------------------------------+ *
 * |                         Curve names chosen by                          | *
 * |                   different standards organizations                    | *
 * +-----------+------------+------------+------------+---------------------+ *
 * |   SECG    | ANSI X9.62 |    NIST    |  OpenSSL   |      ASN.1 OID      | *
 * +-----------+------------+------------+------------+---------------------+ *
 * | secp256r1 | prime256v1 | NIST P-256 | prime256v1 | 1.2.840.10045.3.1.7 | *
 * +-----------+------------+------------+------------+---------------------+ *
 * ========================================================================== */

;(function() {
  const ALGO = { name: 'ECDSA', namedCurve: 'P-256' }
  const SIGN_ALGO = { name: 'ECDSA', hash: { name: 'SHA-256' } }

  /* ========================================================================== *
   * CLASS DEFINITION                                                           *
   * ========================================================================== */

  function ECDSA({ publicKey /*: CryptoKey */, privateKey /*: ?CryptoKey */ }) {
    if (publicKey) this.publicKey = publicKey
    if (privateKey) this.privateKey = privateKey
  }

  /* ========================================================================== *
   * UTILS                                                                      *
   * ========================================================================== */

  function toBase64(buffer) {
    return btoa(buffer)
  }

  function fromBase64(string) {
    return atob(string)
  }

  function arrayBufferToString(buffer) {
    return String.fromCharCode.apply(null, new Uint8Array(buffer))
  }

  function stringToArrayBuffer(string) {
    const buffer = new ArrayBuffer(string.length)
    const bufferView = new Uint8Array(buffer)
    for (let i = 0, strLen = string.length; i < strLen; i++) {
      bufferView[i] = string.charCodeAt(i)
    }
    return buffer
  }

  /* ========================================================================== *
   * FACTORIES                                                                  *
   * ========================================================================== */

  ECDSA.generateKey = async () => /*: Promise<ECDSA> */ {
    const { privateKey, publicKey } = await crypto.subtle.generateKey(ALGO, true, [
      'sign',
      'verify'
    ])
    return new ECDSA({ privateKey, publicKey })
  }

  ECDSA.fromJWK = async (jwk /*: Object */) => /*: Promise<ECDSA> */ {
    const { d, ...rest } = jwk
    const keys = {
      publicKey: await crypto.subtle.importKey('jwk', rest, ALGO, true, ['verify'])
    }
    if (d) {
      keys.privateKey = await crypto.subtle.importKey('jwk', jwk, ALGO, true, ['sign'])
    }
    return new ECDSA(keys)
  }

  ECDSA.fromCompressedPublicKey = async (base64Key /*: string */) => /*: Promise<ECDSA> */ {
    const rawCompressedKey = stringToArrayBuffer(fromBase64(base64Key))
    return new ECDSA({
      publicKey: await crypto.subtle.importKey('raw', rawCompressedKey, ALGO, true, ['verify'])
    })
  }

  ECDSA.fromBase64PrivateKey = async (base64Key /*: string */) => /*: Promise<ECDSA> */ {
    const pkcs8Key = stringToArrayBuffer(fromBase64(base64Key))
    return new ECDSA({
      privateKey: await crypto.subtle.importKey('pkcs8', pkcs8Key, ALGO, true, ['sign'])
    })
  }

  /* ========================================================================== *
   * SIGNING / VALIDATION                                                       *
   * ========================================================================== */

  ECDSA.prototype.sign = async function sign(message /*: string */) /*: Promise<string> */ {
    const signature = await crypto.subtle.sign(
      SIGN_ALGO,
      this.privateKey,
      stringToArrayBuffer(message)
    )
    return toBase64(arrayBufferToString(signature))
  }

  ECDSA.prototype.verify = async function verify(
    message /*: string */,
    signature /*: string */
  ) /*: Promise<Boolean> */ {
    const signatureBuffer = stringToArrayBuffer(fromBase64(signature))
    return crypto.subtle.verify(
      SIGN_ALGO,
      this.publicKey,
      signatureBuffer,
      stringToArrayBuffer(message)
    )
  }

  /* ========================================================================== *
   * CONVERSION                                                                 *
   * ========================================================================== */

  ECDSA.prototype.asPublic = function asPublic() {
    if (!this.privateKey) return this
    return new ECDSA({ publicKey: this.publicKey })
  }

  ECDSA.prototype.toJWK = async function toJWK() /*: Promise<Object> */ {
    return crypto.subtle.exportKey('jwk', this.privateKey ? this.privateKey : this.publicKey)
  }

  ECDSA.prototype.toBase64PrivateKey = async function toBase64PrivateKey() /*: Promise<string> */ {
    const key = await crypto.subtle.exportKey('pkcs8', this.privateKey)
    return toBase64(arrayBufferToString(key))
  }

  ECDSA.prototype.toCompressedPublicKey = async function toCompressedPublicKey() /*: Promise<Uint8Array> */ {
    const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', this.publicKey))
    const x = new Uint8Array(rawKey.slice(1, rawKey.length / 2 + 1))
    const y = new Uint8Array(rawKey.slice(rawKey.length / 2 + 1))
    const compressedKey = new Uint8Array(x.length + 1)
    compressedKey[0] = 2 + (y[y.length - 1] & 1)
    compressedKey.set(x, 1)
    return compressedKey
  }

  ECDSA.prototype.toBase64CompressedPublicKey = async function toBase64CompressedPublicKey() /*: Promise<string> */ {
    const compressedKey = await this.toCompressedPublicKey()
    return toBase64(arrayBufferToString(compressedKey))
  }

  /* ========================================================================== *
   * EXPORTS                                                                    *
   * ========================================================================== */

  if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
    module.exports = ECDSA
  } else {
    if (typeof define === 'function' && define.amd) {
      define([], function() {
        return ECDSA
      })
    } else {
      window.ECDSA = ECDSA
    }
  }
})()
