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
    if (window.TextEncoder) {
      return new TextEncoder('utf-8').encode(string)
    } else {
      // TextEncoder polyfill (https://developer.mozilla.org/en-US/docs/Web/API/TextEncoder)
      const stringLength = string.length
      const buffer = new Uint8Array(stringLength * 3)
      let resPos = -1
      for (let point = 0, nextcode = 0, i = 0; i !== stringLength; ) {
        ;(point = string.charCodeAt(i)), (i += 1)
        if (point >= 0xd800 && point <= 0xdbff) {
          if (i === stringLength) {
            buffer[(resPos += 1)] = 0xef /*0b11101111*/
            buffer[(resPos += 1)] = 0xbf /*0b10111111*/
            buffer[(resPos += 1)] = 0xbd /*0b10111101*/
            break
          }
          nextcode = string.charCodeAt(i)
          if (nextcode >= 0xdc00 && nextcode <= 0xdfff) {
            point = (point - 0xd800) * 0x400 + nextcode - 0xdc00 + 0x10000
            i += 1
            if (point > 0xffff) {
              buffer[(resPos += 1)] = (0x1e /*0b11110*/ << 3) | (point >>> 18)
              buffer[(resPos += 1)] = (0x2 /*0b10*/ << 6) | ((point >>> 12) & 0x3f) /*0b00111111*/
              buffer[(resPos += 1)] = (0x2 /*0b10*/ << 6) | ((point >>> 6) & 0x3f) /*0b00111111*/
              buffer[(resPos += 1)] = (0x2 /*0b10*/ << 6) | (point & 0x3f) /*0b00111111*/
              continue
            }
          } else {
            buffer[(resPos += 1)] = 0xef /*0b11101111*/
            buffer[(resPos += 1)] = 0xbf /*0b10111111*/
            buffer[(resPos += 1)] = 0xbd /*0b10111101*/
            continue
          }
        }
        if (point <= 0x007f) {
          buffer[(resPos += 1)] = (0x0 /*0b0*/ << 7) | point
        } else if (point <= 0x07ff) {
          buffer[(resPos += 1)] = (0x6 /*0b110*/ << 5) | (point >>> 6)
          buffer[(resPos += 1)] = (0x2 /*0b10*/ << 6) | (point & 0x3f) /*0b00111111*/
        } else {
          buffer[(resPos += 1)] = (0xe /*0b1110*/ << 4) | (point >>> 12)
          buffer[(resPos += 1)] = (0x2 /*0b10*/ << 6) | ((point >>> 6) & 0x3f) /*0b00111111*/
          buffer[(resPos += 1)] = (0x2 /*0b10*/ << 6) | (point & 0x3f) /*0b00111111*/
        }
      }
      buffer = new Uint8Array(buffer.buffer.slice(0, resPos + 1))
      return buffer
    }
  }

  async function hash(object) {
    const buffer = stringToArrayBuffer(typeof object === 'string' ? object : JSON.stringify(object))
    const sha256 = await crypto.subtle.digest('SHA-256', buffer)
    return toBase64(arrayBufferToString(sha256))
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

  ECDSA.prototype.hashAndSign = async function hashAndSign(
    message /*: string | Object */
  ) /*: Promise<string> */ {
    return this.sign(await hash(message))
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

  ECDSA.prototype.hashAndVerify = async function hashAndVerify(
    message /*: string | Object */,
    signature /*: string */
  ) /*: Promise<Boolean> */ {
    return this.verify(await hash(message), signature)
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
