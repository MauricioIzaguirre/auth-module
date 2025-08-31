import crypto from 'node:crypto'
import { webcrypto } from 'node:crypto'

// Utilizando las nuevas características crypto de Node.js 22
export class CryptoUtils {
  private static readonly ALGORITHM = 'aes-256-gcm'
  private static readonly KEY_LENGTH = 32
  private static readonly IV_LENGTH = 16
  private static readonly TAG_LENGTH = 16
  private static readonly SALT_LENGTH = 32

  /**
   * Genera una clave segura usando Node.js 22 WebCrypto API
   */
  static generateSecureKey(length: number = 64): string {
    return crypto.randomBytes(length).toString('hex')
  }

  /**
   * Genera un UUID v4 seguro
   */
  static generateUUID(): string {
    return crypto.randomUUID()
  }

  /**
   * Genera un token seguro para verificación de email, reset de password, etc.
   */
  static generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('urlsafe-base64')
  }

  /**
   * Deriva una clave desde una contraseña usando PBKDF2
   */
  static async deriveKey(password: string, salt: string, iterations: number = 100000): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      crypto.pbkdf2(password, salt, iterations, this.KEY_LENGTH, 'sha512', (err, derivedKey) => {
        if (err) reject(err)
        else resolve(derivedKey)
      })
    })
  }

  /**
   * Cifra datos sensibles usando AES-256-GCM
   */
  static async encrypt(plaintext: string, key: string): Promise<{
    encrypted: string
    iv: string
    tag: string
    salt: string
  }> {
    const salt = crypto.randomBytes(this.SALT_LENGTH)
    const derivedKey = await this.deriveKey(key, salt.toString('hex'))
    const iv = crypto.randomBytes(this.IV_LENGTH)
    
    const cipher = crypto.createCipher(this.ALGORITHM, derivedKey)
    cipher.setAAD(Buffer.from('auth-module', 'utf8'))
    
    let encrypted = cipher.update(plaintext, 'utf8', 'hex')
    encrypted += cipher.final('hex')
    
    const tag = cipher.getAuthTag()
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      tag: tag.toString('hex'),
      salt: salt.toString('hex')
    }
  }

  /**
   * Descifra datos usando AES-256-GCM
   */
  static async decrypt(encryptedData: {
    encrypted: string
    iv: string
    tag: string
    salt: string
  }, key: string): Promise<string> {
    const derivedKey = await this.deriveKey(key, encryptedData.salt)
    
    const decipher = crypto.createDecipher(this.ALGORITHM, derivedKey)
    decipher.setAAD(Buffer.from('auth-module', 'utf8'))
    decipher.setAuthTag(Buffer.from(encryptedData.tag, 'hex'))
    
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    
    return decrypted
  }

  /**
   * Hash seguro para tokens usando SHA-256
   */
  static hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex')
  }

  /**
   * Compara hashes de forma segura (timing-safe)
   */
  static secureCompare(a: string, b: string): boolean {
    if (a.length !== b.length) return false
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))
  }

  /**
   * Genera un hash seguro usando Web Crypto API de Node.js 22
   */
  static async webCryptoHash(data: string, algorithm: 'SHA-256' | 'SHA-384' | 'SHA-512' = 'SHA-256'): Promise<string> {
    const encoder = new TextEncoder()
    const dataBuffer = encoder.encode(data)
    const hashBuffer = await webcrypto.subtle.digest(algorithm, dataBuffer)
    return Array.from(new Uint8Array(hashBuffer))
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
  }

  /**
   * Genera una clave usando Web Crypto API para mayor seguridad
   */
  static async generateWebCryptoKey(algorithm: 'AES-GCM' | 'HMAC' = 'AES-GCM'): Promise<CryptoKey> {
    const keyOptions = algorithm === 'AES-GCM' 
      ? { name: 'AES-GCM', length: 256 }
      : { name: 'HMAC', hash: 'SHA-256' }

    return await webcrypto.subtle.generateKey(
      keyOptions,
      true, // extractable
      algorithm === 'AES-GCM' ? ['encrypt', 'decrypt'] : ['sign', 'verify']
    )
  }

  /**
   * Cifrado usando Web Crypto API (más eficiente en Node.js 22)
   */
  static async webCryptoEncrypt(plaintext: string, key: CryptoKey): Promise<{
    encrypted: string
    iv: string
  }> {
    const encoder = new TextEncoder()
    const data = encoder.encode(plaintext)
    const iv = crypto.getRandomValues(new Uint8Array(12)) // GCM recomienda 12 bytes

    const encrypted = await webcrypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      data
    )

    return {
      encrypted: Array.from(new Uint8Array(encrypted))
        .map(b => b.toString(16).padStart(2, '0'))
        .join(''),
      iv: Array.from(iv)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
    }
  }

  /**
   * Descifrado usando Web Crypto API
   */
  static async webCryptoDecrypt(encryptedData: {
    encrypted: string
    iv: string
  }, key: CryptoKey): Promise<string> {
    const iv = new Uint8Array(
      encryptedData.iv.match(/.{2}/g)!.map(byte => parseInt(byte, 16))
    )
    
    const encrypted = new Uint8Array(
      encryptedData.encrypted.match(/.{2}/g)!.map(byte => parseInt(byte, 16))
    )

    const decrypted = await webcrypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      encrypted
    )

    const decoder = new TextDecoder()
    return decoder.decode(decrypted)
  }

  /**
   * Genera un salt criptográficamente seguro
   */
  static generateSalt(): string {
    return crypto.randomBytes(this.SALT_LENGTH).toString('hex')
  }

  /**
   * Función de hash constante en tiempo para evitar timing attacks
   */
  static constantTimeHash(input: string): string {
    // Usando Node.js 22 scrypt que es más resistente a timing attacks
    const salt = crypto.randomBytes(16)
    return crypto.scryptSync(input, salt, 64).toString('hex') + ':' + salt.toString('hex')
  }

  /**
   * Verifica hash constante en tiempo
   */
  static verifyConstantTimeHash(input: string, hash: string): boolean {
    const [storedHash, salt] = hash.split(':')
    const inputHash = crypto.scryptSync(input, Buffer.from(salt, 'hex'), 64).toString('hex')
    return this.secureCompare(inputHash, storedHash)
  }

  /**
   * Genera un número aleatorio criptográficamente seguro en un rango
   */
  static secureRandomInRange(min: number, max: number): number {
    const range = max - min + 1
    const maxValid = Math.floor(0xFFFFFFFF / range) * range - 1
    
    let randomValue: number
    do {
      randomValue = crypto.randomBytes(4).readUInt32BE(0)
    } while (randomValue > maxValid)
    
    return min + (randomValue % range)
  }

  /**
   * Genera una cadena aleatoria segura con caracteres específicos
   */
  static generateSecureString(length: number, charset: string = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'): string {
    let result = ''
    for (let i = 0; i < length; i++) {
      const randomIndex = this.secureRandomInRange(0, charset.length - 1)
      result += charset[randomIndex]
    }
    return result
  }
}