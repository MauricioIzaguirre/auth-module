import bcrypt from 'bcrypt';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { config } from '@/config/environment';
import type { 
  JwtPayload, 
  RefreshTokenPayload, 
  PasswordResetTokenPayload,
  EmailVerificationTokenPayload 
} from '@/types/auth';

/**
 * Password hashing utilities using bcrypt
 */
export class PasswordCrypto {
  /**
   * Hash a password using bcrypt
   */
  static async hashPassword(password: string): Promise<string> {
    try {
      return await bcrypt.hash(password, config.security.bcryptSaltRounds);
    } catch (error) {
      throw new Error('Failed to hash password');
    }
  }

  /**
   * Verify a password against its hash
   */
  static async verifyPassword(password: string, hash: string): Promise<boolean> {
    try {
      return await bcrypt.compare(password, hash);
    } catch (error) {
      return false;
    }
  }

  /**
   * Generate a secure random password
   */
  static generateRandomPassword(length: number = 12): string {
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let password = '';
    
    for (let i = 0; i < length; i++) {
      const randomIndex = crypto.randomInt(0, charset.length);
      password += charset[randomIndex];
    }
    
    return password;
  }
}

/**
 * JWT token utilities
 */
export class TokenCrypto {
  /**
   * Generate an access token
   */
  static generateAccessToken(payload: Omit<JwtPayload, 'iat' | 'exp'>): string {
    try {
      const options: jwt.SignOptions = {
        expiresIn: config.security.jwtExpiresIn,
        issuer: 'auth-module',
        audience: 'auth-module-client'
      };

      return jwt.sign(payload, config.security.jwtSecret, options);
    } catch (error) {
      throw new Error('Failed to generate access token');
    }
  }

  /**
   * Generate a refresh token
   */
  static generateRefreshToken(payload: Omit<RefreshTokenPayload, 'iat' | 'exp'>): string {
    try {
      const options: jwt.SignOptions = {
        expiresIn: config.security.jwtRefreshExpiresIn,
        issuer: 'auth-module',
        audience: 'auth-module-client'
      };

      return jwt.sign(payload, config.security.jwtRefreshSecret, options);
    } catch (error) {
      throw new Error('Failed to generate refresh token');
    }
  }

  /**
   * Verify and decode an access token
   */
  static verifyAccessToken(token: string): JwtPayload {
    try {
      return jwt.verify(token, config.security.jwtSecret) as JwtPayload;
    } catch (error) {
      throw new Error('Invalid access token');
    }
  }

  /**
   * Verify and decode a refresh token
   */
  static verifyRefreshToken(token: string): RefreshTokenPayload {
    try {
      return jwt.verify(token, config.security.jwtRefreshSecret) as RefreshTokenPayload;
    } catch (error) {
      throw new Error('Invalid refresh token');
    }
  }

  /**
   * Generate a password reset token
   */
  static generatePasswordResetToken(userId: string, email: string): string {
    try {
      const payload: Omit<PasswordResetTokenPayload, 'iat' | 'exp'> = {
        sub: userId,
        email,
        type: 'password-reset'
      };

      const options: jwt.SignOptions = {
        expiresIn: '1h',
        issuer: 'auth-module',
        audience: 'auth-module-client'
      };

      return jwt.sign(payload, config.security.jwtSecret, options);
    } catch (error) {
      throw new Error('Failed to generate password reset token');
    }
  }

  /**
   * Generate an email verification token
   */
  static generateEmailVerificationToken(userId: string, email: string): string {
    try {
      const payload: Omit<EmailVerificationTokenPayload, 'iat' | 'exp'> = {
        sub: userId,
        email,
        type: 'email-verification'
      };

      const options: jwt.SignOptions = {
        expiresIn: '24h',
        issuer: 'auth-module',
        audience: 'auth-module-client'
      };

      return jwt.sign(payload, config.security.jwtSecret, options);
    } catch (error) {
      throw new Error('Failed to generate email verification token');
    }
  }

  /**
   * Verify a password reset token
   */
  static verifyPasswordResetToken(token: string): PasswordResetTokenPayload {
    try {
      const payload = jwt.verify(token, config.security.jwtSecret) as PasswordResetTokenPayload;
      
      if (payload.type !== 'password-reset') {
        throw new Error('Invalid token type');
      }
      
      return payload;
    } catch (error) {
      throw new Error('Invalid password reset token');
    }
  }

  /**
   * Verify an email verification token
   */
  static verifyEmailVerificationToken(token: string): EmailVerificationTokenPayload {
    try {
      const payload = jwt.verify(token, config.security.jwtSecret) as EmailVerificationTokenPayload;
      
      if (payload.type !== 'email-verification') {
        throw new Error('Invalid token type');
      }
      
      return payload;
    } catch (error) {
      throw new Error('Invalid email verification token');
    }
  }

  /**
   * Extract token from Authorization header
   */
  static extractBearerToken(authHeader?: string): string | null {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }
    
    return authHeader.substring(7);
  }
}

/**
 * General cryptographic utilities
 */
export class GeneralCrypto {
  /**
   * Generate a cryptographically secure random string
   */
  static generateSecureRandomString(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Generate a UUID v4
   */
  static generateUUID(): string {
    return crypto.randomUUID();
  }

  /**
   * Generate a secure random integer
   */
  static generateSecureRandomInt(min: number, max: number): number {
    const range = max - min + 1;
    const randomBytes = crypto.randomBytes(4);
    const randomInt = randomBytes.readUInt32BE(0);
    return min + (randomInt % range);
  }

  /**
   * Create a hash of arbitrary data
   */
  static createHash(data: string, algorithm: string = 'sha256'): string {
    return crypto.createHash(algorithm).update(data).digest('hex');
  }

  /**
   * Create HMAC signature
   */
  static createHMAC(data: string, secret: string, algorithm: string = 'sha256'): string {
    return crypto.createHmac(algorithm, secret).update(data).digest('hex');
  }

  /**
   * Verify HMAC signature
   */
  static verifyHMAC(data: string, signature: string, secret: string, algorithm: string = 'sha256'): boolean {
    const expectedSignature = this.createHMAC(data, secret, algorithm);
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expectedSignature));
  }

  /**
   * Generate a time-based one-time password (simple implementation)
   */
  static generateTOTP(secret: string, window: number = 30): string {
    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / window);
    const hmac = crypto.createHmac('sha1', secret);
    hmac.update(Buffer.from(counter.toString(16).padStart(16, '0'), 'hex'));
    const digest = hmac.digest();
    
    // Fix TypeScript strict null checks
    const lastByte = digest[digest.length - 1];
    if (lastByte === undefined) {
      throw new Error('Failed to generate TOTP: invalid digest');
    }
    
    const offset = lastByte & 0x0f;
    
    // Ensure array access is safe
    if (offset + 3 >= digest.length) {
      throw new Error('Failed to generate TOTP: invalid offset');
    }
    
    const binary = ((digest[offset]! & 0x7f) << 24) |
                   ((digest[offset + 1]! & 0xff) << 16) |
                   ((digest[offset + 2]! & 0xff) << 8) |
                   (digest[offset + 3]! & 0xff);
    
    return (binary % 1000000).toString().padStart(6, '0');
  }
}

/**
 * Session utilities
 */
export class SessionCrypto {
  /**
   * Generate a session token
   */
  static generateSessionToken(): string {
    return GeneralCrypto.generateSecureRandomString(64);
  }

  /**
   * Generate a refresh token for sessions
   */
  static generateRefreshTokenForSession(): string {
    return GeneralCrypto.generateSecureRandomString(128);
  }

  /**
   * Calculate token expiry date
   */
  static calculateExpiryDate(expiresIn: string): Date {
    const now = new Date();
    const duration = this.parseDuration(expiresIn);
    return new Date(now.getTime() + duration);
  }

  /**
   * Parse duration string (e.g., "1h", "7d", "30m")
   */
  private static parseDuration(duration: string): number {
    const match = duration.match(/^(\d+)([smhdwy])$/);
    if (!match) {
      throw new Error('Invalid duration format');
    }

    // Fix TypeScript undefined check
    const valueStr = match[1];
    const unit = match[2];
    
    if (!valueStr || !unit) {
      throw new Error('Invalid duration format');
    }

    const value = parseInt(valueStr, 10);

    const multipliers = {
      s: 1000,
      m: 1000 * 60,
      h: 1000 * 60 * 60,
      d: 1000 * 60 * 60 * 24,
      w: 1000 * 60 * 60 * 24 * 7,
      y: 1000 * 60 * 60 * 24 * 365
    } as const;

    const multiplier = multipliers[unit as keyof typeof multipliers];
    if (!multiplier) {
      throw new Error('Invalid duration unit');
    }

    return value * multiplier;
  }
}

/**
 * Export all crypto utilities
 */
export const CryptoUtils = {
  password: PasswordCrypto,
  token: TokenCrypto,
  general: GeneralCrypto,
  session: SessionCrypto
} as const;