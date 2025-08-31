import crypto from 'node:crypto'

export interface AuthConfig {
  jwt: {
    secret: string
    accessTokenExpiry: string
    refreshTokenExpiry: string
    issuer: string
    audience: string
    algorithm: 'HS256' | 'HS384' | 'HS512' | 'RS256' | 'RS384' | 'RS512'
  }
  bcrypt: {
    saltRounds: number
  }
  session: {
    secret: string
    maxAge: number
    httpOnly: boolean
    secure: boolean
    sameSite: 'strict' | 'lax' | 'none'
  }
  security: {
    maxLoginAttempts: number
    lockoutDuration: number // en millisegundos
    passwordPolicy: {
      minLength: number
      requireUppercase: boolean
      requireLowercase: boolean
      requireNumbers: boolean
      requireSpecialChars: boolean
    }
    rateLimiting: {
      windowMs: number
      maxRequests: number
    }
  }
  cors: {
    origins: string[]
    credentials: boolean
    optionsSuccessStatus: number
  }
}

const generateSecureKey = (): string => {
  return crypto.randomBytes(64).toString('hex')
}

const getAuthConfig = (): AuthConfig => {
  const isProduction = process.env.NODE_ENV === 'production'
  
  // En producción, el JWT_SECRET debe ser obligatorio
  const jwtSecret = process.env.JWT_SECRET || (isProduction ? 
    (() => { throw new Error('JWT_SECRET is required in production') })() : 
    generateSecureKey())
  
  const sessionSecret = process.env.SESSION_SECRET || (isProduction ?
    (() => { throw new Error('SESSION_SECRET is required in production') })() :
    generateSecureKey())

  return {
    jwt: {
      secret: jwtSecret,
      accessTokenExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
      refreshTokenExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
      issuer: process.env.JWT_ISSUER || 'auth-module',
      audience: process.env.JWT_AUDIENCE || 'auth-users',
      algorithm: (process.env.JWT_ALGORITHM as AuthConfig['jwt']['algorithm']) || 'HS256'
    },
    bcrypt: {
      saltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS || '12')
    },
    session: {
      secret: sessionSecret,
      maxAge: parseInt(process.env.SESSION_MAX_AGE || '3600000'), // 1 hora por defecto
      httpOnly: true,
      secure: isProduction, // Solo HTTPS en producción
      sameSite: isProduction ? 'strict' : 'lax'
    },
    security: {
      maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5'),
      lockoutDuration: parseInt(process.env.LOCKOUT_DURATION || '900000'), // 15 minutos
      passwordPolicy: {
        minLength: parseInt(process.env.PASSWORD_MIN_LENGTH || '8'),
        requireUppercase: process.env.PASSWORD_REQUIRE_UPPERCASE !== 'false',
        requireLowercase: process.env.PASSWORD_REQUIRE_LOWERCASE !== 'false',
        requireNumbers: process.env.PASSWORD_REQUIRE_NUMBERS !== 'false',
        requireSpecialChars: process.env.PASSWORD_REQUIRE_SPECIAL !== 'false'
      },
      rateLimiting: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW || '900000'), // 15 minutos
        maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '50')
      }
    },
    cors: {
      origins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
      credentials: process.env.CORS_CREDENTIALS !== 'false',
      optionsSuccessStatus: 200
    }
  }
}

export const authConfig = getAuthConfig()

export const validateAuthConfig = (config: AuthConfig): boolean => {
  // Validaciones críticas para producción
  if (process.env.NODE_ENV === 'production') {
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
      throw new Error('JWT_SECRET must be at least 32 characters in production')
    }
    if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
      throw new Error('SESSION_SECRET must be at least 32 characters in production')
    }
  }

  // Validar política de contraseñas
  if (config.security.passwordPolicy.minLength < 6) {
    throw new Error('Password minimum length should be at least 6 characters')
  }

  if (config.bcrypt.saltRounds < 10) {
    console.warn('Warning: bcrypt saltRounds should be at least 10 for security')
  }

  return true
}