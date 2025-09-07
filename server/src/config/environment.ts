import { config as dotenvConfig } from 'dotenv';
import { z } from 'zod';
import type { Environment, LogLevel } from '@/types/core';

// Load environment variables
dotenvConfig();

/**
 * Environment variables validation schema
 * Uses Zod for runtime validation and type safety
 */
const environmentSchema = z.object({
  // Server Configuration
  NODE_ENV: z.enum(['development', 'testing', 'staging', 'production'])
    .default('development'),
  PORT: z.coerce.number().min(1).max(65535).default(3000),
  API_VERSION: z.string().default('v1'),

  // Database Configuration
  DB_HOST: z.string().min(1, 'Database host is required'),
  DB_PORT: z.coerce.number().min(1).max(65535).default(5432),
  DB_NAME: z.string().min(1, 'Database name is required'),
  DB_USER: z.string().min(1, 'Database user is required'),
  DB_PASSWORD: z.string().min(1, 'Database password is required'),
  DB_MAX_CONNECTIONS: z.coerce.number().min(1).max(100).default(20),
  DB_MIN_CONNECTIONS: z.coerce.number().min(0).max(50).default(5),
  DB_IDLE_TIMEOUT: z.coerce.number().min(1000).default(30000),
  DB_CONNECTION_TIMEOUT: z.coerce.number().min(1000).default(60000),

  // JWT Configuration
  JWT_SECRET: z.string().min(32, 'JWT secret must be at least 32 characters'),
  JWT_EXPIRES_IN: z.string().default('1h'),
  JWT_REFRESH_SECRET: z.string()
    .min(32, 'JWT refresh secret must be at least 32 characters'),
  JWT_REFRESH_EXPIRES_IN: z.string().default('7d'),

  // Bcrypt Configuration
  BCRYPT_SALT_ROUNDS: z.coerce.number().min(10).max(15).default(12),

  // Rate Limiting
  RATE_LIMIT_WINDOW_MS: z.coerce.number().min(1000).default(900000), // 15 minutes
  RATE_LIMIT_MAX_REQUESTS: z.coerce.number().min(1).default(100),

  // Session Configuration
  SESSION_SECRET: z.string().min(32, 'Session secret must be at least 32 characters'),
  SESSION_MAX_AGE: z.coerce.number().min(1000).default(86400000), // 24 hours

  // Email Configuration
  SMTP_HOST: z.string().optional(),
  SMTP_PORT: z.coerce.number().min(1).max(65535).optional(),
  SMTP_USER: z.string().email().optional(),
  SMTP_PASSWORD: z.string().optional(),
  SMTP_FROM: z.string().email().optional(),

  // Logging
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  LOG_FILE: z.string().default('logs/app.log'),

  // CORS Configuration
  CORS_ORIGIN: z.string().default('http://localhost:3000'),

  // Security
  HELMET_ENABLED: z.coerce.boolean().default(true),

  // Development
  DEBUG: z.string().optional()
});

/**
 * Validate and parse environment variables
 */
function validateEnvironment() {
  try {
    return environmentSchema.parse(process.env);
  } catch (error) {
    if (error instanceof z.ZodError) {
      const errorMessages = error.errors.map(
        (err: z.ZodIssue) => `${err.path.join('.')}: ${err.message}`
      );
      throw new Error(
        `Environment validation failed:\n${errorMessages.join('\n')}`
      );
    }
    throw error;
  }
}

// Validate and export environment configuration
export const env = validateEnvironment();

/**
 * Type-safe environment configuration
 */
export interface EnvironmentConfig {
  // Server
  readonly nodeEnv: Environment;
  readonly port: number;
  readonly apiVersion: string;
  readonly isDevelopment: boolean;
  readonly isProduction: boolean;
  readonly isTesting: boolean;

  // Database
  readonly database: {
    readonly host: string;
    readonly port: number;
    readonly name: string;
    readonly user: string;
    readonly password: string;
    readonly maxConnections: number;
    readonly minConnections: number;
    readonly idleTimeout: number;
    readonly connectionTimeout: number;
  };

  // Security
  readonly security: {
    readonly jwtSecret: string;
    readonly jwtExpiresIn: string;
    readonly jwtRefreshSecret: string;
    readonly jwtRefreshExpiresIn: string;
    readonly bcryptSaltRounds: number;
    readonly sessionSecret: string;
    readonly sessionMaxAge: number;
  };

  // Rate limiting
  readonly rateLimit: {
    readonly windowMs: number;
    readonly maxRequests: number;
  };

  // Email (optional)
  readonly email?: {
    readonly host: string;
    readonly port: number;
    readonly user: string;
    readonly password: string;
    readonly from: string;
  };

  // Logging
  readonly logging: {
    readonly level: LogLevel;
    readonly file: string;
  };

  // CORS
  readonly cors: {
    readonly origins: readonly string[];
  };
}

/**
 * Create typed configuration object
 */
export const config: EnvironmentConfig = {
  // Server
  nodeEnv: env.NODE_ENV,
  port: env.PORT,
  apiVersion: env.API_VERSION,
  isDevelopment: env.NODE_ENV === 'development',
  isProduction: env.NODE_ENV === 'production',
  isTesting: env.NODE_ENV === 'testing',

  // Database
  database: {
    host: env.DB_HOST,
    port: env.DB_PORT,
    name: env.DB_NAME,
    user: env.DB_USER,
    password: env.DB_PASSWORD,
    maxConnections: env.DB_MAX_CONNECTIONS,
    minConnections: env.DB_MIN_CONNECTIONS,
    idleTimeout: env.DB_IDLE_TIMEOUT,
    connectionTimeout: env.DB_CONNECTION_TIMEOUT
  },

  // Security
  security: {
    jwtSecret: env.JWT_SECRET,
    jwtExpiresIn: env.JWT_EXPIRES_IN,
    jwtRefreshSecret: env.JWT_REFRESH_SECRET,
    jwtRefreshExpiresIn: env.JWT_REFRESH_EXPIRES_IN,
    bcryptSaltRounds: env.BCRYPT_SALT_ROUNDS,
    sessionSecret: env.SESSION_SECRET,
    sessionMaxAge: env.SESSION_MAX_AGE
  },

  // Rate limiting
  rateLimit: {
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    maxRequests: env.RATE_LIMIT_MAX_REQUESTS
  },

  // Email (conditional assignment)
  ...(env.SMTP_HOST && env.SMTP_PORT && env.SMTP_USER && 
     env.SMTP_PASSWORD && env.SMTP_FROM ? {
    email: {
      host: env.SMTP_HOST,
      port: env.SMTP_PORT,
      user: env.SMTP_USER,
      password: env.SMTP_PASSWORD,
      from: env.SMTP_FROM
    }
  } : {}),

  // Logging
  logging: {
    level: env.LOG_LEVEL,
    file: env.LOG_FILE
  },

  // CORS
  cors: {
    origins: env.CORS_ORIGIN.split(',').map((origin: string) => origin.trim())
  }
};

/**
 * Helper functions for environment checks
 */
export const isProduction = (): boolean => config.nodeEnv === 'production';
export const isDevelopment = (): boolean => config.nodeEnv === 'development';
export const isTesting = (): boolean => config.nodeEnv === 'testing';

/**
 * Get configuration for specific environment
 */
export const getConfigForEnvironment = (environment: Environment): Partial<EnvironmentConfig> => {
  const baseConfig = { ...config };

  switch (environment) {
    case 'development':
      return {
        ...baseConfig,
        logging: { ...baseConfig.logging, level: 'debug' }
      };
      
    case 'testing':
      return {
        ...baseConfig,
        database: {
          ...baseConfig.database,
          name: `${baseConfig.database.name}_test`
        },
        logging: { ...baseConfig.logging, level: 'warn' }
      };
      
    case 'production':
      return {
        ...baseConfig,
        logging: { ...baseConfig.logging, level: 'info' }
      };
      
    default:
      return baseConfig;
  }
};

/**
 * Validate required configuration
 */
export const validateConfiguration = (): void => {
  const requiredConfigs = [
    'JWT_SECRET',
    'JWT_REFRESH_SECRET',
    'SESSION_SECRET',
    'DB_HOST',
    'DB_NAME',
    'DB_USER',
    'DB_PASSWORD'
  ] as const;

  const missing = requiredConfigs.filter(key => !env[key]);
  
  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(', ')}`
    );
  }
};

// Validate configuration on module load
validateConfiguration();