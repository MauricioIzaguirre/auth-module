import winston from 'winston';
import { existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { config } from './environment.js';
import { LogLevel } from '../types/core';


// Use Winston's built-in TransformableInfo type instead of custom LogInfo
//type LogInfo = winston.LogEntry;

/**
 * Custom log format for better readability
 */
const customFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss.SSS'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf((info) => {
    const { timestamp, level, message, stack, ...meta } = info;
    const metaString = Object.keys(meta).length ? 
      `\n${JSON.stringify(meta, null, 2)}` : '';
    return `[${timestamp}] ${level.toUpperCase()}: ${String(message)}${metaString}`;
  })
);

/**
 * Console format for development
 */
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({
    format: 'HH:mm:ss'
  }),
  winston.format.printf((info) => {
    const { timestamp, level, message, ...meta } = info;
    const metaString = Object.keys(meta).length ? 
      ` ${JSON.stringify(meta)}` : '';
    return `[${timestamp}] ${level}: ${String(message)}${metaString}`;
  })
);

/**
 * Ensure log directory exists
 */
const ensureLogDirectory = (filePath: string): void => {
  const logDir = dirname(filePath);
  if (!existsSync(logDir)) {
    mkdirSync(logDir, { recursive: true });
  }
};

/**
 * Create transports based on environment
 */
const createTransports = (): winston.transport[] => {
  const transports: winston.transport[] = [];

  // Console transport for all environments
  transports.push(
    new winston.transports.Console({
      format: config.isDevelopment ? consoleFormat : customFormat,
      level: config.logging.level
    })
  );

  // File transport for production and staging
  if (config.isProduction || config.nodeEnv === 'staging') {
    ensureLogDirectory(config.logging.file);
    
    // General log file
    transports.push(
      new winston.transports.File({
        filename: config.logging.file,
        format: customFormat,
        level: 'info',
        maxsize: 10 * 1024 * 1024, // 10MB
        maxFiles: 5,
        tailable: true
      })
    );

    // Error log file
    const errorLogPath = config.logging.file.replace('.log', '.error.log');
    transports.push(
      new winston.transports.File({
        filename: errorLogPath,
        format: customFormat,
        level: 'error',
        maxsize: 10 * 1024 * 1024, // 10MB
        maxFiles: 5,
        tailable: true
      })
    );
  }

  return transports;
};

/**
 * Create Winston logger instance
 */
const createLogger = (): winston.Logger => {
  return winston.createLogger({
    level: config.logging.level,
    format: customFormat,
    defaultMeta: {
      service: 'auth-module',
      environment: config.nodeEnv,
      version: process.env.npm_package_version || '1.0.0'
    },
    transports: createTransports(),
    // Handle exceptions
    exceptionHandlers: config.isProduction ? [
      new winston.transports.File({
        filename: config.logging.file.replace('.log', '.exceptions.log'),
        format: customFormat
      })
    ] : [],
    // Handle rejections
    rejectionHandlers: config.isProduction ? [
      new winston.transports.File({
        filename: config.logging.file.replace('.log', '.rejections.log'),
        format: customFormat
      })
    ] : [],
    exitOnError: false
  });
};

// Create logger instance
export const logger = createLogger();

/**
 * Log levels mapping
 */
export const LOG_LEVELS: Record<string, LogLevel> = {
  ERROR: 'error',
  WARN: 'warn',
  INFO: 'info',
  DEBUG: 'debug'
} as const;

/**
 * Enhanced logger interface with additional methods
 */
export interface EnhancedLogger extends winston.Logger {
  database: (message: string, meta?: Record<string, unknown>) => void;
  auth: (message: string, meta?: Record<string, unknown>) => void;
  security: (message: string, meta?: Record<string, unknown>) => void;
  performance: (message: string, meta?: Record<string, unknown>) => void;
  api: (message: string, meta?: Record<string, unknown>) => void;
}

/**
 * Create enhanced logger with custom methods
 */
const createEnhancedLogger = (): EnhancedLogger => {
  const baseLogger = logger;

  // Add custom logging methods
  (baseLogger as EnhancedLogger).database = (
    message: string, 
    meta?: Record<string, unknown>
  ) => {
    baseLogger.info(message, { ...meta, component: 'database' });
  };

  (baseLogger as EnhancedLogger).auth = (
    message: string, 
    meta?: Record<string, unknown>
  ) => {
    baseLogger.info(message, { ...meta, component: 'auth' });
  };

  (baseLogger as EnhancedLogger).security = (
    message: string, 
    meta?: Record<string, unknown>
  ) => {
    baseLogger.warn(message, { ...meta, component: 'security' });
  };

  (baseLogger as EnhancedLogger).performance = (
    message: string, 
    meta?: Record<string, unknown>
  ) => {
    baseLogger.info(message, { ...meta, component: 'performance' });
  };

  (baseLogger as EnhancedLogger).api = (
    message: string, 
    meta?: Record<string, unknown>
  ) => {
    baseLogger.info(message, { ...meta, component: 'api' });
  };

  return baseLogger as EnhancedLogger;
};

// Export enhanced logger
export const enhancedLogger = createEnhancedLogger();

/**
 * Request logging middleware helper
 */
export const createRequestLogger = () => {
  return (req: any, res: any, next: any) => {
    const start = Date.now();
    
    // Override res.end to capture response time
    const originalEnd = res.end;
    res.end = function(...args: any[]) {
      const duration = Date.now() - start;
      
      enhancedLogger.api('HTTP Request', {
        method: req.method,
        url: req.url,
        statusCode: res.statusCode,
        duration: `${duration}ms`,
        userAgent: req.get('User-Agent'),
        ip: req.ip,
        userId: req.user?.id
      });
      
      originalEnd.apply(this, args);
    };
    
    next();
  };
};

/**
 * Error logging helper
 */
export const logError = (
  error: Error, 
  context?: Record<string, unknown>
): void => {
  logger.error(error.message, {
    stack: error.stack,
    name: error.name,
    ...context
  });
};

/**
 * Performance logging helper
 */
export const logPerformance = (
  operation: string,
  startTime: number,
  meta?: Record<string, unknown>
): void => {
  const duration = Date.now() - startTime;
  enhancedLogger.performance(`${operation} completed`, {
    duration: `${duration}ms`,
    ...meta
  });
};

/**
 * Security event logging helper
 */
export const logSecurityEvent = (
  event: string,
  severity: 'low' | 'medium' | 'high' | 'critical',
  meta?: Record<string, unknown>
): void => {
  enhancedLogger.security(`Security event: ${event}`, {
    severity,
    timestamp: new Date().toISOString(),
    ...meta
  });
};

/**
 * Database operation logging helper
 */
export const logDatabaseOperation = (
  operation: string,
  table: string,
  duration?: number,
  meta?: Record<string, unknown>
): void => {
  enhancedLogger.database(`Database ${operation}`, {
    table,
    duration: duration ? `${duration}ms` : undefined,
    ...meta
  });
};

/**
 * Authentication event logging helper
 */
export const logAuthEvent = (
  event: string,
  userId?: string,
  meta?: Record<string, unknown>
): void => {
  enhancedLogger.auth(`Auth event: ${event}`, {
    userId,
    timestamp: new Date().toISOString(),
    ...meta
  });
};

/**
 * Logger factory for different components
 */
export const createComponentLogger = (component: string) => {
  return {
    error: (message: string, meta?: Record<string, unknown>) =>
      logger.error(message, { ...meta, component }),
    warn: (message: string, meta?: Record<string, unknown>) =>
      logger.warn(message, { ...meta, component }),
    info: (message: string, meta?: Record<string, unknown>) =>
      logger.info(message, { ...meta, component }),
    debug: (message: string, meta?: Record<string, unknown>) =>
      logger.debug(message, { ...meta, component })
  };
};