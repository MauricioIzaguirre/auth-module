import { appConfig } from '../config'

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3
}

export interface LogEntry {
  timestamp: string
  level: string
  message: string
  module?: string
  userId?: string
  correlationId?: string
  metadata?: Record<string, any>
  stack?: string
}

export class Logger {
  private static instance: Logger
  private currentLevel: LogLevel
  private moduleName: string

  private constructor(moduleName: string = 'auth-module') {
    this.moduleName = moduleName
    this.currentLevel = this.getLevelFromString(appConfig.logLevel)
  }

  static getInstance(moduleName?: string): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger(moduleName)
    }
    return Logger.instance
  }

  static create(moduleName: string): Logger {
    return new Logger(moduleName)
  }

  private getLevelFromString(level: string): LogLevel {
    switch (level.toLowerCase()) {
      case 'debug': return LogLevel.DEBUG
      case 'info': return LogLevel.INFO
      case 'warn': return LogLevel.WARN
      case 'error': return LogLevel.ERROR
      default: return LogLevel.INFO
    }
  }

  private shouldLog(level: LogLevel): boolean {
    return level >= this.currentLevel
  }

  private formatMessage(level: string, message: string, metadata?: Record<string, any>): LogEntry {
    const timestamp = new Date().toISOString()
    
    return {
      timestamp,
      level,
      message,
      module: this.moduleName,
      metadata: metadata || {},
      correlationId: this.generateCorrelationId()
    }
  }

  private generateCorrelationId(): string {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
  }

  private output(logEntry: LogEntry): void {
    const formattedMessage = this.formatForOutput(logEntry)
    
    switch (logEntry.level) {
      case 'ERROR':
        console.error(formattedMessage)
        break
      case 'WARN':
        console.warn(formattedMessage)
        break
      case 'DEBUG':
        console.debug(formattedMessage)
        break
      default:
        console.log(formattedMessage)
    }

    // En producción, aquí enviarías logs a un servicio externo
    if (appConfig.nodeEnv === 'production') {
      this.sendToExternalService(logEntry)
    }
  }

  private formatForOutput(entry: LogEntry): string {
    const { timestamp, level, message, module, correlationId, metadata } = entry
    
    let formatted = `[${timestamp}] ${level.padEnd(5)} [${module}]`
    
    if (correlationId) {
      formatted += ` [${correlationId}]`
    }
    
    formatted += ` ${message}`
    
    if (metadata && Object.keys(metadata).length > 0) {
      formatted += ` | ${JSON.stringify(metadata)}`
    }
    
    return formatted
  }

  private async sendToExternalService(logEntry: LogEntry): Promise<void> {
    // Implementar envío a servicios como ELK, Splunk, CloudWatch, etc.
    // Por ahora solo implementamos la estructura
    try {
      // await externalLogService.send(logEntry)
    } catch (error) {
      console.error('Failed to send log to external service:', error)
    }
  }

  debug(message: string, metadata?: Record<string, any>): void {
    if (this.shouldLog(LogLevel.DEBUG)) {
      const logEntry = this.formatMessage('DEBUG', message, metadata)
      this.output(logEntry)
    }
  }

  info(message: string, metadata?: Record<string, any>): void {
    if (this.shouldLog(LogLevel.INFO)) {
      const logEntry = this.formatMessage('INFO', message, metadata)
      this.output(logEntry)
    }
  }

  warn(message: string, metadata?: Record<string, any>): void {
    if (this.shouldLog(LogLevel.WARN)) {
      const logEntry = this.formatMessage('WARN', message, metadata)
      this.output(logEntry)
    }
  }

  error(message: string, error?: Error, metadata?: Record<string, any>): void {
    if (this.shouldLog(LogLevel.ERROR)) {
      const logEntry = this.formatMessage('ERROR', message, {
        ...metadata,
        error: error?.message,
        stack: error?.stack
      })
      this.output(logEntry)
    }
  }

  // Métodos específicos para autenticación
  authAttempt(username: string, success: boolean, ipAddress: string, reason?: string): void {
    this.info('Authentication attempt', {
      username,
      success,
      ipAddress,
      reason: success ? 'Success' : reason
    })
  }

  authSuccess(userId: string, username: string, ipAddress: string): void {
    this.info('User authenticated successfully', {
      userId,
      username,
      ipAddress,
      event: 'LOGIN_SUCCESS'
    })
  }

  authFailure(username: string, ipAddress: string, reason: string): void {
    this.warn('Authentication failed', {
      username,
      ipAddress,
      reason,
      event: 'LOGIN_FAILURE'
    })
  }

  securityEvent(event: string, details: Record<string, any>): void {
    this.error('Security event detected', undefined, {
      event,
      ...details,
      severity: 'HIGH'
    })
  }

  apiRequest(method: string, path: string, userId?: string, duration?: number): void {
    this.info('API request', {
      method,
      path,
      userId,
      duration: duration ? `${duration}ms` : undefined,
      event: 'API_REQUEST'
    })
  }

  rbacCheck(userId: string, resource: string, action: string, granted: boolean, reason?: string): void {
    const level = granted ? 'info' : 'warn'
    const message = `RBAC permission check: ${granted ? 'GRANTED' : 'DENIED'}`
    
    const metadata = {
      userId,
      resource,
      action,
      granted,
      reason,
      event: 'RBAC_CHECK'
    }

    if (level === 'info') {
      this.info(message, metadata)
    } else {
      this.warn(message, metadata)
    }
  }

  databaseOperation(operation: string, table: string, duration?: number, error?: Error): void {
    if (error) {
      this.error(`Database operation failed: ${operation} on ${table}`, error, {
        operation,
        table,
        event: 'DB_ERROR'
      })
    } else {
      this.debug(`Database operation: ${operation} on ${table}`, {
        operation,
        table,
        duration: duration ? `${duration}ms` : undefined,
        event: 'DB_OPERATION'
      })
    }
  }

  performance(operation: string, duration: number, metadata?: Record<string, any>): void {
    const level = duration > 1000 ? 'warn' : 'info'
    const message = `Performance: ${operation} took ${duration}ms`
    
    const logMetadata = {
      operation,
      duration,
      ...metadata,
      event: 'PERFORMANCE'
    }

    if (level === 'warn') {
      this.warn(message, logMetadata)
    } else {
      this.info(message, logMetadata)
    }
  }

  setLevel(level: LogLevel): void {
    this.currentLevel = level
  }

  setUserId(userId: string): Logger {
    // Crear una instancia específica del logger con userId
    const logger = new Logger(this.moduleName)
    logger.currentLevel = this.currentLevel
    
    // Override formatMessage para incluir userId
    const originalFormatMessage = logger.formatMessage.bind(logger)
    logger.formatMessage = (level: string, message: string, metadata?: Record<string, any>) => {
      return originalFormatMessage(level, message, { ...metadata, userId })
    }
    
    return logger
  }
}

// Instancia global del logger
export const logger = Logger.getInstance()

// Loggers específicos por módulo
export const authLogger = Logger.create('auth')
export const rbacLogger = Logger.create('rbac')
export const dbLogger = Logger.create('database')
export const apiLogger = Logger.create('api')