import 'dotenv/config'
import { getDatabaseConfig, validateDatabaseConfig } from './database'
import { authConfig, validateAuthConfig } from './auth'

export interface AppConfig {
  port: number
  nodeEnv: 'development' | 'production' | 'test'
  apiVersion: string
  timezone: string
  logLevel: 'debug' | 'info' | 'warn' | 'error'
}

const getAppConfig = (): AppConfig => ({
  port: parseInt(process.env.PORT || '3000'),
  nodeEnv: (process.env.NODE_ENV as AppConfig['nodeEnv']) || 'development',
  apiVersion: process.env.API_VERSION || 'v1',
  timezone: process.env.TZ || 'UTC',
  logLevel: (process.env.LOG_LEVEL as AppConfig['logLevel']) || 'info'
})

// Configuración principal del módulo
class ConfigManager {
  private static instance: ConfigManager
  private _appConfig: AppConfig
  private _databaseConfig: ReturnType<typeof getDatabaseConfig>
  private _authConfig: typeof authConfig

  private constructor() {
    this._appConfig = getAppConfig()
    this._databaseConfig = getDatabaseConfig()
    this._authConfig = authConfig

    this.validateConfigs()
  }

  static getInstance(): ConfigManager {
    if (!ConfigManager.instance) {
      ConfigManager.instance = new ConfigManager()
    }
    return ConfigManager.instance
  }

  private validateConfigs(): void {
    try {
      validateDatabaseConfig(this._databaseConfig)
      validateAuthConfig(this._authConfig)
      
      if (this._appConfig.port < 1024 && process.getuid && process.getuid() !== 0) {
        console.warn(`Warning: Port ${this._appConfig.port} requires root privileges`)
      }

      console.log(`✅ Configuration validated successfully`)
      console.log(`📁 Database: ${this._databaseConfig.type}`)
      console.log(`🌐 Environment: ${this._appConfig.nodeEnv}`)
      console.log(`🚀 Port: ${this._appConfig.port}`)
    } catch (error) {
      console.error('❌ Configuration validation failed:', error)
      process.exit(1)
    }
  }

  get app(): AppConfig {
    return this._appConfig
  }

  get database(): ReturnType<typeof getDatabaseConfig> {
    return this._databaseConfig
  }

  get auth(): typeof authConfig {
    return this._authConfig
  }

  // Método para recargar configuración (útil en desarrollo)
  reload(): void {
    this._appConfig = getAppConfig()
    this._databaseConfig = getDatabaseConfig()
    this._authConfig = authConfig
    this.validateConfigs()
  }

  // Método para obtener configuración específica para diferentes entornos
  getEnvironmentSpecificConfig() {
    const baseConfig = {
      app: this._appConfig,
      database: this._databaseConfig,
      auth: this._authConfig
    }

    // Configuraciones específicas por entorno
    switch (this._appConfig.nodeEnv) {
      case 'development':
        return {
          ...baseConfig,
          debug: true,
          detailedErrors: true,
          corsOrigins: ['http://localhost:3000', 'http://localhost:3001', 'http://localhost:8080']
        }
      
      case 'production':
        return {
          ...baseConfig,
          debug: false,
          detailedErrors: false,
          corsOrigins: this._authConfig.cors.origins
        }
      
      case 'test':
        return {
          ...baseConfig,
          debug: true,
          detailedErrors: true,
          corsOrigins: ['http://localhost:3000']
        }
      
      default:
        return baseConfig
    }
  }
}

// Exportar instancia singleton
export const config = ConfigManager.getInstance()

// Exportar configuraciones individuales para conveniencia
export const appConfig = config.app
export const databaseConfig = config.database
export { authConfig }

// Exportar tipos
export type { DatabaseConfig, DatabaseType } from '@/types/database.types'
export type { AuthConfig } from './auth'