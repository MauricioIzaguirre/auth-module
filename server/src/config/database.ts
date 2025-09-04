// server/src/config/database.ts
import { Pool, PoolConfig } from 'pg'
import { logger } from '../utils/logger'

export interface DatabaseConfig {
  host: string
  port: number
  username: string
  password: string
  database: string
  ssl?: boolean
  poolMin?: number
  poolMax?: number
  connectionTimeoutMillis?: number
  idleTimeoutMillis?: number
  maxUses?: number
  allowExitOnIdle?: boolean
}

const getDatabaseConfig = (): DatabaseConfig => ({
  host: process.env.POSTGRES_HOST || 'localhost',
  port: parseInt(process.env.POSTGRES_PORT || '5432'),
  username: process.env.POSTGRES_USER || 'postgres',
  password: process.env.POSTGRES_PASSWORD || '',
  database: process.env.POSTGRES_DB || 'auth_db',
  ssl: process.env.POSTGRES_SSL === 'true',
  poolMin: parseInt(process.env.POSTGRES_POOL_MIN || '2'),
  poolMax: parseInt(process.env.POSTGRES_POOL_MAX || '10'),
  connectionTimeoutMillis: parseInt(process.env.POSTGRES_CONNECTION_TIMEOUT || '5000'),
  idleTimeoutMillis: parseInt(process.env.POSTGRES_IDLE_TIMEOUT || '30000'),
  maxUses: parseInt(process.env.POSTGRES_MAX_USES || '7500'),
  allowExitOnIdle: process.env.POSTGRES_ALLOW_EXIT_ON_IDLE !== 'false'
})

class DatabaseConnection {
  private static instance: DatabaseConnection
  private pool: Pool | null = null

  private constructor() {}

  static getInstance(): DatabaseConnection {
    if (!DatabaseConnection.instance) {
      DatabaseConnection.instance = new DatabaseConnection()
    }
    return DatabaseConnection.instance
  }

  async connect(): Promise<Pool> {
    if (this.pool) {
      return this.pool
    }

    const config = getDatabaseConfig()

    const poolConfig: PoolConfig = {
      host: config.host,
      port: config.port,
      user: config.username,
      password: config.password,
      database: config.database,
      ssl: config.ssl ? { rejectUnauthorized: false } : false,
      min: config.poolMin,
      max: config.poolMax,
      connectionTimeoutMillis: config.connectionTimeoutMillis,
      idleTimeoutMillis: config.idleTimeoutMillis,
      maxUses: config.maxUses,
      allowExitOnIdle: config.allowExitOnIdle
    }

    this.pool = new Pool(poolConfig)

    // Event listeners
    this.pool.on('connect', () => {
      logger.info('Database connection established')
    })

    this.pool.on('error', (err) => {
      logger.error('Database connection error', err)
    })

    this.pool.on('remove', () => {
      logger.info('Database connection removed from pool')
    })

    // Test connection
    try {
      const client = await this.pool.connect()
      await client.query('SELECT NOW()')
      client.release()
      logger.info('Database connection test successful')
    } catch (error) {
      logger.error('Database connection test failed', error as Error)
      throw new Error('Failed to connect to database')
    }

    return this.pool
  }

  async getPool(): Promise<Pool> {
    if (!this.pool) {
      return await this.connect()
    }
    return this.pool
  }

  async query(text: string, params?: any[]): Promise<any> {
    const pool = await this.getPool()
    const start = Date.now()
    
    try {
      const result = await pool.query(text, params)
      const duration = Date.now() - start
      
      logger.debug('Database query executed', {
        query: text,
        duration,
        rows: result.rows.length
      })
      
      return result
    } catch (error) {
      const duration = Date.now() - start
      logger.error('Database query failed', error as Error, {
        query: text,
        duration,
        params: params?.length
      })
      throw error
    }
  }

  async transaction<T>(callback: (client: any) => Promise<T>): Promise<T> {
    const pool = await this.getPool()
    const client = await pool.connect()
    
    try {
      await client.query('BEGIN')
      const result = await callback(client)
      await client.query('COMMIT')
      return result
    } catch (error) {
      await client.query('ROLLBACK')
      throw error
    } finally {
      client.release()
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      const result = await this.query('SELECT 1 as health')
      return result.rows.length > 0
    } catch {
      return false
    }
  }

  async close(): Promise<void> {
    if (this.pool) {
      await this.pool.end()
      this.pool = null
      logger.info('Database connection pool closed')
    }
  }
}

export const db = DatabaseConnection.getInstance()

export const validateDatabaseConfig = (config: DatabaseConfig): boolean => {
  if (!config.host || !config.port || !config.username || !config.database) {
    throw new Error('Missing required database configuration')
  }

  if (config.port < 1 || config.port > 65535) {
    throw new Error('Invalid database port')
  }

  if (config.poolMin && config.poolMax && config.poolMin > config.poolMax) {
    throw new Error('Pool min cannot be greater than pool max')
  }

  return true
}

export { getDatabaseConfig }