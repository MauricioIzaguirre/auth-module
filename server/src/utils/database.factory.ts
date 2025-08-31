import { DatabaseType, DatabaseConfig, ConnectionPool } from '../types/database.types'
import { IUserModel } from '../models/interfaces/User.interface'
import { IRoleModel } from '../models/interfaces/Role.interface'
import { IPermissionModel } from '../models/interfaces/Permission.interface'

// PostgreSQL
import { UserModelPostgreSQL } from '../models/postgresql/User.model'
import { RoleModelPostgreSQL } from '../models/postgresql/Role.model'
import { PermissionModelPostgreSQL } from '../models/postgresql/Permission.model'

// MySQL
import { UserModelMySQL } from '../models/mysql/User.model'
import { RoleModelMySQL } from '../models/mysql/Role.model'
import { PermissionModelMySQL } from '../models/mysql/Permission.model'

// MongoDB
import { UserModelMongoDB } from '../models/mongodb/User.model'
import { RoleModelMongoDB } from '../models/mongodb/Role.model'
import { PermissionModelMongoDB } from '../models/mongodb/Permission.model'

// Pool de conexiones
import pg from 'pg'
import mysql from 'mysql2/promise'
import { MongoClient } from 'mongodb'

export class DatabaseFactory {
  private static instance: DatabaseFactory
  private pools: Map<DatabaseType, ConnectionPool> = new Map()
  private models: Map<DatabaseType, {
    User: IUserModel
    Role: IRoleModel
    Permission: IPermissionModel
  }> = new Map()

  private constructor() {}

  static getInstance(): DatabaseFactory {
    if (!DatabaseFactory.instance) {
      DatabaseFactory.instance = new DatabaseFactory()
    }
    return DatabaseFactory.instance
  }

  async createConnection(config: DatabaseConfig): Promise<ConnectionPool> {
    const existingPool = this.pools.get(config.type)
    if (existingPool) {
      return existingPool
    }

    let pool: ConnectionPool

    switch (config.type) {
      case 'postgresql':
        pool = await this.createPostgreSQLPool(config.config as any)
        break
      case 'mysql':
        pool = await this.createMySQLPool(config.config as any)
        break
      case 'mongodb':
        pool = await this.createMongoDBPool(config.config as any)
        break
      default:
        throw new Error(`Unsupported database type: ${config.type}`)
    }

    this.pools.set(config.type, pool)
    return pool
  }

  private async createPostgreSQLPool(config: any): Promise<ConnectionPool> {
    const pool = new pg.Pool({
      host: config.host,
      port: config.port,
      user: config.username,
      password: config.password,
      database: config.database,
      ssl: config.ssl,
      min: config.poolMin,
      max: config.poolMax,
      connectionTimeoutMillis: config.connectionTimeoutMillis,
      idleTimeoutMillis: config.idleTimeoutMillis
    })

    // Test connection
    const client = await pool.connect()
    client.release()

    return {
      async getConnection() {
        return await pool.connect()
      },
      async releaseConnection(connection: pg.PoolClient) {
        connection.release()
      },
      async closeAll() {
        await pool.end()
      },
      async isHealthy() {
        try {
          const client = await pool.connect()
          await client.query('SELECT 1')
          client.release()
          return true
        } catch {
          return false
        }
      }
    }
  }

  private async createMySQLPool(config: any): Promise<ConnectionPool> {
    const pool = mysql.createPool({
      host: config.host,
      port: config.port,
      user: config.user,
      password: config.password,
      database: config.database,
      ssl: config.ssl,
      connectionLimit: config.connectionLimit,
      acquireTimeout: config.acquireTimeout,
      timeout: config.timeout
    })

    // Test connection
    const connection = await pool.getConnection()
    connection.release()

    return {
      async getConnection() {
        return await pool.getConnection()
      },
      async releaseConnection(connection: any) {
        connection.release()
      },
      async closeAll() {
        await pool.end()
      },
      async isHealthy() {
        try {
          const connection = await pool.getConnection()
          await connection.query('SELECT 1')
          connection.release()
          return true
        } catch {
          return false
        }
      }
    }
  }

  private async createMongoDBPool(config: any): Promise<ConnectionPool> {
    const client = new MongoClient(config.uri, config.options)
    await client.connect()

    return {
      async getConnection() {
        return client.db()
      },
      async releaseConnection() {
        // MongoDB maneja conexiones automáticamente
      },
      async closeAll() {
        await client.close()
      },
      async isHealthy() {
        try {
          await client.db().admin().ping()
          return true
        } catch {
          return false
        }
      }
    }
  }

  getModels(databaseType: DatabaseType): {
    User: IUserModel
    Role: IRoleModel
    Permission: IPermissionModel
  } {
    const existingModels = this.models.get(databaseType)
    if (existingModels) {
      return existingModels
    }

    let models: {
      User: IUserModel
      Role: IRoleModel
      Permission: IPermissionModel
    }

    switch (databaseType) {
      case 'postgresql':
        models = {
          User: new UserModelPostgreSQL(),
          Role: new RoleModelPostgreSQL(),
          Permission: new PermissionModelPostgreSQL()
        }
        break
      case 'mysql':
        models = {
          User: new UserModelMySQL(),
          Role: new RoleModelMySQL(),
          Permission: new PermissionModelMySQL()
        }
        break
      case 'mongodb':
        models = {
          User: new UserModelMongoDB(),
          Role: new RoleModelMongoDB(),
          Permission: new PermissionModelMongoDB()
        }
        break
      default:
        throw new Error(`Unsupported database type: ${databaseType}`)
    }

    this.models.set(databaseType, models)
    return models
  }

  async closeAllConnections(): Promise<void> {
    const closePromises = Array.from(this.pools.values()).map(pool => pool.closeAll())
    await Promise.all(closePromises)
    this.pools.clear()
  }

  async healthCheck(): Promise<Record<DatabaseType, boolean>> {
    const healthStatus: Partial<Record<DatabaseType, boolean>> = {}
    
    for (const [type, pool] of this.pools.entries()) {
      healthStatus[type] = await pool.isHealthy()
    }
    
    return healthStatus as Record<DatabaseType, boolean>
  }
}

// Factory function para facilitar el uso
export const createDatabaseConnection = async (config: DatabaseConfig): Promise<ConnectionPool> => {
  const factory = DatabaseFactory.getInstance()
  return await factory.createConnection(config)
}

export const getDatabaseModels = (databaseType: DatabaseType) => {
  const factory = DatabaseFactory.getInstance()
  return factory.getModels(databaseType)
}

export const closeDatabaseConnections = async (): Promise<void> => {
  const factory = DatabaseFactory.getInstance()
  await factory.closeAllConnections()
}