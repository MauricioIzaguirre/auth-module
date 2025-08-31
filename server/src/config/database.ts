import { DatabaseConfig, DatabaseType } from "@/types/database.types"

interface PostgreSQLConfig {
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
}

interface MySQLConfig {
  host: string
  port: number
  user: string
  password: string
  database: string
  ssl?: boolean
  connectionLimit?: number
  acquireTimeout?: number
  timeout?: number
}

interface MongoDBConfig {
  uri: string
  options?: {
    maxPoolSize?: number
    serverSelectionTimeoutMS?: number
    socketTimeoutMS?: number
    retryWrites?: boolean
    w?: string | number
  }
}

const getPostgreSQLConfig = (): PostgreSQLConfig => ({
  host: process.env.POSTGRES_HOST || 'localhost',
  port: parseInt(process.env.POSTGRES_PORT || '5432'),
  username: process.env.POSTGRES_USER || 'postgres',
  password: process.env.POSTGRES_PASSWORD || '',
  database: process.env.POSTGRES_DB || 'auth_db',
  ssl: process.env.POSTGRES_SSL === 'true',
  poolMin: parseInt(process.env.POSTGRES_POOL_MIN || '2'),
  poolMax: parseInt(process.env.POSTGRES_POOL_MAX || '10'),
  connectionTimeoutMillis: parseInt(process.env.POSTGRES_CONNECTION_TIMEOUT || '5000'),
  idleTimeoutMillis: parseInt(process.env.POSTGRES_IDLE_TIMEOUT || '30000')
})

const getMySQLConfig = (): MySQLConfig => ({
  host: process.env.MYSQL_HOST || 'localhost',
  port: parseInt(process.env.MYSQL_PORT || '3306'),
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DB || 'auth_db',
  ssl: process.env.MYSQL_SSL === 'true',
  connectionLimit: parseInt(process.env.MYSQL_CONNECTION_LIMIT || '10'),
  acquireTimeout: parseInt(process.env.MYSQL_ACQUIRE_TIMEOUT || '60000'),
  timeout: parseInt(process.env.MYSQL_TIMEOUT || '60000')
})

const getMongoDBConfig = (): MongoDBConfig => {
  const uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/auth_db'
  
  return {
    uri,
    options: {
      maxPoolSize: parseInt(process.env.MONGODB_MAX_POOL_SIZE || '10'),
      serverSelectionTimeoutMS: parseInt(process.env.MONGODB_SERVER_SELECTION_TIMEOUT || '5000'),
      socketTimeoutMS: parseInt(process.env.MONGODB_SOCKET_TIMEOUT || '45000'),
      retryWrites: process.env.MONGODB_RETRY_WRITES !== 'false',
      w: process.env.MONGODB_WRITE_CONCERN || 'majority'
    }
  }
}

export const getDatabaseConfig = (): DatabaseConfig => {
  const dbType: DatabaseType = (process.env.DATABASE_TYPE as DatabaseType) || 'postgresql'
  
  switch (dbType) {
    case 'postgresql':
      return {
        type: 'postgresql',
        config: getPostgreSQLConfig()
      }
    case 'mysql':
      return {
        type: 'mysql',
        config: getMySQLConfig()
      }
    case 'mongodb':
      return {
        type: 'mongodb',
        config: getMongoDBConfig()
      }
    default:
      throw new Error(`Unsupported database type: ${dbType}`)
  }
}

export const validateDatabaseConfig = (config: DatabaseConfig): boolean => {
  switch (config.type) {
    case 'postgresql': {
      const pgConfig = config.config as PostgreSQLConfig
      return !!(pgConfig.host && pgConfig.port && pgConfig.username && pgConfig.database)
    }
    case 'mysql': {
      const mysqlConfig = config.config as MySQLConfig
      return !!(mysqlConfig.host && mysqlConfig.port && mysqlConfig.user && mysqlConfig.database)
    }
    case 'mongodb': {
      const mongoConfig = config.config as MongoDBConfig
      return !!(mongoConfig.uri)
    }
    default:
      return false
  }
}