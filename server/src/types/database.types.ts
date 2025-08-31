export type DatabaseType = 'postgresql' | 'mysql' | 'mongodb'

export interface DatabaseConfig {
  type: DatabaseType
  config: PostgreSQLConfig | MySQLConfig | MongoDBConfig
}

export interface PostgreSQLConfig {
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

export interface MySQLConfig {
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

export interface MongoDBConfig {
  uri: string
  options?: {
    maxPoolSize?: number
    serverSelectionTimeoutMS?: number
    socketTimeoutMS?: number
    retryWrites?: boolean
    w?: string | number
  }
}

// Interfaces para el pool de conexiones
export interface ConnectionPool {
  getConnection(): Promise<any>
  releaseConnection(connection: any): Promise<void>
  closeAll(): Promise<void>
  isHealthy(): Promise<boolean>
}

// Resultado de operaciones de base de datos
export interface DatabaseOperationResult<T = any> {
  success: boolean
  data?: T
  error?: string
  affected?: number
}

// Query builder base
export interface QueryBuilder {
  select(fields?: string[]): QueryBuilder
  where(condition: Record<string, any>): QueryBuilder
  join(table: string, condition: string): QueryBuilder
  orderBy(field: string, direction?: 'ASC' | 'DESC'): QueryBuilder
  limit(count: number): QueryBuilder
  offset(count: number): QueryBuilder
  build(): { query: string; params: any[] }
}

// Transacciones
export interface Transaction {
  id: string
  commit(): Promise<void>
  rollback(): Promise<void>
  query(sql: string, params?: any[]): Promise<any>
}

// Metadatos de tabla
export interface TableMetadata {
  name: string
  columns: ColumnMetadata[]
  indexes: IndexMetadata[]
  foreignKeys: ForeignKeyMetadata[]
}

export interface ColumnMetadata {
  name: string
  type: string
  nullable: boolean
  primaryKey: boolean
  autoIncrement: boolean
  defaultValue?: any
}

export interface IndexMetadata {
  name: string
  columns: string[]
  unique: boolean
}

export interface ForeignKeyMetadata {
  column: string
  referencedTable: string
  referencedColumn: string
  onDelete: 'CASCADE' | 'SET NULL' | 'RESTRICT'
  onUpdate: 'CASCADE' | 'SET NULL' | 'RESTRICT'
}