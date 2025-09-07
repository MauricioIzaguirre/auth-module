import { Pool, PoolClient, PoolConfig } from 'pg';
import { logger } from './logger';
import { env } from './environment';
import type { DatabaseConfig } from '../types/core';

/**
 * PostgreSQL database configuration with connection pooling
 * Implements best practices for production environments
 */
class DatabaseManager {
  private pool: Pool | null = null;
  private isConnected = false;

  /**
   * Get database configuration from environment variables
   */
  private getConfig(): DatabaseConfig {
    return {
      host: env.DB_HOST,
      port: env.DB_PORT,
      database: env.DB_NAME,
      username: env.DB_USER,
      password: env.DB_PASSWORD,
      maxConnections: env.DB_MAX_CONNECTIONS,
      minConnections: env.DB_MIN_CONNECTIONS,
      idleTimeout: env.DB_IDLE_TIMEOUT,
      connectionTimeout: env.DB_CONNECTION_TIMEOUT
    };
  }

  /**
   * Create PostgreSQL pool configuration
   */
  private createPoolConfig(): PoolConfig {
    const config = this.getConfig();
    
    return {
      host: config.host,
      port: config.port,
      database: config.database,
      user: config.username,
      password: config.password,
      max: config.maxConnections,
      min: config.minConnections,
      idleTimeoutMillis: config.idleTimeout,
      connectionTimeoutMillis: config.connectionTimeout,
      keepAlive: true,
      keepAliveInitialDelayMillis: 10000,
      // SSL configuration for production
      ssl: env.NODE_ENV === 'production' ? {
        rejectUnauthorized: false
      } : false,
      // Query timeout
      query_timeout: 30000,
      // Statement timeout
      statement_timeout: 30000,
      // Connection validation
      allowExitOnIdle: false
    };
  }

  /**
   * Initialize database connection pool
   */
  async initialize(): Promise<void> {
    try {
      if (this.pool) {
        logger.warn('Database pool already initialized');
        return;
      }

      const poolConfig = this.createPoolConfig();
      this.pool = new Pool(poolConfig);

      // Handle pool events
      this.setupPoolEventHandlers();

      // Test connection
      await this.testConnection();

      this.isConnected = true;
      logger.info('Database connection pool initialized successfully', {
        host: poolConfig.host,
        database: poolConfig.database,
        maxConnections: poolConfig.max,
        minConnections: poolConfig.min
      });
    } catch (error) {
      logger.error('Failed to initialize database connection pool', { error });
      throw error;
    }
  }

  /**
   * Setup pool event handlers for monitoring
   */
  private setupPoolEventHandlers(): void {
    if (!this.pool) return;

    // Connect event - client connects to database
    this.pool.on('connect', (_client: PoolClient) => {
      logger.debug('New client connected to database pool');
    });

    // Acquire event - client is checked out from pool
    this.pool.on('acquire', (_client: PoolClient) => {
      logger.debug('Client acquired from pool');
    });

    // Release event - client is returned to pool (error first parameter)
    this.pool.on('release', (_error: Error | undefined, _client: PoolClient) => {
      logger.debug('Client released back to pool');
    });

    // Remove event - client is removed from pool
    this.pool.on('remove', (_client: PoolClient) => {
      logger.debug('Client removed from pool');
    });

    // Error event - error occurred on idle client
    this.pool.on('error', (error: Error, client: PoolClient) => {
      logger.error('Database pool error', { 
        error: error.message,
        stack: error.stack,
        // Cast client to any to access pg specific properties
        clientProcessId: (client as any).processID
      });
    });
  }

  /**
   * Test database connection
   */
  private async testConnection(): Promise<void> {
    if (!this.pool) {
      throw new Error('Database pool not initialized');
    }

    try {
      const client = await this.pool.connect();
      const result = await client.query('SELECT NOW() as current_time, version()');
      client.release();
      
      logger.info('Database connection test successful', {
        currentTime: result.rows[0]?.current_time,
        version: result.rows[0]?.version?.split(' ')[0] + ' ' + result.rows[0]?.version?.split(' ')[1]
      });
    } catch (error) {
      logger.error('Database connection test failed', { error });
      throw error;
    }
  }

  /**
   * Get a client from the pool
   */
  async getClient(): Promise<PoolClient> {
    if (!this.pool || !this.isConnected) {
      throw new Error('Database pool not initialized or not connected');
    }

    try {
      return await this.pool.connect();
    } catch (error) {
      logger.error('Failed to get client from pool', { error });
      throw error;
    }
  }

  /**
   * Execute a query with automatic client management
   */
  async query<T = any>(text: string, params?: any[]): Promise<T[]> {
    const client = await this.getClient();
    
    try {
      const start = Date.now();
      const result = await client.query(text, params);
      const duration = Date.now() - start;
      
      logger.debug('Query executed', {
        query: text.substring(0, 100) + (text.length > 100 ? '...' : ''),
        duration: `${duration}ms`,
        rowCount: result.rowCount
      });
      
      return result.rows;
    } catch (error) {
      logger.error('Query execution failed', {
        query: text,
        params,
        error
      });
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Execute multiple queries in a transaction
   */
  async transaction<T>(
    callback: (client: PoolClient) => Promise<T>
  ): Promise<T> {
    const client = await this.getClient();
    
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      
      logger.debug('Transaction committed successfully');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      logger.error('Transaction rolled back due to error', { error });
      throw error;
    } finally {
      client.release();
    }
  }

  /**
   * Get pool statistics
   */
  getPoolStats(): {
    totalCount: number;
    idleCount: number;
    waitingCount: number;
  } {
    if (!this.pool) {
      throw new Error('Database pool not initialized');
    }

    return {
      totalCount: this.pool.totalCount,
      idleCount: this.pool.idleCount,
      waitingCount: this.pool.waitingCount
    };
  }

  /**
   * Check if database is connected
   */
  isHealthy(): boolean {
    return this.isConnected && this.pool !== null;
  }

  /**
   * Close database connection pool
   */
  async close(): Promise<void> {
    if (!this.pool) {
      logger.warn('Database pool already closed or not initialized');
      return;
    }

    try {
      await this.pool.end();
      this.pool = null;
      this.isConnected = false;
      logger.info('Database connection pool closed successfully');
    } catch (error) {
      logger.error('Error closing database pool', { error });
      throw error;
    }
  }
}

// Create singleton instance
export const database = new DatabaseManager();

/**
 * Database helper functions for common operations
 */
export class DatabaseHelpers {
  /**
   * Build WHERE clause from filters
   */
  static buildWhereClause(
    filters: Record<string, unknown>,
    startIndex = 1
  ): { clause: string; values: unknown[]; nextIndex: number } {
    const conditions: string[] = [];
    const values: unknown[] = [];
    let paramIndex = startIndex;

    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== null) {
        if (Array.isArray(value)) {
          const placeholders = value.map(() => `$${paramIndex++}`).join(', ');
          conditions.push(`${key} IN (${placeholders})`);
          values.push(...value);
        } else if (typeof value === 'string' && value.includes('%')) {
          conditions.push(`${key} ILIKE $${paramIndex++}`);
          values.push(value);
        } else {
          conditions.push(`${key} = $${paramIndex++}`);
          values.push(value);
        }
      }
    }

    const clause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    return { clause, values, nextIndex: paramIndex };
  }

  /**
   * Build pagination clause
   */
  static buildPaginationClause(
    page: number,
    limit: number,
    paramIndex: number
  ): { clause: string; values: number[] } {
    const offset = (page - 1) * limit;
    return {
      clause: `LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
      values: [limit, offset]
    };
  }

  /**
   * Build ORDER BY clause
   */
  static buildOrderClause(
    sortBy?: string,
    sortOrder: 'ASC' | 'DESC' = 'ASC'
  ): string {
    if (!sortBy) return 'ORDER BY created_at DESC';
    
    const allowedColumns = [
      'id', 'created_at', 'updated_at', 'username', 'email', 'name'
    ];
    
    if (!allowedColumns.includes(sortBy)) {
      throw new Error(`Invalid sort column: ${sortBy}`);
    }
    
    return `ORDER BY ${sortBy} ${sortOrder}`;
  }
}

/**
 * Database migration utilities
 */
export class MigrationManager {
  /**
   * Check if migrations table exists
   */
  static async ensureMigrationsTable(): Promise<void> {
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS migrations (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        executed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `;
    
    await database.query(createTableQuery);
    logger.info('Migrations table ensured');
  }

  /**
   * Record a migration as executed
   */
  static async recordMigration(name: string): Promise<void> {
    const query = 'INSERT INTO migrations (name) VALUES ($1)';
    await database.query(query, [name]);
    logger.info(`Migration recorded: ${name}`);
  }

  /**
   * Check if a migration has been executed
   */
  static async isMigrationExecuted(name: string): Promise<boolean> {
    const query = 'SELECT COUNT(*) as count FROM migrations WHERE name = $1';
    const result = await database.query<{ count: string }>(query, [name]);
    return parseInt(result[0]?.count ?? '0') > 0;
  }
}