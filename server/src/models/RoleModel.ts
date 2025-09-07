import { PoolClient } from 'pg';
import { database, DatabaseHelpers } from '@/config/database';
import { logger, logDatabaseOperation } from '@/config/logger';
import type { 
  Role, 
  Permission, 
  UserRole
} from '@/types/auth';
import type { 
  QueryParams,
  PaginatedResult 
} from '@/types/core';

/**
 * Role repository for RBAC system
 * Handles roles, permissions, and user-role assignments
 */
export class RoleRepository {
  /**
   * Create a new role
   */
  static async createRole(roleData: {
    name: string;
    description?: string;
    isSystem?: boolean;
  }): Promise<Role> {
    const startTime = Date.now();
    
    try {
      const query = `
        INSERT INTO roles (
          id, name, description, is_system, created_at, updated_at
        ) VALUES (
          gen_random_uuid(), $1, $2, $3, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        RETURNING *
      `;

      const values = [
        roleData.name,
        roleData.description ?? null,
        roleData.isSystem ?? false
      ];

      const result = await database.query<Role>(query, values);
      const role = result[0];
      
      if (!role) {
        throw new Error('Failed to create role');
      }

      logDatabaseOperation('INSERT', 'roles', Date.now() - startTime, {
        roleId: role.id,
        roleName: role.name
      });

      return role;
    } catch (error) {
      logger.error('Error creating role', { error, roleData });
      throw error;
    }
  }

  /**
   * Find role by ID with permissions
   */
  static async findRoleById(id: string): Promise<Role | null> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT 
          r.id, r.name, r.description, r.is_system, r.created_at, r.updated_at,
          COALESCE(
            JSON_AGG(
              JSON_BUILD_OBJECT(
                'id', p.id,
                'name', p.name,
                'resource', p.resource,
                'action', p.action,
                'description', p.description,
                'created_at', p.created_at,
                'updated_at', p.updated_at
              )
            ) FILTER (WHERE p.id IS NOT NULL),
            '[]'
          ) as permissions
        FROM roles r
        LEFT JOIN role_permissions rp ON r.id = rp.role_id
        LEFT JOIN permissions p ON rp.permission_id = p.id AND p.deleted_at IS NULL
        WHERE r.id = $1 AND r.deleted_at IS NULL
        GROUP BY r.id, r.name, r.description, r.is_system, r.created_at, r.updated_at
      `;

      const result = await database.query<Role>(query, [id]);
      const role = result[0] ?? null;

      logDatabaseOperation('SELECT', 'roles', Date.now() - startTime, {
        roleId: id,
        found: !!role
      });

      return role;
    } catch (error) {
      logger.error('Error finding role by ID', { error, roleId: id });
      throw error;
    }
  }

  /**
   * Find role by name with permissions
   */
  static async findRoleByName(name: string): Promise<Role | null> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT 
          r.id, r.name, r.description, r.is_system, r.created_at, r.updated_at,
          COALESCE(
            JSON_AGG(
              JSON_BUILD_OBJECT(
                'id', p.id,
                'name', p.name,
                'resource', p.resource,
                'action', p.action,
                'description', p.description,
                'created_at', p.created_at,
                'updated_at', p.updated_at
              )
            ) FILTER (WHERE p.id IS NOT NULL),
            '[]'
          ) as permissions
        FROM roles r
        LEFT JOIN role_permissions rp ON r.id = rp.role_id
        LEFT JOIN permissions p ON rp.permission_id = p.id AND p.deleted_at IS NULL
        WHERE r.name = $1 AND r.deleted_at IS NULL
        GROUP BY r.id, r.name, r.description, r.is_system, r.created_at, r.updated_at
      `;

      const result = await database.query<Role>(query, [name]);
      const role = result[0] ?? null;

      logDatabaseOperation('SELECT', 'roles', Date.now() - startTime, {
        roleName: name,
        found: !!role
      });

      return role;
    } catch (error) {
      logger.error('Error finding role by name', { error, roleName: name });
      throw error;
    }
  }

  /**
   * Get all roles with pagination
   */
  static async findManyRoles(params: QueryParams = {}): Promise<PaginatedResult<Role>> {
    const startTime = Date.now();
    
    try {
      const {
        page = 1,
        limit = 10,
        sortBy = 'created_at',
        sortOrder = 'DESC',
        search
      } = params;

      // Build base query
      let baseQuery = `
        FROM roles r
        WHERE r.deleted_at IS NULL
      `;

      const queryParams: unknown[] = [];
      let paramIndex = 1;

      // Add search filter
      if (search) {
        baseQuery += ` AND (r.name ILIKE $${paramIndex} OR r.description ILIKE $${paramIndex})`;
        queryParams.push(`%${search}%`);
        paramIndex++;
      }

      // Count total records
      const countQuery = `SELECT COUNT(*) as total ${baseQuery}`;
      const countResult = await database.query<{ total: string }>(countQuery, queryParams);
      const total = parseInt(countResult[0]?.total ?? '0');

      // Build main query with pagination
      const orderClause = DatabaseHelpers.buildOrderClause(sortBy, sortOrder);
      const { clause: paginationClause, values: paginationValues } = 
        DatabaseHelpers.buildPaginationClause(page, limit, paramIndex);

      const selectQuery = `
        SELECT 
          r.id, r.name, r.description, r.is_system, r.created_at, r.updated_at,
          COALESCE(
            JSON_AGG(
              JSON_BUILD_OBJECT(
                'id', p.id,
                'name', p.name,
                'resource', p.resource,
                'action', p.action,
                'description', p.description,
                'created_at', p.created_at,
                'updated_at', p.updated_at
              )
            ) FILTER (WHERE p.id IS NOT NULL),
            '[]'
          ) as permissions
        ${baseQuery}
        LEFT JOIN role_permissions rp ON r.id = rp.role_id
        LEFT JOIN permissions p ON rp.permission_id = p.id AND p.deleted_at IS NULL
        GROUP BY r.id, r.name, r.description, r.is_system, r.created_at, r.updated_at
        ${orderClause}
        ${paginationClause}
      `;

      const allParams = [...queryParams, ...paginationValues];
      const result = await database.query<Role>(selectQuery, allParams);

      const totalPages = Math.ceil(total / limit);

      logDatabaseOperation('SELECT', 'roles', Date.now() - startTime, {
        operation: 'findManyRoles',
        totalRecords: total,
        page,
        limit
      });

      return {
        items: result,
        meta: {
          page,
          limit,
          total,
          totalPages
        }
      };
    } catch (error) {
      logger.error('Error finding roles', { error, params });
      throw error;
    }
  }

  /**
   * Get user roles with permissions
   */
  static async getUserRoles(userId: string): Promise<Role[]> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT 
          r.id, r.name, r.description, r.is_system, r.created_at, r.updated_at,
          COALESCE(
            JSON_AGG(
              JSON_BUILD_OBJECT(
                'id', p.id,
                'name', p.name,
                'resource', p.resource,
                'action', p.action,
                'description', p.description,
                'created_at', p.created_at,
                'updated_at', p.updated_at
              )
            ) FILTER (WHERE p.id IS NOT NULL),
            '[]'
          ) as permissions
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        LEFT JOIN role_permissions rp ON r.id = rp.role_id
        LEFT JOIN permissions p ON rp.permission_id = p.id AND p.deleted_at IS NULL
        WHERE ur.user_id = $1 
          AND r.deleted_at IS NULL
          AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
        GROUP BY r.id, r.name, r.description, r.is_system, r.created_at, r.updated_at
      `;

      const result = await database.query<Role>(query, [userId]);

      logDatabaseOperation('SELECT', 'user_roles', Date.now() - startTime, {
        userId,
        rolesCount: result.length
      });

      return result;
    } catch (error) {
      logger.error('Error getting user roles', { error, userId });
      throw error;
    }
  }

  /**
   * Get user permissions (flattened from all roles)
   */
  static async getUserPermissions(userId: string): Promise<Permission[]> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT DISTINCT
          p.id, p.name, p.resource, p.action, p.description, p.created_at, p.updated_at
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        JOIN role_permissions rp ON r.id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.id
        WHERE ur.user_id = $1 
          AND r.deleted_at IS NULL
          AND p.deleted_at IS NULL
          AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
        ORDER BY p.resource, p.action
      `;

      const result = await database.query<Permission>(query, [userId]);

      logDatabaseOperation('SELECT', 'permissions', Date.now() - startTime, {
        userId,
        permissionsCount: result.length
      });

      return result;
    } catch (error) {
      logger.error('Error getting user permissions', { error, userId });
      throw error;
    }
  }

  /**
   * Assign role to user
   */
  static async assignRoleToUser(
    userId: string,
    roleId: string,
    assignedBy: string,
    expiresAt?: Date
  ): Promise<UserRole> {
    const startTime = Date.now();
    
    try {
      // Check if assignment already exists
      const existsQuery = `
        SELECT id FROM user_roles 
        WHERE user_id = $1 AND role_id = $2
      `;
      const existing = await database.query(existsQuery, [userId, roleId]);
      
      if (existing.length > 0) {
        throw new Error('Role already assigned to user');
      }

      const query = `
        INSERT INTO user_roles (
          id, user_id, role_id, assigned_by, assigned_at, expires_at, created_at, updated_at
        ) VALUES (
          gen_random_uuid(), $1, $2, $3, CURRENT_TIMESTAMP, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        RETURNING *
      `;

      const values = [userId, roleId, assignedBy, expiresAt ?? null];
      const result = await database.query<UserRole>(query, values);
      const userRole = result[0];
      
      if (!userRole) {
        throw new Error('Failed to assign role to user');
      }

      logDatabaseOperation('INSERT', 'user_roles', Date.now() - startTime, {
        userId,
        roleId,
        assignedBy,
        expiresAt
      });

      return userRole;
    } catch (error) {
      logger.error('Error assigning role to user', { error, userId, roleId });
      throw error;
    }
  }

  /**
   * Remove role from user
   */
  static async removeRoleFromUser(userId: string, roleId: string): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      const query = `
        DELETE FROM user_roles 
        WHERE user_id = $1 AND role_id = $2
      `;

      const result = await database.query(query, [userId, roleId]);
      const success = (result as any).rowCount > 0;

      logDatabaseOperation('DELETE', 'user_roles', Date.now() - startTime, {
        userId,
        roleId,
        success
      });

      return success;
    } catch (error) {
      logger.error('Error removing role from user', { error, userId, roleId });
      throw error;
    }
  }

  /**
   * Check if user has permission
   */
  static async userHasPermission(
    userId: string, 
    resource: string, 
    action: string
  ): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT COUNT(*) as count
        FROM user_roles ur
        JOIN roles r ON ur.role_id = r.id
        JOIN role_permissions rp ON r.id = rp.role_id
        JOIN permissions p ON rp.permission_id = p.id
        WHERE ur.user_id = $1 
          AND p.resource = $2 
          AND p.action = $3
          AND r.deleted_at IS NULL
          AND p.deleted_at IS NULL
          AND (ur.expires_at IS NULL OR ur.expires_at > CURRENT_TIMESTAMP)
      `;

      const result = await database.query<{ count: string }>(query, [userId, resource, action]);
      const hasPermission = parseInt(result[0]?.count ?? '0') > 0;

      logDatabaseOperation('SELECT', 'permissions', Date.now() - startTime, {
        userId,
        resource,
        action,
        hasPermission
      });

      return hasPermission;
    } catch (error) {
      logger.error('Error checking user permission', { error, userId, resource, action });
      throw error;
    }
  }

  /**
   * Transaction helper for complex role operations
   */
  static async withTransaction<T>(
    callback: (client: PoolClient) => Promise<T>
  ): Promise<T> {
    return await database.transaction(callback);
  }
}

/**
 * Permission repository
 */
export class PermissionRepository {
  /**
   * Create a new permission
   */
  static async createPermission(permissionData: {
    name: string;
    resource: string;
    action: string;
    description?: string;
  }): Promise<Permission> {
    const startTime = Date.now();
    
    try {
      const query = `
        INSERT INTO permissions (
          id, name, resource, action, description, created_at, updated_at
        ) VALUES (
          gen_random_uuid(), $1, $2, $3, $4, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
        RETURNING *
      `;

      const values = [
        permissionData.name,
        permissionData.resource,
        permissionData.action,
        permissionData.description ?? null
      ];

      const result = await database.query<Permission>(query, values);
      const permission = result[0];
      
      if (!permission) {
        throw new Error('Failed to create permission');
      }

      logDatabaseOperation('INSERT', 'permissions', Date.now() - startTime, {
        permissionId: permission.id,
        permissionName: permission.name
      });

      return permission;
    } catch (error) {
      logger.error('Error creating permission', { error, permissionData });
      throw error;
    }
  }

  /**
   * Assign permission to role
   */
  static async assignPermissionToRole(roleId: string, permissionId: string): Promise<void> {
    const startTime = Date.now();
    
    try {
      // Check if assignment already exists
      const existsQuery = `
        SELECT id FROM role_permissions 
        WHERE role_id = $1 AND permission_id = $2
      `;
      const existing = await database.query(existsQuery, [roleId, permissionId]);
      
      if (existing.length > 0) {
        return; // Already assigned
      }

      const query = `
        INSERT INTO role_permissions (
          id, role_id, permission_id, created_at, updated_at
        ) VALUES (
          gen_random_uuid(), $1, $2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
        )
      `;

      await database.query(query, [roleId, permissionId]);

      logDatabaseOperation('INSERT', 'role_permissions', Date.now() - startTime, {
        roleId,
        permissionId
      });
    } catch (error) {
      logger.error('Error assigning permission to role', { error, roleId, permissionId });
      throw error;
    }
  }

  /**
   * Remove permission from role
   */
  static async removePermissionFromRole(roleId: string, permissionId: string): Promise<boolean> {
    const startTime = Date.now();
    
    try {
      const query = `
        DELETE FROM role_permissions 
        WHERE role_id = $1 AND permission_id = $2
      `;

      const result = await database.query(query, [roleId, permissionId]);
      const success = (result as any).rowCount > 0;

      logDatabaseOperation('DELETE', 'role_permissions', Date.now() - startTime, {
        roleId,
        permissionId,
        success
      });

      return success;
    } catch (error) {
      logger.error('Error removing permission from role', { error, roleId, permissionId });
      throw error;
    }
  }

  /**
   * Get all permissions with pagination
   */
  static async findManyPermissions(params: QueryParams = {}): Promise<PaginatedResult<Permission>> {
    const startTime = Date.now();
    
    try {
      const {
        page = 1,
        limit = 20,
        sortBy = 'resource',
        sortOrder = 'ASC',
        search
      } = params;

      // Build base query
      let baseQuery = `
        FROM permissions p
        WHERE p.deleted_at IS NULL
      `;

      const queryParams: unknown[] = [];
      let paramIndex = 1;

      // Add search filter
      if (search) {
        baseQuery += ` AND (p.name ILIKE $${paramIndex} OR p.resource ILIKE $${paramIndex} OR p.action ILIKE $${paramIndex})`;
        queryParams.push(`%${search}%`);
        paramIndex++;
      }

      // Count total records
      const countQuery = `SELECT COUNT(*) as total ${baseQuery}`;
      const countResult = await database.query<{ total: string }>(countQuery, queryParams);
      const total = parseInt(countResult[0]?.total ?? '0');

      // Build main query with pagination
      const orderClause = DatabaseHelpers.buildOrderClause(sortBy, sortOrder);
      const { clause: paginationClause, values: paginationValues } = 
        DatabaseHelpers.buildPaginationClause(page, limit, paramIndex);

      const selectQuery = `
        SELECT p.id, p.name, p.resource, p.action, p.description, p.created_at, p.updated_at
        ${baseQuery}
        ${orderClause}
        ${paginationClause}
      `;

      const allParams = [...queryParams, ...paginationValues];
      const result = await database.query<Permission>(selectQuery, allParams);

      const totalPages = Math.ceil(total / limit);

      logDatabaseOperation('SELECT', 'permissions', Date.now() - startTime, {
        operation: 'findManyPermissions',
        totalRecords: total,
        page,
        limit
      });

      return {
        items: result,
        meta: {
          page,
          limit,
          total,
          totalPages
        }
      };
    } catch (error) {
      logger.error('Error finding permissions', { error, params });
      throw error;
    }
  }

  /**
   * Find permission by resource and action
   */
  static async findByResourceAndAction(resource: string, action: string): Promise<Permission | null> {
    const startTime = Date.now();
    
    try {
      const query = `
        SELECT id, name, resource, action, description, created_at, updated_at
        FROM permissions 
        WHERE resource = $1 AND action = $2 AND deleted_at IS NULL
      `;

      const result = await database.query<Permission>(query, [resource, action]);
      const permission = result[0] ?? null;

      logDatabaseOperation('SELECT', 'permissions', Date.now() - startTime, {
        resource,
        action,
        found: !!permission
      });

      return permission;
    } catch (error) {
      logger.error('Error finding permission by resource and action', { error, resource, action });
      throw error;
    }
  }
}