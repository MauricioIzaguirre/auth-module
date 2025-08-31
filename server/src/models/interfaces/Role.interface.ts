import { IRole, IRolePublic, CreateRoleDTO, UpdateRoleDTO, RoleFilters, PaginationOptions, APIResponse } from '../../types/auth.types'

// Interface para el modelo de rol
export interface IRoleModel {
  // Operaciones CRUD básicas
  create(roleData: CreateRoleDTO): Promise<IRole>
  findById(id: string): Promise<IRole | null>
  findByName(name: string): Promise<IRole | null>
  update(id: string, roleData: UpdateRoleDTO): Promise<IRole | null>
  delete(id: string): Promise<boolean>
  
  // Operaciones de listado y búsqueda
  findAll(filters?: RoleFilters, pagination?: PaginationOptions): Promise<{
    roles: IRolePublic[]
    total: number
  }>
  
  // Operaciones de permisos
  assignPermission(roleId: string, permissionId: string): Promise<void>
  removePermission(roleId: string, permissionId: string): Promise<void>
  getRolePermissions(roleId: string): Promise<string[]>
  assignMultiplePermissions(roleId: string, permissionIds: string[]): Promise<void>
  removeMultiplePermissions(roleId: string, permissionIds: string[]): Promise<void>
  
  // Operaciones de usuarios
  getUsersByRole(roleId: string, pagination?: PaginationOptions): Promise<{
    users: any[]
    total: number
  }>
  getRoleUsers(roleId: string): Promise<string[]>
  
  // Verificaciones
  existsByName(name: string): Promise<boolean>
  hasPermission(roleId: string, permission: string): Promise<boolean>
  
  // Jerarquía de roles
  setParentRole(roleId: string, parentRoleId: string | null): Promise<void>
  getChildRoles(roleId: string): Promise<IRole[]>
  getParentRole(roleId: string): Promise<IRole | null>
  getRoleHierarchy(roleId: string): Promise<IRoleHierarchy>
  getAllPermissionsWithInheritance(roleId: string): Promise<string[]>
  
  // Operaciones de auditoría
  createRoleAuditLog(auditData: CreateRoleAuditDTO): Promise<void>
  getRoleAuditHistory(roleId: string, limit?: number): Promise<IRoleAuditLog[]>
  
  // Operaciones especiales
  cloneRole(sourceRoleId: string, newRoleName: string): Promise<IRole>
  deactivateRole(roleId: string): Promise<void>
  activateRole(roleId: string): Promise<void>
}

// Jerarquía de roles
export interface IRoleHierarchy {
  role: IRole
  parent?: IRole
  children: IRole[]
  allPermissions: string[] // Incluyendo permisos heredados
  directPermissions: string[]
  inheritedPermissions: string[]
}

// DTOs específicos para roles
export interface CreateRoleAuditDTO {
  roleId: string
  userId?: string
  action: RoleAuditAction
  details?: Record<string, any>
  ipAddress?: string
  userAgent?: string
}

export interface IRoleAuditLog {
  id: string
  roleId: string
  userId?: string
  action: RoleAuditAction
  details?: Record<string, any>
  ipAddress?: string
  userAgent?: string
  timestamp: Date
}

export enum RoleAuditAction {
  ROLE_CREATED = 'ROLE_CREATED',
  ROLE_UPDATED = 'ROLE_UPDATED',
  ROLE_DELETED = 'ROLE_DELETED',
  ROLE_ACTIVATED = 'ROLE_ACTIVATED',
  ROLE_DEACTIVATED = 'ROLE_DEACTIVATED',
  PERMISSION_ASSIGNED = 'PERMISSION_ASSIGNED',
  PERMISSION_REMOVED = 'PERMISSION_REMOVED',
  USER_ASSIGNED = 'USER_ASSIGNED',
  USER_REMOVED = 'USER_REMOVED',
  HIERARCHY_CHANGED = 'HIERARCHY_CHANGED'
}

// Configuración de roles predefinidos para clínica oftalmológica
export interface ClinicRoleConfiguration {
  superAdmin: {
    name: string
    permissions: string[]
    description: string
  }
  admin: {
    name: string
    permissions: string[]
    description: string
    parent?: string
  }
  doctor: {
    name: string
    permissions: string[]
    description: string
    specializations?: string[]
  }
  nurse: {
    name: string
    permissions: string[]
    description: string
  }
  receptionist: {
    name: string
    permissions: string[]
    description: string
  }
  patient: {
    name: string
    permissions: string[]
    description: string
  }
  technician: {
    name: string
    permissions: string[]
    description: string
  }
  manager: {
    name: string
    permissions: string[]
    description: string
  }
}

// Respuestas específicas para operaciones de rol
export interface RoleCreationResponse extends APIResponse {
  data?: {
    role: IRolePublic
    assignedPermissions: string[]
  }
}

export interface RoleListResponse extends APIResponse {
  data?: {
    roles: IRolePublic[]
    pagination: {
      page: number
      limit: number
      total: number
      totalPages: number
    }
  }
}

export interface RoleHierarchyResponse extends APIResponse {
  data?: {
    hierarchy: IRoleHierarchy
  }
}

// Bulk operations para roles
export interface BulkRoleOperation {
  operation: 'assign' | 'remove' | 'update'
  roleIds: string[]
  data?: UpdateRoleDTO
  permissionIds?: string[]
  userIds?: string[]
}

export interface BulkRoleOperationResult {
  success: boolean
  totalProcessed: number
  successful: number
  failed: number
  errors: Array<{
    roleId: string
    error: string
  }>
}