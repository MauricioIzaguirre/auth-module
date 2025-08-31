import { IPermission, CreatePermissionDTO, APIResponse } from '../../types/auth.types'
import { Resource, Action, PermissionCondition } from '../../types/rbac.types'

// Interface para el modelo de permisos
export interface IPermissionModel {
  // Operaciones CRUD básicas
  create(permissionData: CreatePermissionDTO): Promise<IPermission>
  findById(id: string): Promise<IPermission | null>
  findByResourceAndAction(resource: string, action: string): Promise<IPermission | null>
  update(id: string, permissionData: Partial<CreatePermissionDTO>): Promise<IPermission | null>
  delete(id: string): Promise<boolean>
  
  // Operaciones de listado
  findAll(filters?: PermissionFilters): Promise<IPermission[]>
  findByResource(resource: string): Promise<IPermission[]>
  findByAction(action: string): Promise<IPermission[]>
  
  // Operaciones de roles
  findRolesByPermission(permissionId: string): Promise<string[]>
  findUsersByPermission(permissionId: string): Promise<string[]>
  
  // Verificaciones
  exists(resource: string, action: string): Promise<boolean>
  isSystemPermission(permissionId: string): Promise<boolean>
  
  // Operaciones masivas
  createBulk(permissions: CreatePermissionDTO[]): Promise<IPermission[]>
  deleteBulk(permissionIds: string[]): Promise<boolean>
  
  // Permisos contextuales
  checkContextualPermission(
    userId: string, 
    resource: string, 
    action: string, 
    context?: Record<string, any>
  ): Promise<boolean>
  
  // Auditoría de permisos
  createPermissionAuditLog(auditData: CreatePermissionAuditDTO): Promise<void>
  getPermissionAuditHistory(permissionId: string, limit?: number): Promise<IPermissionAuditLog[]>
}

// Filtros para búsqueda de permisos
export interface PermissionFilters {
  resource?: string
  action?: string
  isSystemPermission?: boolean
  search?: string
}

// DTOs específicos para permisos
export interface CreatePermissionAuditDTO {
  permissionId: string
  userId?: string
  action: PermissionAuditAction
  details?: Record<string, any>
  ipAddress?: string
  userAgent?: string
}

export interface IPermissionAuditLog {
  id: string
  permissionId: string
  userId?: string
  action: PermissionAuditAction
  details?: Record<string, any>
  ipAddress?: string
  userAgent?: string
  timestamp: Date
}

export enum PermissionAuditAction {
  PERMISSION_CREATED = 'PERMISSION_CREATED',
  PERMISSION_UPDATED = 'PERMISSION_UPDATED',
  PERMISSION_DELETED = 'PERMISSION_DELETED',
  PERMISSION_ASSIGNED = 'PERMISSION_ASSIGNED',
  PERMISSION_REMOVED = 'PERMISSION_REMOVED',
  PERMISSION_CHECKED = 'PERMISSION_CHECKED',
  PERMISSION_DENIED = 'PERMISSION_DENIED'
}

// Permisos predefinidos para clínica oftalmológica
export interface ClinicPermissions {
  // Gestión de usuarios
  'user:create': IPermission
  'user:read': IPermission
  'user:update': IPermission
  'user:delete': IPermission
  'user:list': IPermission
  'user:manage': IPermission
  
  // Gestión de pacientes
  'patient:create': IPermission
  'patient:read': IPermission
  'patient:update': IPermission
  'patient:delete': IPermission
  'patient:list': IPermission
  'patient:manage': IPermission
  
  // Gestión de citas
  'appointment:create': IPermission
  'appointment:read': IPermission
  'appointment:update': IPermission
  'appointment:delete': IPermission
  'appointment:list': IPermission
  'appointment:schedule': IPermission
  'appointment:cancel': IPermission
  
  // Historial médico
  'medical_record:create': IPermission
  'medical_record:read': IPermission
  'medical_record:update': IPermission
  'medical_record:delete': IPermission
  'medical_record:access_own': IPermission
  'medical_record:access_all': IPermission
  
  // Inventario
  'inventory:create': IPermission
  'inventory:read': IPermission
  'inventory:update': IPermission
  'inventory:delete': IPermission
  'inventory:manage': IPermission
  
  // Facturación
  'billing:create': IPermission
  'billing:read': IPermission
  'billing:update': IPermission
  'billing:delete': IPermission
  'billing:process': IPermission
  
  // Reportes
  'report:generate': IPermission
  'report:view': IPermission
  'report:export': IPermission
  'report:schedule': IPermission
  
  // Sistema
  'system:configure': IPermission
  'system:backup': IPermission
  'system:restore': IPermission
  'system:monitor': IPermission
}

// Builder para construir permisos dinámicamente
export interface PermissionBuilder {
  resource(resource: Resource | string): PermissionBuilder
  action(action: Action | string): PermissionBuilder
  description(description: string): PermissionBuilder
  condition(condition: PermissionCondition): PermissionBuilder
  build(): CreatePermissionDTO
}

// Respuestas específicas para operaciones de permisos
export interface PermissionResponse extends APIResponse {
  data?: {
    permission: IPermission
  }
}

export interface PermissionListResponse extends APIResponse {
  data?: {
    permissions: IPermission[]
    total: number
  }
}

export interface PermissionCheckResponse {
  granted: boolean
  permission: string
  reason?: string
  context?: Record<string, any>
}