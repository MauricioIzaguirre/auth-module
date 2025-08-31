// Tipos específicos para RBAC (Role-Based Access Control)

// Recursos del sistema que pueden ser protegidos
export enum Resource {
  USER = 'user',
  ROLE = 'role',
  PERMISSION = 'permission',
  APPOINTMENT = 'appointment',
  PATIENT = 'patient',
  DOCTOR = 'doctor',
  MEDICAL_RECORD = 'medical_record',
  INVENTORY = 'inventory',
  BILLING = 'billing',
  REPORT = 'report',
  SYSTEM = 'system'
}

// Acciones que se pueden realizar sobre los recursos
export enum Action {
  CREATE = 'create',
  READ = 'read',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  MANAGE = 'manage', // Todas las acciones
  APPROVE = 'approve',
  REJECT = 'reject',
  EXPORT = 'export',
  IMPORT = 'import'
}

// Combinación de recurso y acción para formar un permiso
export interface Permission {
  resource: Resource | string
  action: Action | string
  conditions?: PermissionCondition[]
}

// Condiciones para permisos contextuales
export interface PermissionCondition {
  field: string
  operator: 'equals' | 'not_equals' | 'in' | 'not_in' | 'greater_than' | 'less_than' | 'contains'
  value: any
  context?: 'user' | 'resource' | 'request' | 'time'
}

// Roles predefinidos para una clínica oftalmológica
export enum ClinicRole {
  SUPER_ADMIN = 'super_admin',
  ADMIN = 'admin',
  DOCTOR = 'doctor',
  NURSE = 'nurse',
  RECEPTIONIST = 'receptionist',
  PATIENT = 'patient',
  TECHNICIAN = 'technician',
  MANAGER = 'manager',
  GUEST = 'guest'
}

// Configuración de roles jerárquicos
export interface RoleHierarchy {
  parentRole: string
  childRoles: string[]
  inheritPermissions: boolean
}

// Contexto para evaluación de permisos
export interface PermissionContext {
  userId: string
  resourceId?: string
  resourceData?: Record<string, any>
  requestData?: Record<string, any>
  ipAddress?: string
  timestamp: Date
}

// Resultado de verificación de permisos
export interface PermissionCheckResult {
  granted: boolean
  reason?: string
  requiredPermissions: string[]
  userPermissions: string[]
  context?: PermissionContext
}

// Política de acceso
export interface AccessPolicy {
  id: string
  name: string
  description?: string
  rules: PolicyRule[]
  isActive: boolean
  priority: number
  createdAt: Date
  updatedAt: Date
}

export interface PolicyRule {
  condition: string // Expresión condicional (ej: "user.department === resource.department")
  effect: 'allow' | 'deny'
  resources: string[]
  actions: string[]
}

// Configuración RBAC completa
export interface RBACConfiguration {
  roles: RoleDefinition[]
  permissions: PermissionDefinition[]
  policies: AccessPolicy[]
  hierarchy: RoleHierarchy[]
  defaultAssignments: DefaultRoleAssignment[]
}

export interface RoleDefinition {
  name: string
  description: string
  permissions: string[]
  isSystemRole: boolean
  hierarchy?: {
    parent?: string
    children?: string[]
  }
}

export interface PermissionDefinition {
  resource: string
  action: string
  description: string
  isSystemPermission: boolean
}

export interface DefaultRoleAssignment {
  condition: string // Ej: "user.email.endsWith('@clinic.com')"
  roleNames: string[]
}

// Tipos para middleware RBAC
export interface RBACMiddlewareOptions {
  permissions?: string[]
  roles?: string[]
  requireAll?: boolean // Si true, requiere TODOS los permisos/roles, si false, requiere AL MENOS UNO
  customCheck?: (user: any, context: PermissionContext) => Promise<boolean>
  onDenied?: (req: any, res: any, next: any) => void
}