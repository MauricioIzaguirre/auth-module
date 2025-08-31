import { z } from 'zod'
import { ValidationUtils } from '../utils/validation.utils'

// Schema base para rol
const baseRoleSchema = z.object({
  name: z.string()
    .min(2, 'El nombre del rol debe tener al menos 2 caracteres')
    .max(50, 'El nombre del rol no puede tener más de 50 caracteres')
    .regex(/^[a-zA-Z0-9_\s-]+$/, 'El nombre del rol solo puede contener letras, números, espacios, guiones y guiones bajos')
    .transform(val => val.trim())
    .refine(
      val => !['admin', 'root', 'system', 'guest', 'anonymous'].includes(val.toLowerCase()),
      'Nombre de rol reservado del sistema'
    ),

  description: z.string()
    .max(500, 'La descripción no puede tener más de 500 caracteres')
    .transform(val => ValidationUtils.sanitizeInput(val))
    .optional(),

  isActive: z.boolean().default(true),
  
  permissionIds: z.array(z.string().uuid('ID de permiso debe ser un UUID válido'))
    .max(100, 'Un rol no puede tener más de 100 permisos')
    .optional()
})

// Schema para crear rol
export const createRoleSchema = baseRoleSchema.extend({
  permissionIds: z.array(z.string().uuid('ID de permiso debe ser un UUID válido'))
    .min(1, 'Un rol debe tener al menos un permiso')
    .max(100, 'Un rol no puede tener más de 100 permisos')
    .optional()
})

// Schema para actualizar rol
export const updateRoleSchema = baseRoleSchema.partial().extend({
  id: z.string().uuid('ID de rol debe ser un UUID válido')
}).omit({ permissionIds: true }) // Los permisos se manejan por separado

// Schema para asignación de permisos a rol
export const assignPermissionToRoleSchema = z.object({
  roleId: z.string().uuid('ID de rol debe ser un UUID válido'),
  permissionId: z.string().uuid('ID de permiso debe ser un UUID válido')
})

// Schema para asignación múltiple de permisos
export const assignMultiplePermissionsSchema = z.object({
  roleId: z.string().uuid('ID de rol debe ser un UUID válido'),
  permissionIds: z.array(z.string().uuid('ID de permiso debe ser un UUID válido'))
    .min(1, 'Debe proporcionar al menos un permiso')
    .max(50, 'No puede asignar más de 50 permisos a la vez')
    .transform(val => [...new Set(val)]) // Remover duplicados
})

// Schema para jerarquía de roles
export const roleHierarchySchema = z.object({
  parentRoleId: z.string().uuid('ID de rol padre debe ser un UUID válido').nullable(),
  childRoleId: z.string().uuid('ID de rol hijo debe ser un UUID válido')
}).refine(
  data => data.parentRoleId !== data.childRoleId,
  {
    message: 'Un rol no puede ser padre de sí mismo',
    path: ['parentRoleId']
  }
)

// Schema para filtros de rol
export const roleFiltersSchema = z.object({
  isActive: z.boolean().optional(),
  hasPermission: z.string().optional(),
  search: z.string()
    .max(100, 'La búsqueda no puede tener más de 100 caracteres')
    .transform(val => ValidationUtils.sanitizeInput(val))
    .optional(),
  createdAfter: z.string().datetime().optional(),
  createdBefore: z.string().datetime().optional(),
  parentRoleId: z.string().uuid().optional()
})

// Schema para clonar rol
export const cloneRoleSchema = z.object({
  sourceRoleId: z.string().uuid('ID de rol fuente debe ser un UUID válido'),
  newRoleName: z.string()
    .min(2, 'El nombre del nuevo rol debe tener al menos 2 caracteres')
    .max(50, 'El nombre del nuevo rol no puede tener más de 50 caracteres')
    .regex(/^[a-zA-Z0-9_\s-]+$/, 'El nombre del rol solo puede contener letras, números, espacios, guiones y guiones bajos')
    .transform(val => val.trim()),
  copyPermissions: z.boolean().default(true),
  copyHierarchy: z.boolean().default(false)
})

// Schema para operaciones masivas de roles
export const bulkRoleOperationSchema = z.object({
  operation: z.enum(['activate', 'deactivate', 'delete', 'assign_permission', 'remove_permission']),
  roleIds: z.array(z.string().uuid('ID de rol debe ser un UUID válido'))
    .min(1, 'Debe proporcionar al menos un rol')
    .max(20, 'No puede procesar más de 20 roles a la vez'),
  permissionIds: z.array(z.string().uuid('ID de permiso debe ser un UUID válido'))
    .optional(),
  reason: z.string()
    .max(500, 'La razón no puede tener más de 500 caracteres')
    .optional()
})

// Schema específico para roles de clínica oftalmológica
export const clinicRoleSchema = z.object({
  roleType: z.enum([
    'super_admin',
    'admin', 
    'doctor',
    'nurse',
    'receptionist',
    'patient',
    'technician',
    'manager'
  ]),
  specialization: z.string()
    .max(100, 'La especialización no puede tener más de 100 caracteres')
    .optional(), // Solo para doctores
  department: z.string()
    .max(100, 'El departamento no puede tener más de 100 caracteres')
    .optional(),
  licenseNumber: z.string()
    .max(50, 'El número de licencia no puede tener más de 50 caracteres')
    .optional(), // Para doctores y técnicos
  supervisionLevel: z.enum(['none', 'basic', 'intermediate', 'advanced', 'full'])
    .default('none')
})

// Schema para configuración de permisos por rol
export const rolePermissionConfigSchema = z.object({
  roleId: z.string().uuid('ID de rol debe ser un UUID válido'),
  permissions: z.record(
    z.string(), // resource
    z.array(z.string()) // actions
  ),
  inheritFromParent: z.boolean().default(true),
  overrideInheritance: z.boolean().default(false)
})

// Schema para validación de acceso a recurso
export const resourceAccessSchema = z.object({
  userId: z.string().uuid('ID de usuario debe ser un UUID válido'),
  resource: z.string()
    .min(1, 'El recurso es requerido')
    .max(50, 'El recurso no puede tener más de 50 caracteres')
    .regex(/^[a-z_]+$/, 'El recurso solo puede contener letras minúsculas y guiones bajos'),
  action: z.string()
    .min(1, 'La acción es requerida')
    .max(50, 'La acción no puede tener más de 50 caracteres')
    .regex(/^[a-z_]+$/, 'La acción solo puede contener letras minúsculas y guiones bajos'),
  resourceId: z.string().uuid().optional(),
  context: z.record(z.any()).optional()
})

// Funciones de validación exportadas
export const validateCreateRole = (data: unknown) => {
  return createRoleSchema.safeParse(data)
}

export const validateUpdateRole = (data: unknown) => {
  return updateRoleSchema.safeParse(data)
}

export const validateAssignPermissionToRole = (data: unknown) => {
  return assignPermissionToRoleSchema.safeParse(data)
}

export const validateAssignMultiplePermissions = (data: unknown) => {
  return assignMultiplePermissionsSchema.safeParse(data)
}

export const validateRoleHierarchy = (data: unknown) => {
  return roleHierarchySchema.safeParse(data)
}

export const validateRoleFilters = (data: unknown) => {
  return roleFiltersSchema.safeParse(data)
}

export const validateCloneRole = (data: unknown) => {
  return cloneRoleSchema.safeParse(data)
}

export const validateBulkRoleOperation = (data: unknown) => {
  return bulkRoleOperationSchema.safeParse(data)
}

export const validateClinicRole = (data: unknown) => {
  return clinicRoleSchema.safeParse(data)
}

export const validateRolePermissionConfig = (data: unknown) => {
  return rolePermissionConfigSchema.safeParse(data)
}

export const validateResourceAccess = (data: unknown) => {
  return resourceAccessSchema.safeParse(data)
}