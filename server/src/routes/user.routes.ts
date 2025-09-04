// server/src/routes/user.routes.ts
import { Router } from 'express'
import { UserController } from '../controllers/user.controller'
import { authMiddleware } from '../middleware/auth.middleware'
import { roleMiddleware } from '../middleware/role.middleware'
import { validationMiddleware } from '../middleware/validation.middleware'
import { 
  validateCreateUser,
  validateUpdateUser,
  validateUserFilters,
  validatePagination,
  validateIdParam,
  validateUserStatus,
  validateAssignRole,
  validateAssignMultipleRoles
} from '../schemas/user.schema'

const router = Router()
const userController = new UserController()

// All user routes require authentication
router.use(authMiddleware)

/**
 * @route GET /api/users
 * @desc Get all users with filters and pagination
 * @access Private (Admin, Manager)
 */
router.get('/',
  roleMiddleware(['admin', 'manager']),
  validationMiddleware(validateUserFilters, 'query'),
  validationMiddleware(validatePagination, 'query'),
  userController.getUsers
)

/**
 * @route POST /api/users
 * @desc Create new user
 * @access Private (Admin)
 */
router.post('/',
  roleMiddleware(['admin']),
  validationMiddleware(validateCreateUser),
  userController.createUser
)

/**
 * @route GET /api/users/search
 * @desc Search users
 * @access Private (Admin, Manager)
 */
router.get('/search',
  roleMiddleware(['admin', 'manager']),
  userController.searchUsers
)

/**
 * @route GET /api/users/:id
 * @desc Get user by ID
 * @access Private (Admin, Manager, Owner)
 */
router.get('/:id',
  validationMiddleware(validateIdParam, 'params'),
  userController.getUserById
)

/**
 * @route PUT /api/users/:id
 * @desc Update user
 * @access Private (Admin, Owner)
 */
router.put('/:id',
  validationMiddleware(validateIdParam, 'params'),
  validationMiddleware(validateUpdateUser),
  userController.updateUser
)

/**
 * @route DELETE /api/users/:id
 * @desc Delete user
 * @access Private (Admin)
 */
router.delete('/:id',
  roleMiddleware(['admin']),
  validationMiddleware(validateIdParam, 'params'),
  userController.deleteUser
)

/**
 * @route PATCH /api/users/:id/status
 * @desc Update user status (active/inactive)
 * @access Private (Admin)
 */
router.patch('/:id/status',
  roleMiddleware(['admin']),
  validationMiddleware(validateIdParam, 'params'),
  validationMiddleware(validateUserStatus),
  userController.updateUserStatus
)

/**
 * @route POST /api/users/:id/roles
 * @desc Assign role to user
 * @access Private (Admin)
 */
router.post('/:id/roles',
  roleMiddleware(['admin']),
  validationMiddleware(validateAssignRole),
  userController.assignRole
)

/**
 * @route PUT /api/users/:id/roles
 * @desc Assign multiple roles to user
 * @access Private (Admin)
 */
router.put('/:id/roles',
  roleMiddleware(['admin']),
  validationMiddleware(validateAssignMultipleRoles),
  userController.assignMultipleRoles
)

/**
 * @route DELETE /api/users/:id/roles/:roleId
 * @desc Remove role from user
 * @access Private (Admin)
 */
router.delete('/:id/roles/:roleId',
  roleMiddleware(['admin']),
  userController.removeRole
)

/**
 * @route GET /api/users/:id/roles
 * @desc Get user roles
 * @access Private (Admin, Manager, Owner)
 */
router.get('/:id/roles',
  validationMiddleware(validateIdParam, 'params'),
  userController.getUserRoles
)

/**
 * @route GET /api/users/:id/permissions
 * @desc Get user permissions
 * @access Private (Admin, Manager, Owner)
 */
router.get('/:id/permissions',
  validationMiddleware(validateIdParam, 'params'),
  userController.getUserPermissions
)

/**
 * @route GET /api/users/:id/sessions
 * @desc Get user active sessions
 * @access Private (Admin, Owner)
 */
router.get('/:id/sessions',
  validationMiddleware(validateIdParam, 'params'),
  userController.getUserSessions
)

/**
 * @route GET /api/users/:id/audit-logs
 * @desc Get user audit logs
 * @access Private (Admin)
 */
router.get('/:id/audit-logs',
  roleMiddleware(['admin']),
  validationMiddleware(validateIdParam, 'params'),
  userController.getUserAuditLogs
)

/**
 * @route GET /api/users/:id/login-history
 * @desc Get user login history
 * @access Private (Admin, Owner)
 */
router.get('/:id/login-history',
  validationMiddleware(validateIdParam, 'params'),
  userController.getLoginHistory
)

export { router as userRoutes }