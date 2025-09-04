// server/src/routes/health.routes.ts
import { Router, Request, Response } from 'express'
import { db } from '../config/database'
import { EmailService } from '../services/email.service'
import { logger } from '../utils/logger'

const router = Router()

/**
 * @route GET /health
 * @desc Basic health check
 * @access Public
 */
router.get('/', async (req: Request, res: Response) => {
  try {
    res.status(200).json({
      success: true,
      message: 'Service is healthy',
      data: {
        status: 'UP',
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        version: process.env.API_VERSION || '1.0.0',
        node: process.version,
        environment: process.env.NODE_ENV || 'development'
      }
    })
  } catch (error) {
    res.status(503).json({
      success: false,
      message: 'Service is unhealthy',
      errors: [(error as Error).message]
    })
  }
})

/**
 * @route GET /health/detailed
 * @desc Detailed health check including dependencies
 * @access Public
 */
router.get('/detailed', async (req: Request, res: Response) => {
  const startTime = Date.now()
  const checks: Record<string, any> = {}

  // Database health check
  try {
    const pool = await db.getPool()
    const result = await pool.query('SELECT NOW() as current_time')
    checks.database = {
      status: 'UP',
      responseTime: Date.now() - startTime,
      details: {
        currentTime: result.rows[0].current_time,
        poolSize: pool.totalCount,
        idleCount: pool.idleCount,
        waitingCount: pool.waitingCount
      }
    }
  } catch (error) {
    checks.database = {
      status: 'DOWN',
      error: (error as Error).message
    }
  }

  // Email service health check
  try {
    const emailService = new EmailService()
    const emailHealthy = await emailService.testConnection()
    checks.emailService = {
      status: emailHealthy ? 'UP' : 'DOWN',
      responseTime: Date.now() - startTime
    }
  } catch (error) {
    checks.emailService = {
      status: 'DOWN',
      error: (error as Error).message
    }
  }

  // Memory usage
  const memUsage = process.memoryUsage()
  checks.memory = {
    status: 'UP',
    details: {
      rss: Math.round(memUsage.rss / 1024 / 1024) + ' MB',
      heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024) + ' MB',
      heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024) + ' MB',
      external: Math.round(memUsage.external / 1024 / 1024) + ' MB'
    }
  }

  // CPU usage (basic)
  checks.cpu = {
    status: 'UP',
    details: {
      loadAverage: process.loadavg(),
      uptime: Math.floor(process.uptime())
    }
  }

  const allHealthy = Object.values(checks).every(check => check.status === 'UP')
  const overallStatus = allHealthy ? 'UP' : 'DEGRADED'
  const statusCode = allHealthy ? 200 : 207

  res.status(statusCode).json({
    success: allHealthy,
    message: `Service is ${overallStatus.toLowerCase()}`,
    data: {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      responseTime: Date.now() - startTime,
      checks,
      system: {
        version: process.env.API_VERSION || '1.0.0',
        node: process.version,
        platform: process.platform,
        arch: process.arch,
        environment: process.env.NODE_ENV || 'development'
      }
    }
  })
})

/**
 * @route GET /health/database
 * @desc Database-specific health check
 * @access Public
 */
