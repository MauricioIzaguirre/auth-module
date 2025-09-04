// server/src/app.ts
import express, { Application, Request, Response, NextFunction } from 'express'
import cors from 'cors'
import helmet from 'helmet'
import rateLimit from 'express-rate-limit'
import { config } from 'dotenv'
import { logger, apiLogger } from './utils/logger'
import { appConfig } from './config'
import { db } from './config/database'
import { authRoutes } from './routes/auth.routes'
import { userRoutes } from './routes/user.routes'
import { healthRoutes } from './routes/health.routes'
import { errorHandler } from './middleware/error.middleware'
import { requestLogger } from './middleware/logging.middleware'

// Load environment variables
config()

class App {
  public app: Application
  private port: number

  constructor() {
    this.app = express()
    this.port = parseInt(process.env.PORT || '3000')
    
    this.initializeMiddleware()
    this.initializeRoutes()
    this.initializeErrorHandling()
    this.initializeDatabase()
  }

  private initializeMiddleware(): void {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          scriptSrc: ["'self'"],
          imgSrc: ["'self'", "data:", "https:"],
        },
      },
      crossOriginEmbedderPolicy: false
    }))

    // CORS configuration
    this.app.use(cors({
      origin: process.env.FRONTEND_URL || 'http://localhost:3000',
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'x-csrf-token'],
      exposedHeaders: ['x-csrf-token']
    }))

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: appConfig.nodeEnv === 'development' ? 1000 : 100, // requests per window
      message: {
        success: false,
        message: 'Demasiadas solicitudes, intenta de nuevo más tarde',
        errors: ['Rate limit exceeded']
      },
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        logger.warn('Rate limit exceeded', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          path: req.path,
          method: req.method
        })
        res.status(429).json({
          success: false,
          message: 'Demasiadas solicitudes, intenta de nuevo más tarde',
          errors: ['Rate limit exceeded']
        })
      }
    })

    this.app.use('/api', limiter)

    // Body parsing middleware
    this.app.use(express.json({ limit: '10mb' }))
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }))

    // Cookie parsing
    this.app.use((req: Request, res: Response, next: NextFunction) => {
      const cookieHeader = req.headers.cookie
      req.cookies = {}
      
      if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
          const parts = cookie.trim().split('=')
          if (parts.length === 2) {
            req.cookies[parts[0]] = decodeURIComponent(parts[1])
          }
        })
      }
      next()
    })

    // Request logging
    this.app.use(requestLogger)

    // Trust proxy for production
    if (appConfig.nodeEnv === 'production') {
      this.app.set('trust proxy', 1)
    }
  }

  private initializeRoutes(): void {
    // Health check route (no rate limit)
    this.app.use('/health', healthRoutes)

    // API routes with rate limiting
    this.app.use('/api/auth', authRoutes)
    this.app.use('/api/users', userRoutes)

    // 404 handler for API routes
    this.app.use('/api/*', (req: Request, res: Response) => {
      res.status(404).json({
        success: false,
        message: 'Endpoint no encontrado',
        errors: [`Route ${req.method} ${req.originalUrl} not found`]
      })
    })

    // Root route
    this.app.get('/', (req: Request, res: Response) => {
      res.json({
        success: true,
        message: 'API de Autenticación - Clínica Oftalmológica',
        version: process.env.API_VERSION || '1.0.0',
        timestamp: new Date().toISOString(),
        endpoints: {
          auth: '/api/auth',
          users: '/api/users',
          health: '/health'
        }
      })
    })

    // Catch all other routes
    this.app.use('*', (req: Request, res: Response) => {
      res.status(404).json({
        success: false,
        message: 'Recurso no encontrado',
        errors: [`Route ${req.originalUrl} not found`]
      })
    })
  }

  private initializeErrorHandling(): void {
    this.app.use(errorHandler)
  }

  private async initializeDatabase(): Promise<void> {
    try {
      await db.initialize()
      logger.info('Database initialized successfully')
    } catch (error) {
      logger.error('Database initialization failed', error as Error)
      process.exit(1)
    }
  }

  public async start(): Promise<void> {
    try {
      await this.initializeDatabase()
      
      const server = this.app.listen(this.port, () => {
        logger.info(`Server started successfully`, {
          port: this.port,
          environment: appConfig.nodeEnv,
          timestamp: new Date().toISOString()
        })
      })

      // Graceful shutdown
      process.on('SIGTERM', () => {
        logger.info('SIGTERM received, shutting down gracefully')
        server.close(async () => {
          try {
            await db.close()
            logger.info('Database connections closed')
            process.exit(0)
          } catch (error) {
            logger.error('Error during shutdown', error as Error)
            process.exit(1)
          }
        })
      })

      process.on('SIGINT', () => {
        logger.info('SIGINT received, shutting down gracefully')
        server.close(async () => {
          try {
            await db.close()
            logger.info('Database connections closed')
            process.exit(0)
          } catch (error) {
            logger.error('Error during shutdown', error as Error)
            process.exit(1)
          }
        })
      })

      // Handle uncaught exceptions
      process.on('uncaughtException', (error: Error) => {
        logger.error('Uncaught exception', error)
        process.exit(1)
      })

      process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
        logger.error('Unhandled rejection', new Error(reason), { promise })
        process.exit(1)
      })

    } catch (error) {
      logger.error('Failed to start server', error as Error)
      process.exit(1)
    }
  }
}

// Create and start the application
const app = new App()

if (import.meta.url === `file://${process.argv[1]}`) {
  app.start()
}

export default app.app