/**
 * Example: Public API Documentation Exposure
 * 
 * This file demonstrates the security issue of exposing API documentation publicly
 * and shows how to restrict access based on environment and authentication.
 */

const express = require('express');
const swaggerUi = require('swagger-ui-express');
const swaggerJsdoc = require('swagger-jsdoc');

// ============================================================================
// ❌ INSECURE: Public API documentation
// ============================================================================

function insecureSwaggerSetup() {
  const app = express();
  
  // BAD: Swagger always enabled, publicly accessible
  const swaggerOptions = {
    definition: {
      openapi: '3.0.0',
      info: {
        title: 'API Documentation',
        version: '1.0.0',
      },
    },
    apis: ['./routes/*.js'],
  };
  
  const swaggerSpec = swaggerJsdoc(swaggerOptions);
  
  // BAD: No environment check, no authentication
  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
  
  return app;
}

// ============================================================================
// ✅ SECURE: Environment-based documentation access
// ============================================================================

function secureSwaggerSetup() {
  const app = express();
  const NODE_ENV = process.env.NODE_ENV || 'development';
  
  // GOOD: Only enable Swagger in non-production environments
  if (NODE_ENV !== 'production') {
    const swaggerOptions = {
      definition: {
        openapi: '3.0.0',
        info: {
          title: 'API Documentation',
          version: '1.0.0',
        },
      },
      apis: ['./routes/*.js'],
    };
    
    const swaggerSpec = swaggerJsdoc(swaggerOptions);
    app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
  } else {
    // GOOD: Disable in production
    app.use('/api-docs', (req, res) => {
      res.status(404).json({ error: 'Not found' });
    });
  }
  
  return app;
}

// ============================================================================
// ✅ SECURE: Documentation with authentication
// ============================================================================

const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

function secureSwaggerWithAuth() {
  const app = express();
  const NODE_ENV = process.env.NODE_ENV || 'development';
  
  const swaggerOptions = {
    definition: {
      openapi: '3.0.0',
      info: {
        title: 'API Documentation',
        version: '1.0.0',
      },
    },
    apis: ['./routes/*.js'],
  };
  
  const swaggerSpec = swaggerJsdoc(swaggerOptions);
  
  // GOOD: Require authentication and admin role
  app.use('/api-docs',
    requireAuth,
    requireAdmin,
    swaggerUi.serve,
    swaggerUi.setup(swaggerSpec)
  );
  
  return app;
}

// ============================================================================
// NestJS Example
// ============================================================================

/*
// ❌ BAD: Swagger always enabled in main.ts
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // BAD: Always sets up Swagger
  const config = new DocumentBuilder()
    .setTitle('API')
    .setVersion('1.0')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);
  
  await app.listen(3000);
}
*/

/*
// ✅ GOOD: Swagger only in non-production
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  
  // GOOD: Only enable in development/QA
  if (process.env.NODE_ENV !== 'production') {
    const config = new DocumentBuilder()
      .setTitle('API')
      .setVersion('1.0')
      .build();
    const document = SwaggerModule.createDocument(app, config);
    SwaggerModule.setup('api', app, document);
  }
  
  await app.listen(3000);
}
*/

// ============================================================================
// Environment-based configuration
// ============================================================================

function getSwaggerConfig() {
  const NODE_ENV = process.env.NODE_ENV || 'development';
  
  // GOOD: Configuration based on environment
  const config = {
    enabled: NODE_ENV !== 'production',
    path: '/api-docs',
    requireAuth: true,
    requireAdmin: NODE_ENV === 'production', // Only require admin in prod if enabled
  };
  
  return config;
}

function conditionalSwaggerSetup() {
  const app = express();
  const config = getSwaggerConfig();
  
  if (config.enabled) {
    const swaggerOptions = {
      definition: {
        openapi: '3.0.0',
        info: {
          title: 'API Documentation',
          version: '1.0.0',
        },
      },
      apis: ['./routes/*.js'],
    };
    
    const swaggerSpec = swaggerJsdoc(swaggerOptions);
    
    // Apply middleware based on config
    const middleware = [swaggerUi.serve, swaggerUi.setup(swaggerSpec)];
    
    if (config.requireAuth) {
      middleware.unshift(requireAuth);
    }
    
    if (config.requireAdmin) {
      middleware.unshift(requireAdmin);
    }
    
    app.use(config.path, ...middleware);
  } else {
    // GOOD: Return 404 in production
    app.use(config.path, (req, res) => {
      res.status(404).json({ error: 'Not found' });
    });
  }
  
  return app;
}

module.exports = {
  insecureSwaggerSetup,
  secureSwaggerSetup,
  secureSwaggerWithAuth,
  getSwaggerConfig,
  conditionalSwaggerSetup,
  requireAuth,
  requireAdmin
};
