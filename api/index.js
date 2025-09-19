const express = require('express');
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const cors = require('cors');
const joi = require('joi');

const envSchema = joi.object({
  NODE_ENV: joi.string().valid('development', 'production', 'test').default('production'),
  AWS_REGION: joi.string().required(),
  S3_BUCKET_NAME: joi.string().required(),
  AWS_ACCESS_KEY_ID: joi.string().required(),
  AWS_SECRET_ACCESS_KEY: joi.string().required(),
  ALLOWED_ORIGINS: joi.string().default('*'),
  MAX_FILE_SIZE_MB: joi.number().min(1).max(50).default(10),
  UPLOAD_RATE_LIMIT_WINDOW_MS: joi.number().default(15 * 60 * 1000),
  UPLOAD_RATE_LIMIT_MAX: joi.number().default(10),
  PRESIGNED_URL_EXPIRY: joi.number().default(300) // 5 minutos
}).unknown();

const { error, value: envVars } = envSchema.validate(process.env);

if (error) {
  console.error(`❌ Error crítico en configuración: ${error.message}`);
  throw new Error(`Configuration error: ${error.message}`);
}

const logger = {
  info: (message, meta = {}) => console.log(JSON.stringify({ level: 'info', message, ...meta, timestamp: new Date().toISOString() })),
  error: (message, meta = {}) => console.error(JSON.stringify({ level: 'error', message, ...meta, timestamp: new Date().toISOString() })),
  warn: (message, meta = {}) => console.warn(JSON.stringify({ level: 'warn', message, ...meta, timestamp: new Date().toISOString() }))
};

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", `https://${envVars.S3_BUCKET_NAME}.s3.amazonaws.com`],
      connectSrc: ["'self'"]
    }
  },
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

app.use(compression({
  level: 6,
  threshold: 1024
}));

const uploadLimiter = rateLimit({
  windowMs: envVars.UPLOAD_RATE_LIMIT_WINDOW_MS,
  max: envVars.UPLOAD_RATE_LIMIT_MAX,
  message: {
    success: false,
    error: 'RATE_LIMIT_EXCEEDED',
    message: `Demasiadas solicitudes. Máximo ${envVars.UPLOAD_RATE_LIMIT_MAX} uploads cada ${Math.floor(envVars.UPLOAD_RATE_LIMIT_WINDOW_MS / 1000 / 60)} minutos.`,
    retryAfter: Math.floor(envVars.UPLOAD_RATE_LIMIT_WINDOW_MS / 1000)
  },
  standardHeaders: true,
  legacyHeaders: false
});

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false
});

app.use(generalLimiter);

const allowedOrigins = envVars.ALLOWED_ORIGINS === '*' ? '*' : envVars.ALLOWED_ORIGINS.split(',').map(origin => origin.trim());

app.use(cors({
  origin: allowedOrigins === '*' ? true : (origin, callback) => {
    if (!origin && envVars.NODE_ENV !== 'production') {
      return callback(null, true);
    }
    
    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    logger.warn('Origen CORS rechazado', { origin, allowedOrigins });
    return callback(new Error('No permitido por política CORS'));
  },
  methods: ['GET', 'POST', 'PUT', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true,
  maxAge: 86400
}));

const s3Client = new S3Client({
  region: envVars.AWS_REGION,
  credentials: {
    accessKeyId: envVars.AWS_ACCESS_KEY_ID,
    secretAccessKey: envVars.AWS_SECRET_ACCESS_KEY
  },
  maxAttempts: 3,
  retryMode: 'adaptive',
  requestTimeout: 30000
});

const ALLOWED_MIME_TYPES = {
  'image/jpeg': '.jpg',
  'image/png': '.png',
  'image/webp': '.webp',
  'application/pdf': '.pdf'
};

const generateSafeFileName = (originalName, mimetype) => {
  const extension = ALLOWED_MIME_TYPES[mimetype];
  const timestamp = Date.now();
  const uuid = uuidv4();
  const datePath = new Date().toISOString().slice(0, 10);
  
  return `uploads/${datePath}/${timestamp}-${uuid}${extension}`;
};

const validateFileRequest = (fileName, fileSize, mimeType) => {
  const errors = [];

  if (!fileName || !/^[a-zA-Z0-9._-]+$/.test(fileName)) {
    errors.push('Nombre de archivo inválido. Solo se permiten letras, números, puntos, guiones y guiones bajos.');
  }

  if (!ALLOWED_MIME_TYPES[mimeType]) {
    errors.push(`Tipo de archivo no permitido: ${mimeType}`);
  }

  if (fileName && mimeType && ALLOWED_MIME_TYPES[mimeType]) {
    const fileExtension = path.extname(fileName).toLowerCase();
    if (fileExtension !== ALLOWED_MIME_TYPES[mimeType]) {
      errors.push('La extensión del archivo no coincide con su tipo');
    }
  }

  const maxSize = envVars.MAX_FILE_SIZE_MB * 1024 * 1024;
  if (fileSize > maxSize) {
    errors.push(`Archivo demasiado grande. Tamaño máximo: ${envVars.MAX_FILE_SIZE_MB}MB`);
  }

  return errors;
};

app.use((req, res, next) => {
  const startTime = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    logger.info('Request completado', {
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });
  });
  
  next();
});

// Health check endpoint
app.get('/health', async (req, res) => {
  const healthCheck = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    environment: envVars.NODE_ENV,
    uploadMethod: 'presigned-urls',
    maxFileSize: `${envVars.MAX_FILE_SIZE_MB}MB`,
    services: {
      s3: 'checking'
    }
  };

  try {
    await s3Client.config.credentials();
    healthCheck.services.s3 = 'healthy';
  } catch (error) {
    healthCheck.services.s3 = 'error';
    healthCheck.status = 'degraded';
  }

  const statusCode = healthCheck.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(healthCheck);
});

app.post('/api/v1/upload/presigned', 
  uploadLimiter,
  async (req, res) => {
    const requestId = uuidv4();
    
    try {
      const { fileName, fileSize, mimeType } = req.body;

      // Validar parámetros requeridos
      if (!fileName || !fileSize || !mimeType) {
        return res.status(400).json({
          success: false,
          error: 'MISSING_PARAMETERS',
          message: 'Se requieren fileName, fileSize y mimeType',
          requestId
        });
      }

      // Validar archivo
      const validationErrors = validateFileRequest(fileName, fileSize, mimeType);
      if (validationErrors.length > 0) {
        return res.status(400).json({
          success: false,
          error: 'VALIDATION_ERROR',
          message: 'Error de validación del archivo',
          details: validationErrors,
          allowedTypes: Object.keys(ALLOWED_MIME_TYPES),
          requestId
        });
      }

      const s3Key = generateSafeFileName(fileName, mimeType);
      
      // Crear comando para upload
      const command = new PutObjectCommand({
        Bucket: envVars.S3_BUCKET_NAME,
        Key: s3Key,
        ContentType: mimeType,
        ContentLength: fileSize,
        ServerSideEncryption: 'AES256',
        CacheControl: 'max-age=31536000',
        Metadata: {
          'uploaded-at': new Date().toISOString(),
          'service': 'dermaia-api',
          'original-name': fileName,
          'file-size': fileSize.toString(),
          'request-id': requestId
        }
      });

      // Generar URL firmada
      const presignedUrl = await getSignedUrl(s3Client, command, {
        expiresIn: envVars.PRESIGNED_URL_EXPIRY
      });

      const fileUrl = `https://${envVars.S3_BUCKET_NAME}.s3.${envVars.AWS_REGION}.amazonaws.com/${s3Key}`;

      logger.info('URL firmada generada', {
        requestId,
        fileName,
        fileSize,
        mimeType,
        s3Key,
        ip: req.ip
      });

      res.status(200).json({
        success: true,
        data: {
          uploadUrl: presignedUrl,
          fileUrl,
          s3Key,
          expiresIn: envVars.PRESIGNED_URL_EXPIRY,
          uploadMethod: 'PUT',
          headers: {
            'Content-Type': mimeType,
            'Content-Length': fileSize
          }
        },
        message: 'URL de upload generada correctamente',
        requestId
      });

    } catch (error) {
      logger.error('Error generando URL firmada', {
        requestId,
        error: error.message,
        stack: error.stack,
        ip: req.ip
      });

      res.status(500).json({
        success: false,
        error: 'PRESIGNED_URL_ERROR',
        message: 'Error interno al generar URL de upload',
        requestId
      });
    }
  }
);

app.post('/api/v1/upload/confirm',
  async (req, res) => {
    const requestId = uuidv4();
    
    try {
      const { s3Key } = req.body;

      if (!s3Key) {
        return res.status(400).json({
          success: false,
          error: 'MISSING_S3_KEY',
          message: 'Se requiere s3Key para confirmar el upload',
          requestId
        });
      }

      const command = new GetObjectCommand({
        Bucket: envVars.S3_BUCKET_NAME,
        Key: s3Key
      });

      const response = await s3Client.send(command);
      
      const fileUrl = `https://${envVars.S3_BUCKET_NAME}.s3.${envVars.AWS_REGION}.amazonaws.com/${s3Key}`;

      logger.info('Upload confirmado', {
        requestId,
        s3Key,
        fileSize: response.ContentLength,
        ip: req.ip
      });

      res.status(200).json({
        success: true,
        data: {
          fileUrl,
          s3Key,
          size: response.ContentLength,
          type: response.ContentType,
          uploadedAt: response.LastModified,
          metadata: response.Metadata
        },
        message: 'Upload confirmado exitosamente',
        requestId
      });

    } catch (error) {
      logger.error('Error confirmando upload', {
        requestId,
        error: error.message,
        stack: error.stack,
        ip: req.ip
      });

      if (error.name === 'NoSuchKey') {
        return res.status(404).json({
          success: false,
          error: 'FILE_NOT_FOUND',
          message: 'El archivo no fue encontrado en S3',
          requestId
        });
      }

      res.status(500).json({
        success: false,
        error: 'CONFIRMATION_ERROR',
        message: 'Error interno al confirmar el upload',
        requestId
      });
    }
  }
);

app.post('/api/v1/upload/small',
  uploadLimiter,
  express.raw({ 
    type: ['image/jpeg', 'image/png', 'image/webp', 'application/pdf'],
    limit: '4mb' 
  }),
  async (req, res) => {
    const requestId = uuidv4();
    
    try {
      if (!req.body || req.body.length === 0) {
        return res.status(400).json({
          success: false,
          error: 'MISSING_FILE_DATA',
          message: 'No se recibieron datos del archivo',
          requestId
        });
      }

      const contentType = req.get('content-type');
      const fileName = req.get('x-file-name') || `file-${Date.now()}${ALLOWED_MIME_TYPES[contentType] || ''}`;
      
      if (!ALLOWED_MIME_TYPES[contentType]) {
        return res.status(400).json({
          success: false,
          error: 'INVALID_CONTENT_TYPE',
          message: `Tipo de contenido no permitido: ${contentType}`,
          allowedTypes: Object.keys(ALLOWED_MIME_TYPES),
          requestId
        });
      }

      const s3Key = generateSafeFileName(fileName, contentType);
      
      const command = new PutObjectCommand({
        Bucket: envVars.S3_BUCKET_NAME,
        Key: s3Key,
        Body: req.body,
        ContentType: contentType,
        ServerSideEncryption: 'AES256',
        CacheControl: 'max-age=31536000',
        Metadata: {
          'uploaded-at': new Date().toISOString(),
          'service': 'dermaia-api',
          'original-name': fileName,
          'file-size': req.body.length.toString(),
          'upload-method': 'direct',
          'request-id': requestId
        }
      });

      await s3Client.send(command);
      
      const fileUrl = `https://${envVars.S3_BUCKET_NAME}.s3.${envVars.AWS_REGION}.amazonaws.com/${s3Key}`;

      logger.info('Upload directo exitoso', {
        requestId,
        fileName,
        fileSize: req.body.length,
        contentType,
        s3Key,
        ip: req.ip
      });

      res.status(201).json({
        success: true,
        data: {
          fileUrl,
          fileName,
          size: req.body.length,
          type: contentType,
          uploadedAt: new Date().toISOString(),
          uploadMethod: 'direct'
        },
        message: 'Archivo subido correctamente (método directo)',
        requestId
      });

    } catch (error) {
      logger.error('Error en upload directo', {
        requestId,
        error: error.message,
        stack: error.stack,
        ip: req.ip
      });

      res.status(500).json({
        success: false,
        error: 'DIRECT_UPLOAD_ERROR',
        message: 'Error interno al procesar el archivo',
        requestId
      });
    }
  }
);

app.use((err, req, res, next) => {
  const requestId = uuidv4();
  
  logger.error('Error no controlado', {
    requestId,
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });

  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      success: false,
      error: 'PAYLOAD_TOO_LARGE',
      message: 'El archivo es demasiado grande para upload directo. Usa el endpoint /api/v1/upload/presigned',
      maxDirectSize: '4MB',
      requestId
    });
  }

  if (err.message.includes('CORS')) {
    return res.status(403).json({
      success: false,
      error: 'CORS_ERROR',
      message: 'Origen no permitido',
      requestId
    });
  }

  res.status(500).json({
    success: false,
    error: 'INTERNAL_SERVER_ERROR',
    message: envVars.NODE_ENV === 'production' 
      ? 'Error interno del servidor'
      : err.message,
    requestId
  });
});

app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'NOT_FOUND',
    message: 'Endpoint no encontrado',
    availableEndpoints: [
      'GET /health',
      'POST /api/v1/upload/presigned',
      'POST /api/v1/upload/confirm',
      'POST /api/v1/upload/small'
    ]
  });
});

module.exports = app;