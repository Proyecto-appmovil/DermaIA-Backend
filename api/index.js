const express = require('express');
const multer = require('multer');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
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
  UPLOAD_RATE_LIMIT_MAX: joi.number().default(10)
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
  legacyHeaders: false,
  handler: (req, res) => {
    logger.warn('Rate limit excedido', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl
    });
    res.status(429).json({
      success: false,
      error: 'RATE_LIMIT_EXCEEDED',
      message: `Demasiadas solicitudes. Máximo ${envVars.UPLOAD_RATE_LIMIT_MAX} uploads cada ${Math.floor(envVars.UPLOAD_RATE_LIMIT_WINDOW_MS / 1000 / 60)} minutos.`,
      retryAfter: Math.floor(envVars.UPLOAD_RATE_LIMIT_WINDOW_MS / 1000)
    });
  }
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
  methods: ['GET', 'POST', 'OPTIONS'],
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

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: envVars.MAX_FILE_SIZE_MB * 1024 * 1024,
    files: 1,
    fieldSize: 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_MIME_TYPES[file.mimetype]) {
      const error = new Error(`Tipo de archivo no permitido: ${file.mimetype}`);
      error.code = 'INVALID_FILE_TYPE';
      return cb(error);
    }
    
    const fileExtension = path.extname(file.originalname).toLowerCase();
    if (fileExtension !== ALLOWED_MIME_TYPES[file.mimetype]) {
      const error = new Error('La extensión del archivo no coincide con su tipo');
      error.code = 'EXTENSION_MISMATCH';
      return cb(error);
    }
    
    if (!/^[a-zA-Z0-9._-]+$/.test(file.originalname)) {
      const error = new Error('Nombre de archivo inválido. Solo se permiten letras, números, puntos, guiones y guiones bajos.');
      error.code = 'INVALID_FILENAME';
      return cb(error);
    }
    
    cb(null, true);
  }
});

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

const generateSafeFileName = (originalName, mimetype) => {
  const extension = ALLOWED_MIME_TYPES[mimetype];
  const timestamp = Date.now();
  const uuid = uuidv4();
  const datePath = new Date().toISOString().slice(0, 10);
  
  return `uploads/${datePath}/${timestamp}-${uuid}${extension}`;
};

const uploadToS3 = async (buffer, key, contentType, originalName) => {
  const command = new PutObjectCommand({
    Bucket: envVars.S3_BUCKET_NAME,
    Key: key,
    Body: buffer,
    ContentType: contentType,
    ServerSideEncryption: 'AES256',
    CacheControl: 'max-age=31536000',
    Metadata: {
      'uploaded-at': new Date().toISOString(),
      'service': 'dermaia-api',
      'original-name': originalName,
      'file-size': buffer.length.toString()
    }
  });

  return await s3Client.send(command);
};

app.get('/health', async (req, res) => {
  const healthCheck = {
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: envVars.NODE_ENV,
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

app.post('/api/v1/upload', 
  uploadLimiter,
  upload.single('file'),
  async (req, res) => {
    const requestId = uuidv4();
    
    if (!req.file) {
      logger.warn('Upload sin archivo', { requestId, ip: req.ip });
      return res.status(400).json({
        success: false,
        error: 'MISSING_FILE',
        message: 'No se ha proporcionado ningún archivo',
        requestId
      });
    }
    
    try {
      logger.info('Iniciando upload', {
        requestId,
        fileName: req.file.originalname,
        fileSize: req.file.size,
        mimetype: req.file.mimetype,
        ip: req.ip
      });

      const s3Key = generateSafeFileName(req.file.originalname, req.file.mimetype);
      
      await uploadToS3(req.file.buffer, s3Key, req.file.mimetype, req.file.originalname);

      const fileUrl = `https://${envVars.S3_BUCKET_NAME}.s3.${envVars.AWS_REGION}.amazonaws.com/${s3Key}`;

      logger.info('Upload exitoso', {
        requestId,
        s3Key,
        fileUrl,
        fileSize: req.file.size
      });

      res.status(201).json({
        success: true,
        data: {
          fileUrl,
          fileName: req.file.originalname,
          size: req.file.size,
          type: req.file.mimetype,
          uploadedAt: new Date().toISOString()
        },
        message: 'Archivo subido correctamente'
      });

    } catch (error) {
      logger.error('Error en upload', {
        requestId,
        error: error.message,
        stack: error.stack,
        fileName: req.file?.originalname,
        ip: req.ip
      });

      let statusCode = 500;
      let errorCode = 'UPLOAD_ERROR';
      let message = 'Error interno al procesar el archivo';
      
      if (error.code === 'NoSuchBucket') {
        errorCode = 'S3_CONFIGURATION_ERROR';
        message = 'Error de configuración del servicio de almacenamiento';
      } else if (error.code === 'AccessDenied') {
        errorCode = 'S3_PERMISSIONS_ERROR';
        message = 'Error de permisos del servicio de almacenamiento';
      } else if (error.name === 'TimeoutError') {
        errorCode = 'TIMEOUT_ERROR';
        message = 'Tiempo de espera agotado. Intenta con un archivo más pequeño.';
      }

      res.status(statusCode).json({
        success: false,
        error: errorCode,
        message,
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

  if (err instanceof multer.MulterError) {
    let message = 'Error al procesar el archivo';
    let errorCode = 'MULTER_ERROR';
    
    switch (err.code) {
      case 'LIMIT_FILE_SIZE':
        message = `Archivo demasiado grande. Tamaño máximo: ${envVars.MAX_FILE_SIZE_MB}MB`;
        errorCode = 'FILE_TOO_LARGE';
        break;
      case 'LIMIT_FILE_COUNT':
        message = 'Demasiados archivos';
        errorCode = 'TOO_MANY_FILES';
        break;
      case 'LIMIT_UNEXPECTED_FILE':
        message = 'Campo de archivo inesperado';
        errorCode = 'UNEXPECTED_FILE';
        break;
    }
    
    return res.status(400).json({
      success: false,
      error: errorCode,
      message,
      requestId
    });
  }

  if (err.code === 'INVALID_FILE_TYPE' || err.code === 'EXTENSION_MISMATCH' || err.code === 'INVALID_FILENAME') {
    return res.status(400).json({
      success: false,
      error: err.code,
      message: err.message,
      allowedTypes: Object.keys(ALLOWED_MIME_TYPES),
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
  logger.warn('Endpoint no encontrado', {
    url: req.originalUrl,
    method: req.method,
    ip: req.ip
  });
  
  res.status(404).json({
    success: false,
    error: 'NOT_FOUND',
    message: 'Endpoint no encontrado'
  });
});

module.exports = app;