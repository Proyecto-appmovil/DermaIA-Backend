const express = require('express');
const multer = require('multer');
const { S3Client, PutObjectCommand } = require('@aws-sdk/client-s3');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');

require('dotenv').config();



const requiredEnvVars = ['AWS_REGION', 'S3_BUCKET_NAME', 'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY'];
const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
  console.error(`❌ Variables de entorno faltantes: ${missingVars.join(', ')}`);
}

const envVars = {
  NODE_ENV: process.env.NODE_ENV || 'production',
  AWS_REGION: process.env.AWS_REGION || 'us-east-1',
  S3_BUCKET_NAME: process.env.S3_BUCKET_NAME || '',
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID || '',
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY || '',
  ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS || '*',
  MAX_FILE_SIZE_MB: parseInt(process.env.MAX_FILE_SIZE_MB) || 4
};

const logger = {
  info: (message, meta = {}) => console.log(JSON.stringify({ level: 'info', message, ...meta, timestamp: new Date().toISOString() })),
  error: (message, meta = {}) => console.error(JSON.stringify({ level: 'error', message, ...meta, timestamp: new Date().toISOString() })),
  warn: (message, meta = {}) => console.warn(JSON.stringify({ level: 'warn', message, ...meta, timestamp: new Date().toISOString() }))
};

const app = express();

app.set('trust proxy', 1);

app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

const allowedOrigins = envVars.ALLOWED_ORIGINS === '*' ? '*' : envVars.ALLOWED_ORIGINS.split(',').map(origin => origin.trim());

app.use(cors({
  origin: allowedOrigins === '*' ? true : allowedOrigins,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  credentials: true
}));

let s3Client = null;
if (envVars.AWS_ACCESS_KEY_ID && envVars.AWS_SECRET_ACCESS_KEY) {
  try {
    s3Client = new S3Client({
      region: envVars.AWS_REGION,
      credentials: {
        accessKeyId: envVars.AWS_ACCESS_KEY_ID,
        secretAccessKey: envVars.AWS_SECRET_ACCESS_KEY
      },
      maxAttempts: 3,
      retryMode: 'adaptive'
    });
  } catch (error) {
    logger.error('Error creando cliente S3', { error: error.message });
  }
}

const ALLOWED_MIME_TYPES = {
  'image/jpeg': ['.jpg', '.jpeg', '.jpe', '.jfif'],  // ← Múltiples extensiones
  'image/png': ['.png'],
  'image/webp': ['.webp'],
  'application/pdf': ['.pdf']
};

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: envVars.MAX_FILE_SIZE_MB * 1024 * 1024,
    files: 1
  },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_MIME_TYPES[file.mimetype]) {
      const error = new Error(`Tipo de archivo no permitido: ${file.mimetype}`);
      error.code = 'INVALID_FILE_TYPE';
      return cb(error);
    }
    
    if (!allowedExtensions.includes(fileExtension)) {
      const error = new Error(`La extensión ${fileExtension} no es válida para ${file.mimetype}. Extensiones permitidas: ${allowedExtensions.join(', ')}`);
      error.code = 'EXTENSION_MISMATCH';
      return cb(error);
    }
    
    if (!/^[a-zA-Z0-9._-]+$/.test(file.originalname)) {
      const error = new Error('Nombre de archivo inválido');
      error.code = 'INVALID_FILENAME';
      return cb(error);
    }
    
    cb(null, true);
  }
});

const generateSafeFileName = (originalName, mimetype) => {
  const extension = ALLOWED_MIME_TYPES[mimetype];
  const timestamp = Date.now();
  const uuid = uuidv4();
  const datePath = new Date().toISOString().slice(0, 10);
  
  return `uploads/${datePath}/${timestamp}-${uuid}${extension}`;
};

const uploadToS3 = async (buffer, key, contentType, originalName) => {
  if (!s3Client) {
    throw new Error('Cliente S3 no disponible - verificar configuración de AWS');
  }

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
    maxFileSize: `${envVars.MAX_FILE_SIZE_MB}MB`,
    allowedTypes: Object.keys(ALLOWED_MIME_TYPES),
    s3Client: s3Client ? 'configured' : 'not_configured',
    bucket: envVars.S3_BUCKET_NAME ? 'configured' : 'not_configured'
  };

  if (!s3Client || !envVars.S3_BUCKET_NAME) {
    healthCheck.status = 'degraded';
  }

  const statusCode = healthCheck.status === 'healthy' ? 200 : 503;
  res.status(statusCode).json(healthCheck);
});

app.get('/debug', async (req, res) => {
  if (envVars.NODE_ENV === 'production') {
    return res.status(404).json({ error: 'Not found' });
  }

  const debug = {
    env: {
      NODE_ENV: envVars.NODE_ENV,
      AWS_REGION: envVars.AWS_REGION,
      S3_BUCKET_NAME: envVars.S3_BUCKET_NAME,
      AWS_ACCESS_KEY_ID: envVars.AWS_ACCESS_KEY_ID ? `${envVars.AWS_ACCESS_KEY_ID.substring(0, 8)}...` : 'not_set',
      AWS_SECRET_ACCESS_KEY: envVars.AWS_SECRET_ACCESS_KEY ? 'set' : 'not_set',
      ALLOWED_ORIGINS: envVars.ALLOWED_ORIGINS,
      MAX_FILE_SIZE_MB: envVars.MAX_FILE_SIZE_MB
    },
    s3Client: {
      configured: !!s3Client,
      region: s3Client?.config?.region || 'not_set'
    }
  };

  res.json(debug);
});

app.post('/api/v1/upload', 
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

    if (!s3Client || !envVars.S3_BUCKET_NAME) {
      logger.error('Configuración S3 incompleta', { requestId });
      return res.status(500).json({
        success: false,
        error: 'S3_CONFIGURATION_ERROR',
        message: 'Configuración de almacenamiento no disponible',
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
        errorCode: error.code,
        errorName: error.name,
        stack: error.stack,
        fileName: req.file?.originalname,
        fileSize: req.file?.size,
        bucket: envVars.S3_BUCKET_NAME,
        region: envVars.AWS_REGION,
        ip: req.ip
      });

      let statusCode = 500;
      let errorCode = 'UPLOAD_ERROR';
      let message = 'Error interno al procesar el archivo';
      
      if (error.code === 'NoSuchBucket') {
        errorCode = 'S3_CONFIGURATION_ERROR';
        message = `Bucket '${envVars.S3_BUCKET_NAME}' no encontrado`;
      } else if (error.code === 'AccessDenied' || error.name === 'AccessDenied') {
        errorCode = 'S3_PERMISSIONS_ERROR';
        message = 'Error de permisos del servicio de almacenamiento';
      } else if (error.code === 'InvalidAccessKeyId') {
        errorCode = 'S3_CREDENTIALS_ERROR';
        message = 'Credenciales de AWS inválidas';
      } else if (error.code === 'SignatureDoesNotMatch') {
        errorCode = 'S3_SIGNATURE_ERROR';
        message = 'Error de autenticación con AWS';
      } else if (error.message.includes('Cliente S3 no disponible')) {
        errorCode = 'S3_CLIENT_ERROR';
        message = 'Servicio de almacenamiento no disponible';
      } else if (error.name === 'NetworkingError' || error.code === 'ENOTFOUND') {
        errorCode = 'NETWORK_ERROR';
        message = 'Error de conectividad de red';
      }

      res.status(statusCode).json({
        success: false,
        error: errorCode,
        message,
        requestId,
        ...(envVars.NODE_ENV !== 'production' && {
          debug: {
            originalError: error.message,
            errorCode: error.code,
            errorName: error.name
          }
        })
      });
    }
  }
);

app.use((err, req, res, next) => {
  const requestId = uuidv4();
  
  logger.error('Error no controlado', {
    requestId,
    error: err.message,
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

  if (err.message && err.message.includes('CORS')) {
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
    message: 'Error interno del servidor',
    requestId
  });
});

app.use((req, res) => {
  res.status(200).json({
    success: true,
    message: 'Trabajando sobre el puerto 3000. API de DermaIA funcionando correctamente.'
  });
});

module.exports = app;