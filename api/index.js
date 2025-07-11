const express = require('express');
const multer = require('multer');
const aws = require('aws-sdk');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const dotenv = require('dotenv');
const cors = require('cors');


// Cargar variables de entorno
dotenv.config();

// Verificar que las variables de entorno están cargadas
console.log('Verificando variables de entorno:', {
  AWS_REGION: process.env.AWS_REGION,
  S3_BUCKET_NAME: process.env.S3_BUCKET_NAME,
  HAS_AWS_ACCESS_KEY: !!process.env.AWS_ACCESS_KEY_ID,
  HAS_AWS_SECRET_KEY: !!process.env.AWS_SECRET_ACCESS_KEY
});

// Configuración de la aplicación Express
const app = express();
const port = 3000;

// Habilitar CORS
app.use(cors({
  origin: ['https://derma-ia-front.vercel.app', 'http://localhost:8100'],
  methods: ['GET', 'POST'],
  credentials: true
}));

// Configuración de AWS S3
const s3 = new aws.S3({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
});

// Configuración de Multer para almacenamiento en memoria
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 5 * 1024 * 1024, // límite de 5MB
  },
  fileFilter: (req, file, cb) => {
    // Aceptar todos los tipos de archivo
    cb(null, true);
  }
});

// Ruta para subir archivos
app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No se ha proporcionado ningún archivo' });
    }

    // Generar un nombre único para el archivo
    const fileExtension = path.extname(req.file.originalname);
    const fileName = `${uuidv4()}${fileExtension}`;

    // Parámetros para la subida a S3
    const uploadParams = {
      Bucket: process.env.S3_BUCKET_NAME,
      Key: fileName,
      Body: req.file.buffer,
      ContentType: req.file.mimetype
    };

    // Subir archivo a S3
    const uploadResult = await s3.upload(uploadParams).promise();

    // Devolver la URL del archivo
    res.json({
      message: 'Archivo subido correctamente',
      fileUrl: uploadResult.Location
    });

  } catch (error) {
    console.error('Error al subir el archivo:', error);
    res.status(500).json({
      error: 'Error al subir el archivo',
      details: error.message
    });
  }
});

// Ruta de prueba
app.get('/', (req, res) => {
  res.json({ message: 'API de subida de archivos funcionando correctamente' });
});

// Manejo de errores
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        error: 'El archivo es demasiado grande. El tamaño máximo permitido es 5MB'
      });
    }
    return res.status(400).json({ error: err.message });
  }
  console.error('Error no manejado:', err);
  res.status(500).json({ error: 'Error interno del servidor' });
});

// Iniciar el servidor
app.listen(port, () => {
  console.log(`Servidor corriendo en http://localhost:${port}`);
});