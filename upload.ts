import multer from 'multer';
import path from 'path';
import sharp from 'sharp';
import { logger } from '../utils/logger';

// Configure multer for handling file uploads
const storage = multer.memoryStorage();

// Configure file filter to allow only images
const fileFilter = (req: any, file: Express.Multer.File, cb: multer.FileFilterCallback) => {
  const allowedMimes = ['image/jpeg', 'image/png', 'image/gif'];
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Formato de arquivo inválido. Use JPEG, PNG ou GIF'));
  }
};

export const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB
  }
});

// Process and save the uploaded image
export async function processProfileImage(file: Express.Multer.File): Promise<string> {
  try {
    const filename = `${Date.now()}-${Math.round(Math.random() * 1E9)}${path.extname(file.originalname)}`;
    const uploadPath = path.join(process.cwd(), 'uploads', filename);

    // Process image with sharp
    await sharp(file.buffer)
      .resize(300, 300, {
        fit: 'cover',
        position: 'center'
      })
      .toFile(uploadPath);

    logger.info('Imagem de perfil processada com sucesso', {
      data: { filename }
    });

    return filename;
  } catch (error) {
    logger.error('Erro ao processar imagem de perfil');
    throw error;
  }
}
