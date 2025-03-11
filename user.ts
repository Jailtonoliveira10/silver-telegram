import { Router } from 'express';
import { logger } from '../utils/logger';
import { authMiddleware } from '../services/auth';
import { users } from '@shared/schema';
import { eq } from 'drizzle-orm';
import { db } from '../db';
import { upload, processProfileImage } from '../services/upload';
import path from 'path';
import fs from 'fs';

const router = Router();

// Ensure uploads directory exists
const uploadsDir = path.join(process.cwd(), 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

/**
 * @swagger
 * /api/user/profile:
 *   get:
 *     tags: [Usuário]
 *     summary: Obtém dados do perfil do usuário
 *     description: Retorna os dados do perfil do usuário autenticado
 *     security:
 *       - BearerAuth: []
 *     responses:
 *       200:
 *         description: Dados do perfil recuperados com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Dados do perfil recuperados com sucesso"
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                     username:
 *                       type: string
 *                     email:
 *                       type: string
 *                     profileImage:
 *                       type: string
 *       401:
 *         description: Usuário não autenticado
 *       404:
 *         description: Usuário não encontrado
 */
router.get('/profile', authMiddleware, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Usuário não autenticado' });
    }

    logger.info('Requisição de perfil recebida', {
      data: {
        userId: req.user.id,
        method: req.method,
        path: req.path
      }
    });

    const user = await db.query.users.findFirst({
      where: eq(users.id, req.user.id)
    });

    if (!user) {
      logger.warn('Usuário não encontrado ao buscar perfil', {
        data: { userId: req.user.id }
      });
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    // Remove senha dos dados retornados
    const { password, ...userWithoutPassword } = user;

    logger.info('Dados do perfil retornados com sucesso', {
      data: { userId: user.id }
    });

    res.json({
      message: 'Dados do perfil recuperados com sucesso',
      user: userWithoutPassword
    });
  } catch (error) {
    logger.error('Erro ao buscar dados do perfil', error as Error);
    res.status(500).json({ error: 'Erro ao buscar dados do perfil' });
  }
});

/**
 * @swagger
 * /api/user/profile/image:
 *   post:
 *     tags: [Usuário]
 *     summary: Faz upload de foto de perfil
 *     description: |
 *       Permite que o usuário faça upload de uma foto de perfil.
 *       - Formatos aceitos: JPG, PNG ou GIF
 *       - Tamanho máximo: 5MB
 *       - A imagem será redimensionada e otimizada automaticamente
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               image:
 *                 type: string
 *                 format: binary
 *     responses:
 *       200:
 *         description: Foto de perfil atualizada com sucesso
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 message:
 *                   type: string
 *                   example: "Foto de perfil atualizada com sucesso"
 *                 user:
 *                   type: object
 *                   properties:
 *                     profileImage:
 *                       type: string
 *       400:
 *         description: Arquivo inválido (formato ou tamanho incorreto)
 *       401:
 *         description: Usuário não autenticado
 */
router.post('/profile/image', authMiddleware, upload.single('image'), async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Usuário não autenticado' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'Nenhuma imagem fornecida' });
    }

    logger.info('Upload de foto de perfil recebido', {
      data: {
        userId: req.user.id,
        filename: req.file.originalname,
        size: req.file.size
      }
    });

    // Processa e salva a imagem
    const filename = await processProfileImage(req.file);

    // Atualiza o usuário com o novo caminho da imagem
    const [updatedUser] = await db
      .update(users)
      .set({ profileImage: filename })
      .where(eq(users.id, req.user.id))
      .returning();

    if (!updatedUser) {
      logger.warn('Usuário não encontrado ao atualizar foto', {
        data: { userId: req.user.id }
      });
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    // Remove senha dos dados retornados
    const { password, ...userWithoutPassword } = updatedUser;

    logger.info('Foto de perfil atualizada com sucesso', {
      data: {
        userId: updatedUser.id,
        filename
      }
    });

    res.json({
      message: 'Foto de perfil atualizada com sucesso',
      user: userWithoutPassword
    });
  } catch (error) {
    logger.error('Erro ao atualizar foto de perfil', error as Error);

    // Remove arquivo temporário em caso de erro
    if (req.file?.path) {
      fs.unlink(req.file.path, (err) => {
        if (err) logger.error('Erro ao remover arquivo temporário', err);
      });
    }

    res.status(500).json({ error: 'Erro ao atualizar foto de perfil' });
  }
});

/**
 * @swagger
 * /api/user/update:
 *   put:
 *     tags: [Usuário]
 *     summary: Atualiza dados do perfil
 *     description: Atualiza os dados do perfil do usuário autenticado
 *     security:
 *       - BearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *             properties:
 *               email:
 *                 type: string
 *                 format: email
 *     responses:
 *       200:
 *         description: Perfil atualizado com sucesso
 *       400:
 *         description: Dados inválidos
 *       401:
 *         description: Usuário não autenticado
 *       404:
 *         description: Usuário não encontrado
 */
router.put('/update', authMiddleware, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: 'Usuário não autenticado' });
    }

    logger.info('Requisição de atualização de perfil recebida', {
      data: {
        userId: req.user.id,
        method: req.method,
        path: req.path,
        updateFields: Object.keys(req.body)
      }
    });

    const { email } = req.body;

    // Validação básica
    if (!email) {
      logger.warn('Dados incompletos na atualização', {
        data: {
          userId: req.user.id,
          missingFields: { email: !email }
        }
      });
      return res.status(400).json({ error: 'Email é obrigatório' });
    }

    // Atualiza o usuário
    const [updatedUser] = await db
      .update(users)
      .set({ email })
      .where(eq(users.id, req.user.id))
      .returning();

    if (!updatedUser) {
      logger.warn('Usuário não encontrado ao atualizar', {
        data: { userId: req.user.id }
      });
      return res.status(404).json({ error: 'Usuário não encontrado' });
    }

    // Remove senha dos dados retornados
    const { password, ...userWithoutPassword } = updatedUser;

    logger.info('Perfil atualizado com sucesso', {
      data: { userId: updatedUser.id }
    });

    res.json({
      message: 'Perfil atualizado com sucesso',
      user: userWithoutPassword
    });
  } catch (error) {
    logger.error('Erro ao atualizar perfil', error as Error);
    res.status(500).json({ error: 'Erro ao atualizar perfil' });
  }
});

export { router as userRouter };