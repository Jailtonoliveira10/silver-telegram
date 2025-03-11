var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// server/index.ts
import dotenv from "dotenv";
import express2 from "express";
import path5 from "path";
import fs3 from "fs";

// server/utils/logger.ts
import { format } from "date-fns";
function formatTime() {
  return format(/* @__PURE__ */ new Date(), "HH:mm:ss");
}
function formatMessage(level, message, options2 = {}) {
  const time = formatTime();
  const source = options2.source ? `[${options2.source}]` : "";
  const data = options2.data ? `
${JSON.stringify(options2.data, null, 2)}` : "";
  return `${time} ${source} ${level.toUpperCase()}: ${message}${data}`;
}
function info(message, options2) {
  console.log(formatMessage("info", message, options2));
}
function warn(message, options2) {
  console.warn(formatMessage("warn", message, options2));
}
function error(message, error2, options2) {
  const errorData = error2 ? {
    message: error2.message,
    stack: error2.stack,
    ...options2?.data
  } : options2?.data;
  console.error(formatMessage("error", message, { ...options2, data: errorData }));
}
function debug(message, options2) {
  if (process.env.NODE_ENV === "development") {
    console.debug(formatMessage("debug", message, options2));
  }
}
var logger = {
  info,
  warn,
  error,
  debug
};

// server/routes/auth.ts
import { Router } from "express";
import passport from "passport";

// shared/schema.ts
var schema_exports = {};
__export(schema_exports, {
  alertPreferencesSchema: () => alertPreferencesSchema,
  blacklistedTokens: () => blacklistedTokens,
  insertBlacklistedTokenSchema: () => insertBlacklistedTokenSchema,
  insertUserSchema: () => insertUserSchema,
  players: () => players,
  profileImageSchema: () => profileImageSchema,
  users: () => users
});
import { pgTable, text, serial, integer, boolean, jsonb, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";
var users = pgTable("users", {
  id: serial("id").primaryKey(),
  username: text("username").notNull().unique(),
  password: text("password").notNull(),
  email: text("email").notNull(),
  googleId: text("google_id").unique(),
  displayName: text("display_name"),
  profileImage: text("profile_image"),
  resetToken: text("reset_token"),
  resetTokenExpiresAt: timestamp("reset_token_expires_at"),
  twoFactorSecret: text("two_factor_secret"),
  twoFactorEnabled: boolean("two_factor_enabled").default(false).notNull(),
  backupCodes: jsonb("backup_codes").default([]),
  alertPreferences: jsonb("alert_preferences").default({
    positions: [],
    minMarketValue: 0,
    maxMarketValue: 1e8,
    ageRange: [16, 40],
    notificationEnabled: true,
    whatsappNumber: "",
    whatsappEnabled: false,
    alertTypes: {
      marketValue: true,
      performance: true,
      injury: true,
      transfer: true
    }
  }).notNull()
});
var blacklistedTokens = pgTable("blacklisted_tokens", {
  id: serial("id").primaryKey(),
  token: text("token").notNull().unique(),
  expiresAt: timestamp("expires_at").notNull(),
  blacklistedAt: timestamp("blacklisted_at").defaultNow().notNull()
});
var players = pgTable("players", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  position: text("position").notNull(),
  age: integer("age").notNull(),
  nationality: text("nationality").notNull(),
  club: text("club").notNull(),
  marketValue: integer("market_value").notNull(),
  stats: jsonb("stats").notNull()
});
var insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  email: true,
  googleId: true,
  displayName: true
});
var alertPreferencesSchema = z.object({
  positions: z.array(z.string()),
  minMarketValue: z.number(),
  maxMarketValue: z.number(),
  ageRange: z.tuple([z.number(), z.number()]),
  notificationEnabled: z.boolean(),
  whatsappNumber: z.string(),
  whatsappEnabled: z.boolean(),
  alertTypes: z.object({
    marketValue: z.boolean(),
    performance: z.boolean(),
    injury: z.boolean(),
    transfer: z.boolean()
  })
});
var profileImageSchema = z.object({
  file: z.any().refine((file) => file?.size <= 5e6, "O arquivo deve ter no m\xE1ximo 5MB").refine(
    (file) => ["image/jpeg", "image/png", "image/gif"].includes(file?.type),
    "Formato de arquivo inv\xE1lido. Use JPEG, PNG ou GIF"
  )
});
var insertBlacklistedTokenSchema = createInsertSchema(blacklistedTokens).pick({
  token: true,
  expiresAt: true
});

// server/services/auth.ts
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";

// server/db.ts
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";
if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL environment variable must be set");
}
var client = postgres(process.env.DATABASE_URL);
var db = drizzle(client, { schema: schema_exports });

// server/services/auth.ts
import { eq } from "drizzle-orm";
async function hashPassword(password) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}
async function verifyPassword(password, hashedPassword) {
  return bcrypt.compare(password, hashedPassword);
}
function extractTokenFromHeader(authHeader) {
  const [scheme, token] = authHeader.split(" ");
  if (!token || scheme !== "Bearer") {
    return null;
  }
  return token;
}
function generateToken(user) {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET environment variable must be set");
  }
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "24h" }
  );
}
async function blacklistToken(token) {
  try {
    const decoded = jwt.decode(token);
    if (!decoded?.exp) {
      throw new Error("Token inv\xE1lido");
    }
    await db.insert(blacklistedTokens).values({
      token,
      expiresAt: new Date(decoded.exp * 1e3)
    });
    logger.info("Token adicionado \xE0 lista negra com sucesso");
  } catch (error2) {
    logger.error("Erro ao adicionar token \xE0 lista negra");
    throw error2;
  }
}
async function isTokenBlacklisted(token) {
  try {
    const blacklistedToken = await db.query.blacklistedTokens.findFirst({
      where: eq(blacklistedTokens.token, token)
    });
    return !!blacklistedToken;
  } catch (error2) {
    logger.error("Erro ao verificar token na lista negra");
    throw error2;
  }
}
async function verifyToken(token) {
  if (!process.env.JWT_SECRET) {
    throw new Error("JWT_SECRET environment variable must be set");
  }
  try {
    const isBlacklisted = await isTokenBlacklisted(token);
    if (isBlacklisted) {
      return null;
    }
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error2) {
    return null;
  }
}
async function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    logger.warn("Token n\xE3o fornecido", {
      data: { path: req.path }
    });
    return res.status(401).json({
      error: "Acesso negado",
      message: "Token n\xE3o fornecido"
    });
  }
  const token = extractTokenFromHeader(authHeader);
  if (!token) {
    logger.warn("Formato de token inv\xE1lido", {
      data: { path: req.path }
    });
    return res.status(401).json({
      error: "Acesso negado",
      message: "Formato de token inv\xE1lido"
    });
  }
  try {
    const decoded = await verifyToken(token);
    if (!decoded) {
      logger.warn("Token inv\xE1lido, expirado ou revogado", {
        data: { path: req.path }
      });
      return res.status(401).json({
        error: "Acesso negado",
        message: "Token inv\xE1lido, expirado ou revogado"
      });
    }
    req.user = decoded;
    logger.info("Token verificado com sucesso", {
      data: {
        userId: decoded.id,
        username: decoded.username,
        path: req.path
      }
    });
    next();
  } catch (error2) {
    logger.error("Erro ao verificar token");
    return res.status(500).json({
      error: "Erro interno",
      message: "Erro ao verificar token"
    });
  }
}

// server/routes/auth.ts
import { eq as eq2 } from "drizzle-orm";
import crypto from "crypto";

// server/services/email.ts
async function sendPasswordResetEmail(to, resetToken) {
  try {
    const resetLink = `${process.env.APP_URL || "http://localhost:5000"}/reset-password?token=${resetToken}`;
    logger.info("Simulando envio de email de recupera\xE7\xE3o de senha", {
      source: "email",
      data: {
        to,
        resetLink,
        subject: "Recupera\xE7\xE3o de Senha - Elite Scouting Network"
      }
    });
    logger.info("Email de recupera\xE7\xE3o de senha simulado com sucesso", {
      source: "email",
      data: { to }
    });
    return true;
  } catch (error2) {
    logger.error("Erro ao simular envio de email de recupera\xE7\xE3o de senha", error2, {
      source: "email",
      data: { to }
    });
    return false;
  }
}
async function send2FAConfirmationEmail(to, confirmToken, type) {
  try {
    const confirmLink = `${process.env.APP_URL || "http://localhost:5000"}/settings/2fa/confirm?token=${confirmToken}&type=${type}`;
    const subjects = {
      enable: "Confirmar Ativa\xE7\xE3o do 2FA",
      disable: "Confirmar Desativa\xE7\xE3o do 2FA",
      backup_codes: "Confirmar Gera\xE7\xE3o de C\xF3digos de Backup 2FA"
    };
    const messages = {
      enable: "confirmar a ativa\xE7\xE3o da autentica\xE7\xE3o de dois fatores",
      disable: "confirmar a desativa\xE7\xE3o da autentica\xE7\xE3o de dois fatores",
      backup_codes: "gerar novos c\xF3digos de backup para autentica\xE7\xE3o de dois fatores"
    };
    logger.info("Simulando envio de email de confirma\xE7\xE3o 2FA", {
      source: "email",
      data: {
        to,
        confirmLink,
        subject: subjects[type],
        type
      }
    });
    logger.info("Email de confirma\xE7\xE3o 2FA simulado com sucesso", {
      source: "email",
      data: { to, type }
    });
    return true;
  } catch (error2) {
    logger.error("Erro ao simular envio de email de confirma\xE7\xE3o 2FA", error2, {
      source: "email",
      data: { to, type }
    });
    return false;
  }
}

// server/routes/auth.ts
import speakeasy from "speakeasy";
import QRCode from "qrcode";
var router = Router();
router.get(
  "/google",
  passport.authenticate("google", {
    scope: ["email", "profile"],
    prompt: "select_account"
  })
);
router.get(
  "/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/auth",
    failureMessage: true
  }),
  (req, res) => {
    logger.info("Login com Google bem-sucedido", {
      data: {
        userId: req.user?.id,
        email: req.user?.email
      }
    });
    const token = generateToken(req.user);
    res.redirect(`/?token=${token}`);
  }
);
router.post("/register", async (req, res) => {
  try {
    logger.info("Tentativa de registro recebida", {
      data: {
        username: req.body.username,
        email: req.body.email,
        method: req.method,
        path: req.path
      }
    });
    const { username, password, email } = req.body;
    if (!username || !password || !email) {
      logger.warn("Dados incompletos no registro", {
        data: {
          missingFields: {
            username: !username,
            password: !password,
            email: !email
          }
        }
      });
      return res.status(400).json({ error: "Todos os campos s\xE3o obrigat\xF3rios" });
    }
    const existingUser = await db.query.users.findFirst({
      where: eq2(users.username, username)
    });
    if (existingUser) {
      logger.warn("Tentativa de registro com username existente", {
        data: { username }
      });
      return res.status(409).json({ error: "Usu\xE1rio j\xE1 existe" });
    }
    const hashedPassword = await hashPassword(password);
    const [newUser] = await db.insert(users).values({
      username,
      password: hashedPassword,
      email,
      alertPreferences: {
        positions: [],
        minMarketValue: 0,
        maxMarketValue: 1e8,
        ageRange: [16, 40],
        notificationEnabled: true,
        whatsappNumber: "",
        whatsappEnabled: false,
        alertTypes: {
          marketValue: true,
          performance: true,
          injury: true,
          transfer: true
        }
      }
    }).returning();
    const token = generateToken(newUser);
    logger.info("Novo usu\xE1rio registrado com sucesso", {
      data: {
        username,
        id: newUser.id,
        statusCode: 201
      }
    });
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "POST");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.header("Content-Type", "application/json");
    res.status(201).json({
      message: "Usu\xE1rio registrado com sucesso",
      token
    });
  } catch (err) {
    const error2 = err;
    logger.error("Erro ao registrar usu\xE1rio", error2);
    res.status(500).json({ error: "Erro ao registrar usu\xE1rio" });
  }
});
router.post("/login", async (req, res) => {
  try {
    logger.info("Tentativa de login recebida", {
      data: {
        username: req.body.username,
        method: req.method,
        path: req.path
      }
    });
    const { username, password } = req.body;
    if (!username || !password) {
      logger.warn("Dados incompletos no login", {
        data: {
          missingFields: {
            username: !username,
            password: !password
          }
        }
      });
      return res.status(400).json({ error: "Username e senha s\xE3o obrigat\xF3rios" });
    }
    const user = await db.query.users.findFirst({
      where: eq2(users.username, username)
    });
    if (!user) {
      logger.warn("Tentativa de login com usu\xE1rio inexistente", {
        data: { username }
      });
      return res.status(401).json({ error: "Credenciais inv\xE1lidas" });
    }
    const isValidPassword = await verifyPassword(password, user.password);
    if (!isValidPassword) {
      logger.warn("Tentativa de login com senha incorreta", {
        data: { username }
      });
      return res.status(401).json({ error: "Credenciais inv\xE1lidas" });
    }
    const token = generateToken(user);
    logger.info("Login realizado com sucesso", {
      data: {
        username,
        id: user.id
      }
    });
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Methods", "POST");
    res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.header("Content-Type", "application/json");
    res.json({
      message: "Login realizado com sucesso",
      token
    });
  } catch (err) {
    const error2 = err;
    logger.error("Erro ao fazer login", error2);
    res.status(500).json({ error: "Erro ao fazer login" });
  }
});
router.get("/me", authMiddleware, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: "Usu\xE1rio n\xE3o autenticado" });
    }
    const user = await db.query.users.findFirst({
      where: eq2(users.id, req.user.id)
    });
    if (!user) {
      return res.status(404).json({ error: "Usu\xE1rio n\xE3o encontrado" });
    }
    const { password, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
  } catch (err) {
    const error2 = err;
    logger.error("Erro ao buscar usu\xE1rio", error2);
    res.status(500).json({ error: "Erro ao buscar usu\xE1rio" });
  }
});
router.post("/forgot-password", async (req, res) => {
  try {
    logger.info("Requisi\xE7\xE3o de recupera\xE7\xE3o de senha recebida", {
      data: {
        email: req.body.email,
        method: req.method,
        path: req.path
      }
    });
    const { email } = req.body;
    if (!email) {
      logger.warn("Email n\xE3o fornecido", {
        data: { path: req.path }
      });
      return res.status(400).json({ error: "Email \xE9 obrigat\xF3rio" });
    }
    const user = await db.query.users.findFirst({
      where: eq2(users.email, email)
    });
    if (!user) {
      logger.warn("Email n\xE3o encontrado ao solicitar recupera\xE7\xE3o", {
        data: { email }
      });
      return res.status(404).json({ error: "Email n\xE3o encontrado" });
    }
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetTokenExpiresAt = new Date(Date.now() + 36e5);
    await db.update(users).set({
      resetToken,
      resetTokenExpiresAt
    }).where(eq2(users.id, user.id));
    const emailSent = await sendPasswordResetEmail(email, resetToken);
    if (!emailSent) {
      logger.error("Erro ao enviar email de recupera\xE7\xE3o");
      return res.status(500).json({ error: "Erro ao enviar email de recupera\xE7\xE3o" });
    }
    logger.info("Email de recupera\xE7\xE3o enviado com sucesso", {
      data: { email }
    });
    res.json({ message: "Email de recupera\xE7\xE3o enviado com sucesso" });
  } catch (err) {
    const error2 = err;
    logger.error("Erro ao processar recupera\xE7\xE3o de senha", error2);
    res.status(500).json({ error: "Erro ao processar recupera\xE7\xE3o de senha" });
  }
});
router.post("/reset-password", async (req, res) => {
  try {
    logger.info("Requisi\xE7\xE3o de redefini\xE7\xE3o de senha recebida", {
      data: {
        method: req.method,
        path: req.path
      }
    });
    const { token, password } = req.body;
    if (!token || !password) {
      logger.warn("Dados incompletos na redefini\xE7\xE3o", {
        data: {
          missingFields: {
            token: !token,
            password: !password
          }
        }
      });
      return res.status(400).json({ error: "Token e senha s\xE3o obrigat\xF3rios" });
    }
    const user = await db.query.users.findFirst({
      where: eq2(users.resetToken, token)
    });
    if (!user || !user.resetTokenExpiresAt || user.resetTokenExpiresAt < /* @__PURE__ */ new Date()) {
      logger.warn("Token inv\xE1lido ou expirado", {
        data: { token }
      });
      return res.status(400).json({ error: "Token inv\xE1lido ou expirado" });
    }
    const hashedPassword = await hashPassword(password);
    await db.update(users).set({
      password: hashedPassword,
      resetToken: null,
      resetTokenExpiresAt: null
    }).where(eq2(users.id, user.id));
    logger.info("Senha redefinida com sucesso", {
      data: { userId: user.id }
    });
    res.json({ message: "Senha redefinida com sucesso" });
  } catch (err) {
    const error2 = err;
    logger.error("Erro ao redefinir senha", error2);
    res.status(500).json({ error: "Erro ao redefinir senha" });
  }
});
router.post("/logout", authMiddleware, async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: "Token n\xE3o fornecido" });
    }
    const token = extractTokenFromHeader(authHeader);
    if (!token) {
      return res.status(401).json({ error: "Token inv\xE1lido" });
    }
    await blacklistToken(token);
    logger.info("Logout realizado com sucesso", {
      data: {
        userId: req.user?.id,
        username: req.user?.username
      }
    });
    res.json({ message: "Logout realizado com sucesso" });
  } catch (error2) {
    logger.error("Erro ao realizar logout");
    res.status(500).json({ error: "Erro ao realizar logout" });
  }
});
router.get("/protected-test", authMiddleware, (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: "Usu\xE1rio n\xE3o autenticado" });
    }
    logger.info("Acesso a rota protegida bem-sucedido", {
      data: {
        userId: req.user.id,
        username: req.user.username,
        method: req.method,
        path: req.path
      }
    });
    res.json({
      message: "Acesso permitido \xE0 rota protegida",
      user: {
        id: req.user.id,
        username: req.user.username
      }
    });
  } catch (err) {
    const error2 = err;
    logger.error("Erro ao acessar rota protegida", error2);
    res.status(500).json({ error: "Erro ao acessar rota protegida" });
  }
});
router.post("/2fa/enable", authMiddleware, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: "Usu\xE1rio n\xE3o autenticado" });
    }
    const confirmToken = crypto.randomBytes(32).toString("hex");
    const confirmTokenExpiresAt = new Date(Date.now() + 36e5);
    await db.update(users).set({
      twoFactorConfirmToken: confirmToken,
      twoFactorConfirmTokenExpiresAt: confirmTokenExpiresAt
    }).where(eq2(users.id, req.user.id));
    const emailSent = await send2FAConfirmationEmail(
      req.user.email,
      confirmToken,
      "enable"
    );
    if (!emailSent) {
      return res.status(500).json({ error: "Erro ao enviar email de confirma\xE7\xE3o" });
    }
    logger.info("Email de confirma\xE7\xE3o 2FA enviado", {
      data: {
        userId: req.user.id,
        email: req.user.email
      }
    });
    res.json({ message: "Email de confirma\xE7\xE3o enviado. Por favor, verifique sua caixa de entrada." });
  } catch (err) {
    const error2 = err;
    logger.error("Erro ao processar solicita\xE7\xE3o de ativa\xE7\xE3o 2FA", error2);
    res.status(500).json({ error: "Erro ao processar solicita\xE7\xE3o de ativa\xE7\xE3o 2FA" });
  }
});
router.post("/2fa/confirm", authMiddleware, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: "Usu\xE1rio n\xE3o autenticado" });
    }
    const { token, type } = req.body;
    const user = await db.query.users.findFirst({
      where: eq2(users.id, req.user.id)
    });
    if (!user?.twoFactorConfirmToken || user.twoFactorConfirmToken !== token || !user.twoFactorConfirmTokenExpiresAt || user.twoFactorConfirmTokenExpiresAt < /* @__PURE__ */ new Date()) {
      return res.status(400).json({ error: "Token inv\xE1lido ou expirado" });
    }
    const secret = speakeasy.generateSecret({
      name: `ESN:${user.email}`
    });
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
    await db.update(users).set({
      twoFactorSecret: secret.base32,
      twoFactorEnabled: true,
      //Enable 2FA after confirmation
      twoFactorConfirmToken: null,
      twoFactorConfirmTokenExpiresAt: null
    }).where(eq2(users.id, req.user.id));
    logger.info("Configura\xE7\xE3o 2FA confirmada via email", {
      data: {
        userId: req.user.id,
        email: req.user.email,
        type
      }
    });
    res.json({
      secret: secret.base32,
      qrCodeUrl
    });
  } catch (err) {
    const error2 = err;
    logger.error("Erro ao confirmar configura\xE7\xE3o 2FA", error2);
    res.status(500).json({ error: "Erro ao confirmar configura\xE7\xE3o 2FA" });
  }
});
router.post("/2fa/validate", async (req, res) => {
  try {
    const { userId, token } = req.body;
    const user = await db.query.users.findFirst({
      where: eq2(users.id, userId)
    });
    if (!user?.twoFactorSecret || !user?.twoFactorEnabled) {
      return res.status(400).json({ error: "2FA n\xE3o est\xE1 ativo para este usu\xE1rio" });
    }
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: "base32",
      token
    });
    if (!verified) {
      return res.status(401).json({ error: "C\xF3digo inv\xE1lido" });
    }
    const jwtToken = generateToken(user);
    logger.info("Valida\xE7\xE3o 2FA bem-sucedida", {
      data: {
        userId: user.id,
        email: user.email
      }
    });
    res.json({
      message: "C\xF3digo 2FA validado com sucesso",
      token: jwtToken
    });
  } catch (err) {
    const error2 = err;
    logger.error("Erro ao validar c\xF3digo 2FA", error2);
    res.status(500).json({ error: "Erro ao validar c\xF3digo 2FA" });
  }
});
router.post("/2fa/disable", authMiddleware, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: "Usu\xE1rio n\xE3o autenticado" });
    }
    await db.update(users).set({
      twoFactorSecret: null,
      twoFactorEnabled: false
    }).where(eq2(users.id, req.user.id));
    logger.info("2FA desativado com sucesso", {
      data: {
        userId: req.user.id,
        email: req.user.email
      }
    });
    res.json({ message: "2FA desativado com sucesso" });
  } catch (err) {
    const error2 = err;
    logger.error("Erro ao desativar 2FA", error2);
    res.status(500).json({ error: "Erro ao desativar 2FA" });
  }
});

// server/routes/user.ts
import { Router as Router2 } from "express";
import { eq as eq3 } from "drizzle-orm";

// server/services/upload.ts
import multer from "multer";
import path from "path";
import sharp from "sharp";
var storage = multer.memoryStorage();
var fileFilter = (req, file, cb) => {
  const allowedMimes = ["image/jpeg", "image/png", "image/gif"];
  if (allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("Formato de arquivo inv\xE1lido. Use JPEG, PNG ou GIF"));
  }
};
var upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024
    // 5MB
  }
});
async function processProfileImage(file) {
  try {
    const filename = `${Date.now()}-${Math.round(Math.random() * 1e9)}${path.extname(file.originalname)}`;
    const uploadPath = path.join(process.cwd(), "uploads", filename);
    await sharp(file.buffer).resize(300, 300, {
      fit: "cover",
      position: "center"
    }).toFile(uploadPath);
    logger.info("Imagem de perfil processada com sucesso", {
      data: { filename }
    });
    return filename;
  } catch (error2) {
    logger.error("Erro ao processar imagem de perfil");
    throw error2;
  }
}

// server/routes/user.ts
import path2 from "path";
import fs from "fs";
var router2 = Router2();
var uploadsDir = path2.join(process.cwd(), "uploads");
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
router2.get("/profile", authMiddleware, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: "Usu\xE1rio n\xE3o autenticado" });
    }
    logger.info("Requisi\xE7\xE3o de perfil recebida", {
      data: {
        userId: req.user.id,
        method: req.method,
        path: req.path
      }
    });
    const user = await db.query.users.findFirst({
      where: eq3(users.id, req.user.id)
    });
    if (!user) {
      logger.warn("Usu\xE1rio n\xE3o encontrado ao buscar perfil", {
        data: { userId: req.user.id }
      });
      return res.status(404).json({ error: "Usu\xE1rio n\xE3o encontrado" });
    }
    const { password, ...userWithoutPassword } = user;
    logger.info("Dados do perfil retornados com sucesso", {
      data: { userId: user.id }
    });
    res.json({
      message: "Dados do perfil recuperados com sucesso",
      user: userWithoutPassword
    });
  } catch (error2) {
    logger.error("Erro ao buscar dados do perfil", error2);
    res.status(500).json({ error: "Erro ao buscar dados do perfil" });
  }
});
router2.post("/profile/image", authMiddleware, upload.single("image"), async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: "Usu\xE1rio n\xE3o autenticado" });
    }
    if (!req.file) {
      return res.status(400).json({ error: "Nenhuma imagem fornecida" });
    }
    logger.info("Upload de foto de perfil recebido", {
      data: {
        userId: req.user.id,
        filename: req.file.originalname,
        size: req.file.size
      }
    });
    const filename = await processProfileImage(req.file);
    const [updatedUser] = await db.update(users).set({ profileImage: filename }).where(eq3(users.id, req.user.id)).returning();
    if (!updatedUser) {
      logger.warn("Usu\xE1rio n\xE3o encontrado ao atualizar foto", {
        data: { userId: req.user.id }
      });
      return res.status(404).json({ error: "Usu\xE1rio n\xE3o encontrado" });
    }
    const { password, ...userWithoutPassword } = updatedUser;
    logger.info("Foto de perfil atualizada com sucesso", {
      data: {
        userId: updatedUser.id,
        filename
      }
    });
    res.json({
      message: "Foto de perfil atualizada com sucesso",
      user: userWithoutPassword
    });
  } catch (error2) {
    logger.error("Erro ao atualizar foto de perfil", error2);
    if (req.file?.path) {
      fs.unlink(req.file.path, (err) => {
        if (err) logger.error("Erro ao remover arquivo tempor\xE1rio", err);
      });
    }
    res.status(500).json({ error: "Erro ao atualizar foto de perfil" });
  }
});
router2.put("/update", authMiddleware, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ error: "Usu\xE1rio n\xE3o autenticado" });
    }
    logger.info("Requisi\xE7\xE3o de atualiza\xE7\xE3o de perfil recebida", {
      data: {
        userId: req.user.id,
        method: req.method,
        path: req.path,
        updateFields: Object.keys(req.body)
      }
    });
    const { email } = req.body;
    if (!email) {
      logger.warn("Dados incompletos na atualiza\xE7\xE3o", {
        data: {
          userId: req.user.id,
          missingFields: { email: !email }
        }
      });
      return res.status(400).json({ error: "Email \xE9 obrigat\xF3rio" });
    }
    const [updatedUser] = await db.update(users).set({ email }).where(eq3(users.id, req.user.id)).returning();
    if (!updatedUser) {
      logger.warn("Usu\xE1rio n\xE3o encontrado ao atualizar", {
        data: { userId: req.user.id }
      });
      return res.status(404).json({ error: "Usu\xE1rio n\xE3o encontrado" });
    }
    const { password, ...userWithoutPassword } = updatedUser;
    logger.info("Perfil atualizado com sucesso", {
      data: { userId: updatedUser.id }
    });
    res.json({
      message: "Perfil atualizado com sucesso",
      user: userWithoutPassword
    });
  } catch (error2) {
    logger.error("Erro ao atualizar perfil", error2);
    res.status(500).json({ error: "Erro ao atualizar perfil" });
  }
});

// server/swagger.ts
import swaggerJSDoc from "swagger-jsdoc";
import swaggerUi from "swagger-ui-express";
var swaggerDefinition = {
  openapi: "3.0.0",
  info: {
    title: "Elite Scouting Network API",
    version: "1.0.0",
    description: "API para plataforma de scouting e intelig\xEAncia de mercado no futebol",
    license: {
      name: "MIT",
      url: "https://opensource.org/licenses/MIT"
    },
    contact: {
      name: "Suporte ESN",
      url: "https://esn.com.br",
      email: "suporte@esn.com.br"
    }
  },
  servers: [
    {
      url: "http://localhost:5000",
      description: "Servidor de Desenvolvimento"
    }
  ],
  components: {
    securitySchemes: {
      BearerAuth: {
        type: "http",
        scheme: "bearer",
        bearerFormat: "JWT"
      }
    }
  }
};
var options = {
  swaggerDefinition,
  apis: ["./server/routes/*.ts"]
  // Caminhos para os arquivos com anotações JSDoc
};
var swaggerSpec = swaggerJSDoc(options);
var swaggerUiServe = swaggerUi.serve;
var swaggerUiSetup = swaggerUi.setup(swaggerSpec);

// server/middleware/rate-limit.ts
import rateLimit from "express-rate-limit";
var isTestEnv = process.env.DISABLE_RATE_LIMIT_FOR_TESTS === "true";
var authMax = isTestEnv ? Infinity : 1e3;
var generalMax = isTestEnv ? Infinity : 2e3;
logger.info("Configurando rate limiting", {
  source: "rate-limit",
  data: {
    isTestEnv,
    authMax,
    generalMax
  }
});
var authLimiter = rateLimit({
  windowMs: 15 * 60 * 1e3,
  // 15 minutos
  max: isTestEnv ? Infinity : authMax,
  message: { error: "Muitas tentativas de login. Por favor, tente novamente mais tarde." },
  handler: (req, res, next) => {
    if (isTestEnv) {
      return next();
    }
    logger.warn("Rate limit excedido na autentica\xE7\xE3o", {
      data: {
        ip: req.ip,
        method: req.method,
        path: req.path,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      }
    });
    res.status(429).json({ error: "Muitas tentativas de login. Por favor, tente novamente mais tarde." });
  },
  skip: () => isTestEnv,
  // Skip rate limiting durante testes
  standardHeaders: true,
  legacyHeaders: false,
  skipFailedRequests: isTestEnv,
  // Ignora requisições com falha durante testes
  skipSuccessfulRequests: isTestEnv
  // Ignora requisições bem-sucedidas durante testes
});
var generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1e3,
  // 15 minutos
  max: isTestEnv ? Infinity : generalMax,
  message: { error: "Limite de requisi\xE7\xF5es excedido. Por favor, tente novamente mais tarde." },
  handler: (req, res, next) => {
    if (isTestEnv) {
      return next();
    }
    logger.warn("Rate limit excedido em rota geral", {
      data: {
        ip: req.ip,
        method: req.method,
        path: req.path,
        timestamp: (/* @__PURE__ */ new Date()).toISOString()
      }
    });
    res.status(429).json({ error: "Limite de requisi\xE7\xF5es excedido. Por favor, tente novamente mais tarde." });
  },
  skip: () => isTestEnv,
  // Skip rate limiting durante testes
  standardHeaders: true,
  legacyHeaders: false,
  skipFailedRequests: isTestEnv,
  // Ignora requisições com falha durante testes
  skipSuccessfulRequests: isTestEnv
  // Ignora requisições bem-sucedidas durante testes
});

// server/vite.ts
import express from "express";
import fs2 from "fs";
import path4, { dirname as dirname2 } from "path";
import { fileURLToPath as fileURLToPath2 } from "url";
import { createServer as createViteServer, createLogger } from "vite";

// vite.config.ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import themePlugin from "@replit/vite-plugin-shadcn-theme-json";
import path3, { dirname } from "path";
import runtimeErrorOverlay from "@replit/vite-plugin-runtime-error-modal";
import { fileURLToPath } from "url";
var __filename = fileURLToPath(import.meta.url);
var __dirname = dirname(__filename);
var vite_config_default = defineConfig({
  plugins: [
    react(),
    runtimeErrorOverlay(),
    themePlugin(),
    ...process.env.NODE_ENV !== "production" && process.env.REPL_ID !== void 0 ? [
      await import("@replit/vite-plugin-cartographer").then(
        (m) => m.cartographer()
      )
    ] : []
  ],
  resolve: {
    alias: {
      "@": path3.resolve(__dirname, "client", "src"),
      "@shared": path3.resolve(__dirname, "shared")
    }
  },
  root: path3.resolve(__dirname, "client"),
  build: {
    outDir: path3.resolve(__dirname, "dist/public"),
    emptyOutDir: true
  }
});

// server/vite.ts
import { nanoid } from "nanoid";
var __filename2 = fileURLToPath2(import.meta.url);
var __dirname2 = dirname2(__filename2);
var viteLogger = createLogger();
async function setupVite(app2, server2) {
  const serverOptions = {
    middlewareMode: true,
    hmr: { server: server2 },
    allowedHosts: true
  };
  const vite = await createViteServer({
    ...vite_config_default,
    configFile: false,
    customLogger: {
      ...viteLogger,
      error: (msg, options2) => {
        viteLogger.error(msg, options2);
        process.exit(1);
      }
    },
    server: serverOptions,
    appType: "custom"
  });
  app2.use(vite.middlewares);
  app2.use("*", async (req, res, next) => {
    const url = req.originalUrl;
    try {
      const clientTemplate = path4.resolve(
        __dirname2,
        "..",
        "client",
        "index.html"
      );
      let template = await fs2.promises.readFile(clientTemplate, "utf-8");
      template = template.replace(
        `src="/src/main.tsx"`,
        `src="/src/main.tsx?v=${nanoid()}"`
      );
      const page = await vite.transformIndexHtml(url, template);
      res.status(200).set({ "Content-Type": "text/html" }).end(page);
    } catch (e) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
}
function serveStatic(app2) {
  const distPath = path4.resolve(__dirname2, "public");
  if (!fs2.existsSync(distPath)) {
    throw new Error(
      `Could not find the build directory: ${distPath}, make sure to build the client first`
    );
  }
  app2.use(express.static(distPath));
  app2.use("*", (_req, res) => {
    res.sendFile(path4.resolve(distPath, "index.html"));
  });
}

// server/index.ts
dotenv.config();
var isTestEnv2 = process.env.DISABLE_RATE_LIMIT_FOR_TESTS === "true";
console.log("Environment variables loaded:", {
  DISABLE_RATE_LIMIT_FOR_TESTS: process.env.DISABLE_RATE_LIMIT_FOR_TESTS,
  isTestEnv: isTestEnv2,
  hasJwtSecret: !!process.env.JWT_SECRET,
  hasDatabase: !!process.env.DATABASE_URL,
  hasFootballKey: !!process.env.API_FOOTBALL_KEY,
  nodeEnv: process.env.NODE_ENV,
  port: process.env.PORT
});
logger.info("Configura\xE7\xE3o de rate limiting", {
  source: "server",
  data: {
    disableRateLimit: process.env.DISABLE_RATE_LIMIT_FOR_TESTS === "true",
    nodeEnv: process.env.NODE_ENV
  }
});
if (!process.env.JWT_SECRET) {
  logger.error("JWT_SECRET n\xE3o est\xE1 definido", {
    message: "Environment variable missing",
    variable: "JWT_SECRET"
  });
  process.exit(1);
}
if (!process.env.DATABASE_URL) {
  logger.error("DATABASE_URL n\xE3o est\xE1 definido", {
    message: "Environment variable missing",
    variable: "DATABASE_URL"
  });
  process.exit(1);
}
process.on("uncaughtException", (err) => {
  logger.error("Erro n\xE3o capturado no processo", {
    message: err.message,
    stack: err.stack,
    type: "uncaughtException"
  });
  process.exit(1);
});
process.on("unhandledRejection", (reason, promise) => {
  logger.error("Promessa rejeitada n\xE3o tratada", {
    message: reason instanceof Error ? reason.message : String(reason),
    type: "unhandledRejection",
    promise: String(promise)
  });
  process.exit(1);
});
var app = express2();
app.set("trust proxy", 1);
app.use(express2.json());
app.use(express2.urlencoded({ extended: false }));
app.use((_req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  if (_req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});
if (!isTestEnv2) {
  logger.info("Aplicando rate limiting...", { source: "server" });
  app.use(generalLimiter);
  app.use("/api/auth", authLimiter);
} else {
  logger.info("Rate limiting desabilitado para testes", { source: "server" });
}
app.use("/uploads", express2.static(path5.join(process.cwd(), "uploads")));
app.use("/api-docs", swaggerUiServe, swaggerUiSetup);
app.get("/api/health", (_req, res) => {
  res.json({
    status: "ok",
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    environment: process.env.NODE_ENV,
    rateLimit: process.env.DISABLE_RATE_LIMIT_FOR_TESTS === "true" ? "disabled" : "enabled",
    variables: {
      hasJwtSecret: !!process.env.JWT_SECRET,
      hasDatabase: !!process.env.DATABASE_URL,
      hasFootballKey: !!process.env.API_FOOTBALL_KEY
    }
  });
});
app.use("/api/auth", router);
app.use("/api/user", router2);
var frontendPath = path5.join(process.cwd(), "dist", "public");
logger.info("Configurando caminho do frontend", {
  frontendPath,
  exists: fs3.existsSync(frontendPath),
  cwd: process.cwd(),
  files: fs3.readdirSync(process.cwd())
});
app.use(express2.static(frontendPath));
app.get("*", (_req, res) => {
  logger.info("Servindo frontend", {
    path: frontendPath,
    url: _req.url,
    cwd: process.cwd(),
    exists: fs3.existsSync(path5.join(frontendPath, "index.html")),
    files: fs3.existsSync(frontendPath) ? fs3.readdirSync(frontendPath) : []
  });
  res.sendFile(path5.join(frontendPath, "index.html"));
});
app.use((err, _req, res, _next) => {
  logger.error("Erro na aplica\xE7\xE3o", {
    message: err.message,
    stack: err.stack,
    type: "middleware"
  });
  res.status(500).json({
    message: "Erro interno do servidor",
    error: process.env.NODE_ENV === "development" ? err.message : void 0
  });
});
logger.info("Configura\xE7\xE3o da porta", {
  source: "server",
  portEnv: process.env.PORT,
  nodeEnv: process.env.NODE_ENV
});
var port = process.env.NODE_ENV === "production" ? Number(process.env.PORT) : Number(process.env.PORT || 5e3);
if (isNaN(port)) {
  logger.error("Porta inv\xE1lida configurada", {
    message: "Invalid port number",
    providedPort: process.env.PORT,
    type: "configuration"
  });
  process.exit(1);
}
var server = app.listen(port, "0.0.0.0", () => {
  logger.info(`Servidor rodando na porta ${port}`, {
    source: "server",
    data: {
      port,
      environment: process.env.NODE_ENV,
      nodeVersion: process.version,
      rateLimit: isTestEnv2 ? "disabled" : "enabled",
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    }
  });
});
server.on("error", (err) => {
  logger.error("Erro ao iniciar servidor", {
    message: err.message,
    stack: err.stack,
    type: "server",
    port,
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  });
  process.exit(1);
});
if (process.env.NODE_ENV === "production") {
  serveStatic(app);
} else {
  setupVite(app, server);
}
