const express = require("express");
const path = require("path");
const fs = require("fs");
const { drizzle } = require("drizzle-orm/postgres-js");
const postgres = require("postgres");
const logger = require("./utils/logger");
const authRoutes = require("./routes/auth");
const cors = require("cors");

// Verificação de variáveis de ambiente CRÍTICAS
if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL não configurado!");
}
if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET não configurado!");
}
if (!process.env.API_FOOTBALL_KEY) {
  throw new Error("API_FOOTBALL_KEY não configurado!");
}
if (!process.env.NEXT_PUBLIC_API_URL) {
  throw new Error("NEXT_PUBLIC_API_URL não configurado!");
}

// Configurações do servidor
const app = express();
const PORT = process.env.PORT || 8080;

// Caminho CORRETO para os arquivos do frontend (raiz do projeto)
const distPath = path.join(__dirname, "../dist"); // Pasta onde o Vite gera os arquivos

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Middleware de log para todas as requisições
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.url}`);
  next();
});

// Servir arquivos estáticos do frontend
app.use(express.static(distPath));

// Rota de healthcheck
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    environment: process.env.NODE_ENV || "development",
    timestamp: new Date().toISOString()
  });
});

// Rota padrão para SPA (Single-Page Application)
app.get("*", (req, res) => {
  // Verifica se o diretório do frontend existe (debug)
  if (!fs.existsSync(distPath)) {
    logger.error(`Pasta do frontend não encontrada: ${distPath}`);
    res.status(500).send("Erro: Pasta do frontend não encontrada!");
    return;
  }
  
  // Adiciona verificação de ambiente 
  if (process.env.NODE_ENV === "production") {
    res.sendFile(path.join(distPath, "index.html"));
  } else {
    logger.warn("Tentativa de acesso em ambiente não produtivo");
    res.status(500).send("Erro: Modo de desenvolvimento não configurado!");
  }
});

// Rotas do sistema
app.use("/api/auth", authRoutes);

// Configuração do banco de dados
const client = postgres(process.env.DATABASE_URL);
const db = drizzle(client);

// Variável global para o banco de dados
global.db = db;

// Iniciar o servidor
const server = app.listen(PORT, () => {
  logger.info(`Servidor rodando na porta ${PORT}`);
  logger.info(`Ambiente: ${process.env.NODE_ENV || "development"}`);
});

// Tratamento de erros de servidor
server.on("error", (error) => {
  logger.error("Erro no servidor:", error);
});

// Tratamento de erros não capturados
process.on("uncaughtException", (err) => {
  logger.error("Erro não tratado:", err);
  // Tenta fazer um shutdown gracioso
  if (server) {
    server.close(() => {
      logger.info("Servidor fechado após erro crítico");
      process.exit(1);
    });
  } else {
    process.exit(1);
  }
});

// Tratamento de rejeições de promises não tratadas
process.on("unhandledRejection", (err) => {
  logger.error("Promise rejeitada não tratada:", err);
  // Tenta fazer um shutdown gracioso
  if (server) {
    server.close(() => {
      logger.info("Servidor fechado após rejeição de promise");
      process.exit(1);
    });
  } else {
    process.exit(1);
  }
});

// Exporta o app e o servidor para possíveis importações
module.exports = {
  app,
  server,
  db
};
