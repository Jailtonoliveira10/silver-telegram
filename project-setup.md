# Elite Scouting Network (ESN) - Guia de Implementação

## Dependências Principais

### Frontend (React + TypeScript)
```json
{
  "dependencies": {
    "@hookform/resolvers": "^3.3.4",
    "@tanstack/react-query": "^5.0.0",
    "axios": "^1.6.7",
    "date-fns": "^3.3.1",
    "jspdf": "^2.5.1",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-hook-form": "^7.50.0",
    "wouter": "^3.0.0",
    "xlsx": "^0.18.5",
    "zod": "^3.22.4"
  }
}
```

### Backend (Node.js + TypeScript)
```json
{
  "dependencies": {
    "@sendgrid/mail": "^8.1.0",
    "bcryptjs": "^2.4.3",
    "drizzle-orm": "^0.29.3",
    "express": "^4.18.2",
    "express-rate-limit": "^7.1.5",
    "jsonwebtoken": "^9.0.2",
    "passport": "^0.7.0",
    "passport-google-oauth20": "^2.0.0",
    "twilio": "^4.21.0"
  }
}
```

## Variáveis de Ambiente Necessárias
```env
# Database
DATABASE_URL=postgresql://user:password@host:port/database

# Auth
JWT_SECRET=seu_jwt_secret
GOOGLE_CLIENT_ID=seu_google_client_id
GOOGLE_CLIENT_SECRET=seu_google_client_secret

# APIs
API_FOOTBALL_KEY=sua_chave_api_football
TRANSFERMARKT_API_KEY=sua_chave_transfermarkt

# WhatsApp/Twilio
TWILIO_ACCOUNT_SID=seu_twilio_sid
TWILIO_AUTH_TOKEN=seu_twilio_token
TWILIO_PHONE_NUMBER=seu_twilio_numero
```

## Estrutura de Diretórios
```
esn/
├── client/                  # Frontend React
│   ├── src/
│   │   ├── components/     # Componentes React
│   │   ├── hooks/         # Custom hooks
│   │   ├── pages/         # Páginas da aplicação
│   │   └── lib/           # Utilitários
├── server/                 # Backend Node.js
│   ├── routes/            # Rotas da API
│   ├── services/          # Serviços
│   └── middleware/        # Middlewares
└── shared/                # Código compartilhado
    └── schema.ts          # Schemas Zod/Drizzle
```

## Implementação em Outras Plataformas

### 1. Preparação do Ambiente

1. Clone o repositório:
```bash
git clone <seu-repositorio>
cd esn
```

2. Instale as dependências:
```bash
# Frontend
cd client
npm install

# Backend
cd ../server
npm install
```

3. Configure as variáveis de ambiente em `.env`

### 2. Deploy do Frontend (Vercel)

1. Push para o GitHub
2. Conecte o repositório no Vercel
3. Configure as variáveis de ambiente
4. Deploy automático após push

### 3. Deploy do Backend (Railway)

1. Crie uma conta no Railway
2. Conecte o repositório
3. Configure as variáveis de ambiente
4. Deploy automático

### 4. Banco de Dados (Neon)

1. Crie um banco PostgreSQL no Neon
2. Configure a URL do banco nas variáveis de ambiente
3. Execute as migrações:
```bash
npm run db:push
```

## Manutenção e Monitoramento

1. Logs e Monitoramento:
   - Use o dashboard do Vercel para frontend
   - Railway para logs do backend
   - Neon para métricas do banco

2. Backups:
   - Configure backups automáticos no Neon
   - Mantenha cópias do código no GitHub

3. Escalabilidade:
   - Vercel e Railway escalam automaticamente
   - Monitore o uso do banco no Neon

## Troubleshooting

1. Problemas comuns:
   - Verifique variáveis de ambiente
   - Confirme as versões das dependências
   - Verifique logs de erro

2. Performance:
   - Use React Query para caching
   - Configure rate limiting
   - Otimize consultas do banco
