# Elite Scouting Network (ESN) - Guia Completo

## 1. Visão Geral do Projeto

O ESN é uma plataforma avançada de análise esportiva que oferece os seguintes serviços:

### Análise de Desempenho de Jogadores
- Estatísticas detalhadas e comparações
- Relatórios exportáveis (PDF/Excel)
- Histórico de desempenho e tendências

### Monitoramento de Mercado
- Acompanhamento de valores
- Histórico de transferências
- Sistema de alertas para mudanças significativas

### Dados em Tempo Real
- Partidas ao vivo via API Football-Data.org
- Placares e estatísticas atualizadas
- Status de jogadores (lesões, suspensões)

### Recursos Avançados
- Autenticação segura com 2FA
- Suporte multilíngue (PT/EN/ES)
- Tema adaptativo (claro/escuro/sistema)
- Alertas via WhatsApp

## 2. Estrutura do Projeto e Dependências

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
    "wouter": "^3.0.0",
    "xlsx": "^0.18.5"
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
    "jsonwebtoken": "^9.0.2",
    "passport": "^0.7.0",
    "twilio": "^4.21.0"
  }
}
```

### Variáveis de Ambiente
```env
# Banco de Dados
DATABASE_URL=postgresql://user:senha@host:porta/banco

# Autenticação
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

## 3. Estrutura de Diretórios
```
esn/
├── client/                  # Frontend React
│   ├── src/
│   │   ├── components/     # Componentes React
│   │   ├── hooks/         # Hooks personalizados
│   │   ├── pages/         # Páginas da aplicação
│   │   └── lib/           # Utilitários
├── server/                 # Backend Node.js
│   ├── routes/            # Rotas da API
│   ├── services/          # Serviços
│   └── middleware/        # Middlewares
└── shared/                # Código compartilhado
    └── schema.ts          # Schemas Zod/Drizzle
```

## 4. Guia de Migração

### Preparação do Ambiente

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

3. Configure o arquivo `.env` com as variáveis necessárias

### Plataformas Recomendadas

1. Frontend: Vercel
   - Deploy automático
   - Integração com GitHub
   - Configuração simples de variáveis

2. Backend: Railway
   - Suporte nativo Node.js
   - Gerenciamento de variáveis
   - Escalabilidade automática

3. Banco de Dados: Neon
   - PostgreSQL serverless
   - Backups automáticos
   - Compatível com Drizzle

### Processo de Migração

1. **Clone e Backup**
   - Faça backup do banco:
   ```bash
   pg_dump -U $PGUSER -h $PGHOST -d $PGDATABASE > backup.sql
   ```

2. **Frontend (Vercel)**
   - Push para GitHub
   - Conecte ao Vercel
   - Configure variáveis
   - Deploy automático

3. **Backend (Railway)**
   - Conecte repositório
   - Configure variáveis
   - Deploy automático

4. **Banco de Dados (Neon)**
   - Crie banco PostgreSQL
   - Configure URL
   - Execute migrações:
   ```bash
   npm run db:push
   ```

## 5. Manutenção e Monitoramento

### Logs e Monitoramento
- Use dashboard Vercel para frontend
- Railway para logs do backend
- Neon para métricas do banco

### Backups
- Configure backups automáticos no Neon
- Mantenha cópias do código no GitHub

### Escalabilidade
- Vercel e Railway escalam automaticamente
- Monitore uso do banco no Neon

## 6. Solução de Problemas

### Problemas Comuns
1. Verifique variáveis de ambiente
2. Confirme versões das dependências
3. Verifique logs de erro

### Performance
1. Use React Query para cache
2. Configure rate limiting
3. Otimize consultas do banco

## 7. Considerações Finais

Este guia contém todas as informações necessárias para migrar o ESN para outra plataforma. Mantenha este documento atualizado conforme o projeto evolui.

Para suporte adicional:
- Consulte a documentação das plataformas (Vercel, Railway, Neon)
- Verifique os logs de erro
- Mantenha backups regulares
