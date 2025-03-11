# Guia de Migração e Implantação do ESN

## Migrando do Replit

### 1. Preparação

1. Exporte o código do Replit:
   - Use o git para clonar o repositório
   - Ou faça download do ZIP

2. Backup do banco de dados:
```bash
pg_dump -U $PGUSER -h $PGHOST -d $PGDATABASE > backup.sql
```

### 2. Deploy no Vercel (Frontend)

1. Crie uma conta no Vercel (vercel.com)

2. Configure o projeto:
```bash
# Instale o CLI do Vercel
npm i -g vercel

# Login e deploy
cd client
vercel
```

3. Variáveis de ambiente no Vercel:
   - Settings > Environment Variables
   - Adicione `VITE_API_URL` apontando para seu backend

### 3. Deploy no Railway (Backend)

1. Crie uma conta no Railway (railway.app)

2. Novo projeto:
   - Conecte com GitHub
   - Selecione o repositório
   - Configure o Dockerfile

3. Variáveis de ambiente:
   - DATABASE_URL
   - JWT_SECRET
   - API_FOOTBALL_KEY
   - Demais chaves de API

### 4. Banco de Dados no Neon

1. Crie uma conta no Neon (neon.tech)

2. Novo banco de dados:
   - Crie um novo projeto
   - Copie a connection string

3. Migre os dados:
```bash
# Restaure o backup
psql -h seu-host.neon.tech -U seu-usuario -d seu-banco < backup.sql
```

## Configuração de Domínio Personalizado

### 1. Frontend (Vercel)
1. Settings > Domains
2. Adicione seu domínio
3. Configure DNS conforme instruções

### 2. Backend (Railway)
1. Settings > Domains
2. Gere um domínio personalizado
3. Configure CNAME no seu DNS

## Monitoramento e Manutenção

### 1. Logs e Métricas
- Vercel: Analytics e logs em tempo real
- Railway: Logs do servidor e métricas
- Neon: Métricas do banco de dados

### 2. Backups
1. Configure backups automáticos no Neon
2. Mantenha repositório atualizado no GitHub
3. Exporte dados periodicamente

### 3. Escalabilidade
- Vercel: Escala automaticamente
- Railway: Ajuste recursos conforme necessário
- Neon: Monitore uso do banco

## Checklist de Deploy

### Frontend
- [ ] Build bem sucedido
- [ ] Variáveis de ambiente configuradas
- [ ] HTTPS ativo
- [ ] Performance otimizada

### Backend
- [ ] Servidor iniciando corretamente
- [ ] Conexão com banco estabelecida
- [ ] APIs externas respondendo
- [ ] Rate limiting configurado

### Banco de Dados
- [ ] Migração concluída
- [ ] Backups configurados
- [ ] Índices otimizados
- [ ] Conexões seguras

## Troubleshooting Comum

### 1. Problemas de Conexão
- Verifique URLs e portas
- Confirme variáveis de ambiente
- Teste conectividade do banco

### 2. Erros de Build
- Limpe cache do npm
- Atualize dependências
- Verifique compatibilidade

### 3. Performance
- Implemente caching
- Otimize consultas
- Configure CDN

## Manutenção Contínua

### 1. Updates Regulares
- Atualize dependências mensalmente
- Monitore vulnerabilidades
- Mantenha documentação atualizada

### 2. Backup e Recuperação
- Teste recuperação periodicamente
- Mantenha múltiplas cópias
- Documente procedimentos

### 3. Monitoramento
- Configure alertas
- Revise métricas semanalmente
- Mantenha logs organizados
