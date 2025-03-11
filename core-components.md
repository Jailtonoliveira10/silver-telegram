# Componentes Principais do ESN

## 1. Configuração do Cliente (React)

### src/App.tsx
```typescript
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { AuthProvider } from '@/hooks/use-auth'
import { ThemeProvider } from '@/components/theme-provider'
import Router from '@/components/router'

const queryClient = new QueryClient()

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <ThemeProvider>
          <Router />
        </ThemeProvider>
      </AuthProvider>
    </QueryClientProvider>
  )
}
```

### src/hooks/use-auth.ts
```typescript
import { createContext, useContext } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'

export function useAuth() {
  const { data: user } = useQuery({
    queryKey: ['/api/user'],
    queryFn: () => fetch('/api/user').then(res => res.json())
  })

  const loginMutation = useMutation({
    mutationFn: (credentials) => 
      fetch('/api/login', {
        method: 'POST',
        body: JSON.stringify(credentials)
      }).then(res => res.json())
  })

  return { user, loginMutation }
}
```

## 2. Configuração do Servidor (Node.js)

### server/index.ts
```typescript
import express from 'express'
import session from 'express-session'
import { setupAuth } from './auth'
import { setupRoutes } from './routes'

const app = express()

app.use(express.json())
app.use(session({
  secret: process.env.JWT_SECRET!,
  resave: false,
  saveUninitialized: false
}))

setupAuth(app)
setupRoutes(app)

app.listen(process.env.PORT || 5000)
```

### server/auth.ts
```typescript
import passport from 'passport'
import { Strategy as LocalStrategy } from 'passport-local'
import { storage } from './storage'

export function setupAuth(app: Express) {
  passport.use(new LocalStrategy(async (username, password, done) => {
    try {
      const user = await storage.getUserByUsername(username)
      if (!user) return done(null, false)
      const valid = await comparePasswords(password, user.password)
      if (!valid) return done(null, false)
      return done(null, user)
    } catch (err) {
      return done(err)
    }
  }))

  app.use(passport.initialize())
  app.use(passport.session())
}
```

## 3. Schemas e Tipos (Compartilhados)

### shared/schema.ts
```typescript
import { z } from 'zod'
import { createInsertSchema } from 'drizzle-zod'
import { users } from './db/schema'

export const userSchema = createInsertSchema(users)
export type User = z.infer<typeof userSchema>

export const loginSchema = userSchema.pick({
  username: true,
  password: true
})
```

## 4. Integrações de API

### server/services/sports-api.ts
```typescript
import axios from 'axios'

const api = axios.create({
  baseURL: 'https://api.football-data.org/v4',
  headers: {
    'X-Auth-Token': process.env.API_FOOTBALL_KEY
  }
})

export async function getLiveMatches() {
  const { data } = await api.get('/matches')
  return data
}
```

## 5. Componentes de UI

### src/components/live-matches.tsx
```typescript
import { useQuery } from '@tanstack/react-query'

export default function LiveMatches() {
  const { data: matches } = useQuery({
    queryKey: ['/api/matches'],
    queryFn: () => fetch('/api/matches').then(res => res.json())
  })

  return (
    <div>
      {matches?.map(match => (
        <div key={match.id}>
          {match.homeTeam} vs {match.awayTeam}
        </div>
      ))}
    </div>
  )
}
```

## 6. Configuração do Banco de Dados

### server/db/schema.ts
```typescript
import { pgTable, serial, text, timestamp } from 'drizzle-orm/pg-core'

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  username: text('username').notNull(),
  password: text('password').notNull(),
  createdAt: timestamp('created_at').defaultNow()
})
```

## 7. Serviços de Notificação

### server/services/notifications.ts
```typescript
import twilio from 'twilio'

const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
)

export async function sendWhatsAppAlert(to: string, message: string) {
  return client.messages.create({
    body: message,
    from: process.env.TWILIO_PHONE_NUMBER,
    to: `whatsapp:${to}`
  })
}
```
