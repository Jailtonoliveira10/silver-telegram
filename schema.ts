import { pgTable, text, serial, integer, boolean, jsonb, timestamp } from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod";

export const users = pgTable("users", {
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
    maxMarketValue: 100000000,
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

export const blacklistedTokens = pgTable("blacklisted_tokens", {
  id: serial("id").primaryKey(),
  token: text("token").notNull().unique(),
  expiresAt: timestamp("expires_at").notNull(),
  blacklistedAt: timestamp("blacklisted_at").defaultNow().notNull()
});

export const players = pgTable("players", {
  id: serial("id").primaryKey(),
  name: text("name").notNull(),
  position: text("position").notNull(),
  age: integer("age").notNull(),
  nationality: text("nationality").notNull(),
  club: text("club").notNull(),
  marketValue: integer("market_value").notNull(),
  stats: jsonb("stats").notNull()
});

export const insertUserSchema = createInsertSchema(users).pick({
  username: true,
  password: true,
  email: true,
  googleId: true,
  displayName: true
});

export const alertPreferencesSchema = z.object({
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

export const profileImageSchema = z.object({
  file: z.any()
    .refine((file) => file?.size <= 5000000, 'O arquivo deve ter no máximo 5MB')
    .refine(
      (file) => ['image/jpeg', 'image/png', 'image/gif'].includes(file?.type),
      'Formato de arquivo inválido. Use JPEG, PNG ou GIF'
    )
});

export const insertBlacklistedTokenSchema = createInsertSchema(blacklistedTokens).pick({
  token: true,
  expiresAt: true
});

export type InsertUser = z.infer<typeof insertUserSchema>;
export type User = typeof users.$inferSelect;
export type Player = typeof players.$inferSelect;
export type AlertPreferences = z.infer<typeof alertPreferencesSchema>;
export type BlacklistedToken = typeof blacklistedTokens.$inferSelect;
export type InsertBlacklistedToken = z.infer<typeof insertBlacklistedTokenSchema>;
export type ProfileImage = z.infer<typeof profileImageSchema>;