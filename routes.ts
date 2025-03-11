import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth } from "./auth";
import { sendPlayerAlert } from "./mailer";
import { alertPreferencesSchema } from "@shared/schema";
import { searchPlayers, getPlayerById } from "./services/football-api";

export async function registerRoutes(app: Express): Promise<Server> {
  setupAuth(app);

  app.get("/api/players/search", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);

    const { query } = req.query;
    if (!query) {
      return res.status(400).json({ error: "Search query is required" });
    }

    try {
      const players = await searchPlayers(query as string);
      res.json(players);
    } catch (error) {
      res.status(500).json({ error: "Failed to search players" });
    }
  });

  app.get("/api/players/:id", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);

    try {
      const player = await getPlayerById(parseInt(req.params.id));
      if (!player) {
        return res.status(404).json({ error: "Player not found" });
      }
      res.json(player);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch player" });
    }
  });

  app.get("/api/players", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);

    const { positions, minValue, maxValue, minAge, maxAge } = req.query;

    const filters = {
      positions: positions ? (positions as string).split(",") : undefined,
      minValue: minValue ? parseInt(minValue as string) : undefined,
      maxValue: maxValue ? parseInt(maxValue as string) : undefined,
      minAge: minAge ? parseInt(minAge as string) : undefined,
      maxAge: maxAge ? parseInt(maxAge as string) : undefined
    };

    try {
      const players = await storage.getPlayersByFilter(filters);
      res.json(players);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch players" });
    }
  });

  app.patch("/api/users/alert-preferences", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);

    try {
      const prefs = alertPreferencesSchema.parse(req.body);
      const user = await storage.updateUserAlertPreferences(req.user.id, prefs);
      res.json(user);
    } catch (error) {
      res.status(400).json({ error: "Invalid alert preferences" });
    }
  });

  app.post("/api/alerts/test", async (req, res) => {
    if (!req.isAuthenticated()) return res.sendStatus(401);

    const success = await sendPlayerAlert(
      req.user.email,
      await storage.getPlayers().then(players => players[0]),
      "Test alert"
    );

    if (success) {
      res.sendStatus(200);
    } else {
      res.status(500).json({ error: "Failed to send test alert" });
    }
  });

  const httpServer = createServer(app);
  return httpServer;
}