import { User, InsertUser, Player, AlertPreferences } from "@shared/schema";
import session from "express-session";
import createMemoryStore from "memorystore";
import { scrypt, randomBytes } from "crypto";
import { promisify } from "util";

const MemoryStore = createMemoryStore(session);
const scryptAsync = promisify(scrypt);

export interface IStorage {
  getUser(id: number): Promise<User | undefined>;
  getUserByUsername(username: string): Promise<User | undefined>;
  getUserByGoogleId(googleId: string): Promise<User | undefined>;
  createUser(user: InsertUser): Promise<User>;
  updateUserAlertPreferences(userId: number, prefs: AlertPreferences): Promise<User>;
  getPlayers(): Promise<Player[]>;
  getPlayersByFilter(filters: {
    positions?: string[];
    minValue?: number;
    maxValue?: number;
    minAge?: number;
    maxAge?: number;
  }): Promise<Player[]>;
  sessionStore: session.Store;
}

export class MemStorage implements IStorage {
  private users: Map<number, User>;
  private players: Map<number, Player>;
  public sessionStore: session.Store;
  private currentId: number;

  constructor() {
    this.users = new Map();
    this.players = new Map();
    this.currentId = 1;
    this.sessionStore = new MemoryStore({
      checkPeriod: 86400000
    });

    // Criar usuário de teste com senha já hasheada
    this.initializeTestUser();

    // Add sample players
    this.initializeSamplePlayers();
  }

  private async initializeTestUser() {
    const salt = randomBytes(16).toString("hex");
    const buf = (await scryptAsync("teste123", salt, 64)) as Buffer;
    const hashedPassword = `${buf.toString("hex")}.${salt}`;

    const user: User = {
      id: this.currentId++,
      username: "teste",
      password: hashedPassword,
      email: "teste@teste.com",
      alertPreferences: {
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
      }
    };

    this.users.set(user.id, user);
    console.log("Usuário de teste criado:", { ...user, password: "[HIDDEN]" });
  }

  private initializeSamplePlayers() {
    // Manter os jogadores de exemplo existentes...
    this.players.set(1, {
      id: 1,
      name: "Erling Haaland",
      position: "Forward",
      age: 23,
      nationality: "Norway",
      club: "Manchester City",
      marketValue: 180000000,
      stats: {
        goals: 36,
        assists: 8,
        games: 35,
        rating: "8.5"
      }
    });

    this.players.set(2, {
      id: 2,
      name: "Neymar Jr",
      position: "Forward",
      age: 32,
      nationality: "Brazil",
      club: "Al-Hilal",
      marketValue: 50000000,
      stats: {
        goals: 13,
        assists: 11,
        games: 17,
        rating: "8.1"
      }
    });

    this.players.set(3, {
      id: 3,
      name: "Thiago Silva",
      position: "Defender",
      age: 39,
      nationality: "Brazil",
      club: "Chelsea",
      marketValue: 4000000,
      stats: {
        goals: 2,
        assists: 1,
        games: 25,
        rating: "7.3"
      }
    });
  }

  async getUser(id: number): Promise<User | undefined> {
    return this.users.get(id);
  }

  async getUserByUsername(username: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.username === username
    );
  }

  async getUserByGoogleId(googleId: string): Promise<User | undefined> {
    return Array.from(this.users.values()).find(
      (user) => user.googleId === googleId
    );
  }

  async createUser(insertUser: InsertUser): Promise<User> {
    const id = this.currentId++;
    const user: User = {
      ...insertUser,
      id,
      alertPreferences: {
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
      }
    };
    this.users.set(id, user);
    console.log("Novo usuário criado:", { ...user, password: "[HIDDEN]" });
    return user;
  }

  async updateUserAlertPreferences(userId: number, prefs: AlertPreferences): Promise<User> {
    const user = await this.getUser(userId);
    if (!user) throw new Error("User not found");

    const updatedUser = {
      ...user,
      alertPreferences: prefs
    };
    this.users.set(userId, updatedUser);
    return updatedUser;
  }

  async getPlayers(): Promise<Player[]> {
    return Array.from(this.players.values());
  }

  async getPlayersByFilter(filters: {
    positions?: string[];
    minValue?: number;
    maxValue?: number;
    minAge?: number;
    maxAge?: number;
  }): Promise<Player[]> {
    return Array.from(this.players.values()).filter(player => {
      if (filters.positions?.length && !filters.positions.includes(player.position)) return false;
      if (filters.minValue && player.marketValue < filters.minValue) return false;
      if (filters.maxValue && player.marketValue > filters.maxValue) return false;
      if (filters.minAge && player.age < filters.minAge) return false;
      if (filters.maxAge && player.age > filters.maxAge) return false;
      return true;
    });
  }
}

export const storage = new MemStorage();