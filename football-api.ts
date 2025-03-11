import { Player } from "@shared/schema";

const API_BASE_URL = "https://api-football-v1.p.rapidapi.com/v3";
const API_KEY = process.env.API_FOOTBALL_KEY || "1d1c4c54a2cdc6633b97cc0b19a3e241";

interface ApiFootballPlayer {
  player: {
    id: number;
    name: string;
    age: number;
    nationality: string;
    position: string;
  };
  statistics: Array<{
    team: {
      name: string;
    };
    games: {
      appearences: number;
      lineups: number;
      minutes: number;
      rating: string;
    };
    goals: {
      total: number;
      assists: number;
    };
  }>;
}

export async function searchPlayers(name: string): Promise<Player[]> {
  try {
    console.log(`Iniciando busca por jogador: ${name}`);
    const season = 2023;
    const league = 307; // Saudi Pro League
    const players = new Map<number, Player>();

    // Busca direta na liga saudita
    console.log(`Buscando na liga ${league} (Saudi Pro League)`);
    try {
      const url = `${API_BASE_URL}/players?search=${name}&league=${league}&season=${season}`;
      console.log(`URL da requisição: ${url}`);

      const response = await fetch(url, {
        headers: {
          "x-rapidapi-key": API_KEY,
          "x-rapidapi-host": "api-football-v1.p.rapidapi.com"
        },
      });

      console.log(`Status da resposta: ${response.status}`);
      const responseText = await response.text();
      console.log(`Resposta completa: ${responseText}`);

      if (!response.ok) {
        throw new Error(`API request failed: ${response.statusText}`);
      }

      const data = JSON.parse(responseText);
      console.log(`Jogadores encontrados: ${data.response?.length || 0}`);

      if (data.response) {
        data.response.forEach((item: ApiFootballPlayer) => {
          players.set(item.player.id, {
            id: item.player.id,
            name: item.player.name,
            position: item.player.position,
            age: item.player.age,
            nationality: item.player.nationality,
            club: item.statistics[0]?.team.name || "Unknown",
            marketValue: 0,
            stats: {
              games: item.statistics[0]?.games.appearences || 0,
              goals: item.statistics[0]?.goals.total || 0,
              assists: item.statistics[0]?.goals.assists || 0,
              rating: parseFloat(item.statistics[0]?.games.rating || "0").toFixed(1)
            }
          });
        });
      }
    } catch (error) {
      console.error("Erro durante a busca na API:", error);
    }

    console.log(`Total de jogadores encontrados: ${players.size}`);
    return Array.from(players.values());
  } catch (error) {
    console.error("Erro geral na busca:", error);
    throw error;
  }
}

export async function getPlayerById(id: number): Promise<Player | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/players?id=${id}&season=2023`, {
      headers: {
        "x-rapidapi-key": API_KEY,
        "x-rapidapi-host": "api-football-v1.p.rapidapi.com"
      },
    });

    if (!response.ok) {
      throw new Error(`API request failed: ${response.statusText}`);
    }

    const data = await response.json();
    if (!data.response?.length) {
      return null;
    }

    const item = data.response[0];
    return {
      id: item.player.id,
      name: item.player.name,
      position: item.player.position,
      age: item.player.age,
      nationality: item.player.nationality,
      club: item.statistics[0]?.team.name || "Unknown",
      marketValue: 0,
      stats: {
        games: item.statistics[0]?.games.appearences || 0,
        goals: item.statistics[0]?.goals.total || 0,
        assists: item.statistics[0]?.goals.assists || 0,
        rating: parseFloat(item.statistics[0]?.games.rating || "0").toFixed(1)
      }
    };
  } catch (error) {
    console.error("Error fetching player:", error);
    throw error;
  }
}