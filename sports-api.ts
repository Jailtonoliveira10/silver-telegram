import axios from 'axios';

if (!process.env.API_FOOTBALL_KEY) {
  throw new Error("API_FOOTBALL_KEY environment variable must be set");
}

const footballApi = axios.create({
  baseURL: 'http://api.football-data.org/v4',
  headers: { 'X-Auth-Token': process.env.API_FOOTBALL_KEY }
});

export interface MatchResponse {
  matches: {
    id: number;
    homeTeam: { name: string };
    awayTeam: { name: string };
    score: {
      fullTime: {
        home: number | null;
        away: number | null;
      }
    };
    status: string;
    utcDate: string;
  }[];
}

export async function getLatestMatches() {
  try {
    const response = await footballApi.get<MatchResponse>('/matches');
    return response.data.matches;
  } catch (error) {
    console.error('Error fetching matches:', error);
    throw new Error('Failed to fetch matches data');
  }
}

export async function getTeamMatches(teamId: number) {
  try {
    const response = await footballApi.get<MatchResponse>(`/teams/${teamId}/matches`);
    return response.data.matches;
  } catch (error) {
    console.error('Error fetching team matches:', error);
    throw new Error('Failed to fetch team matches data');
  }
}
