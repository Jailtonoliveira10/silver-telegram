import { Router } from 'express';
import { getLatestMatches, getTeamMatches } from '../services/sports-api';

const router = Router();

router.get('/api/matches', async (req, res) => {
  try {
    const matches = await getLatestMatches();
    res.json(matches);
  } catch (error) {
    console.error('Error in /api/matches:', error);
    res.status(500).json({ error: 'Failed to fetch matches' });
  }
});

router.get('/api/teams/:teamId/matches', async (req, res) => {
  try {
    const teamId = parseInt(req.params.teamId);
    const matches = await getTeamMatches(teamId);
    res.json(matches);
  } catch (error) {
    console.error('Error in /api/teams/:teamId/matches:', error);
    res.status(500).json({ error: 'Failed to fetch team matches' });
  }
});

export default router;
