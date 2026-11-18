const express = require('express');
const { getDB } = require('../../config/db');
const { authMiddleware } = require('../../middlewares/auth');

const router = express.Router();
const EXPO_TOKEN = /^(ExponentPushToken|ExpoPushToken)\[[A-Za-z0-9_-]+\]$/;

router.get('/status', authMiddleware, async (req, res) => {
  try {
    const db = await getDB();
    const [[row]] = await db.execute(
      'SELECT COUNT(*) AS total FROM push_tokens WHERE user_id = ? AND active = 1',
      [req.user.id],
    );
    res.json({ registered: Number(row.total) > 0, devices: Number(row.total) });
  } catch (error) {
    res.status(500).json({ error: 'No se pudo consultar el registro de notificaciones' });
  }
});

router.post('/token', authMiddleware, async (req, res) => {
  const token = String(req.body.token || '').trim();
  if (!EXPO_TOKEN.test(token)) {
    return res.status(400).json({ error: 'Token de notificaciones inválido' });
  }
  try {
    const db = await getDB();
    await db.execute(
      `INSERT INTO push_tokens (user_id, token, platform, active)
       VALUES (?, ?, ?, 1)
       ON DUPLICATE KEY UPDATE user_id = VALUES(user_id), platform = VALUES(platform), active = 1, updated_at = CURRENT_TIMESTAMP`,
      [req.user.id, token, String(req.body.platform || 'expo').slice(0, 20)],
    );
    res.status(201).json({ message: 'Dispositivo registrado para notificaciones' });
  } catch (error) {
    console.error('Error registrando token push:', error.message);
    res.status(500).json({ error: 'No se pudo registrar el dispositivo' });
  }
});

router.delete('/token', authMiddleware, async (req, res) => {
  const token = String(req.body.token || '').trim();
  try {
    const db = await getDB();
    await db.execute('UPDATE push_tokens SET active = 0 WHERE user_id = ? AND token = ?', [req.user.id, token]);
    res.json({ message: 'Notificaciones desactivadas en este dispositivo' });
  } catch (error) {
    res.status(500).json({ error: 'No se pudo desactivar el dispositivo' });
  }
});

module.exports = router;
