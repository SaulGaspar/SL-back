const express = require('express');
const router = express.Router();

const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');

router.use(authMiddleware, adminOnly);

router.get('/', async (req, res) => {
  const status = ['nuevo', 'leido', 'cerrado'].includes(req.query.status) ? req.query.status : null;
  try {
    const db = await getDB();
    let sql = 'SELECT * FROM mensajes_contacto';
    const params = [];
    if (status) { sql += ' WHERE estado = ?'; params.push(status); }
    sql += ' ORDER BY creado_en DESC LIMIT 200';
    const [messages] = await db.execute(sql, params);
    res.json(messages);
  } catch (error) {
    console.error('Error consultando mensajes de contacto:', error.message);
    res.status(500).json({ error: 'No se pudieron cargar los mensajes.' });
  }
});

router.patch('/:id', async (req, res) => {
  const id = Number(req.params.id);
  const status = req.body?.estado;
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Mensaje inválido.' });
  if (!['nuevo', 'leido', 'cerrado'].includes(status)) return res.status(400).json({ error: 'Estado inválido.' });
  try {
    const db = await getDB();
    const [result] = await db.execute('UPDATE mensajes_contacto SET estado = ? WHERE id = ?', [status, id]);
    if (!result.affectedRows) return res.status(404).json({ error: 'Mensaje no encontrado.' });
    res.json({ message: 'Estado actualizado.' });
  } catch (error) {
    console.error('Error actualizando mensaje de contacto:', error.message);
    res.status(500).json({ error: 'No se pudo actualizar el mensaje.' });
  }
});

module.exports = router;
