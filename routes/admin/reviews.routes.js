const express = require('express');
const router = express.Router();

const { getDB } = require('../../config/db');
const { authMiddleware, adminOnly } = require('../../middlewares/auth');

router.use(authMiddleware, adminOnly);

router.get('/', async (req, res) => {
  const status = ['pendiente', 'publicada', 'rechazada'].includes(req.query.status)
    ? req.query.status
    : null;
  try {
    const db = await getDB();
    let sql = `SELECT r.id, r.calificacion AS rating, r.comentario AS comment,
                      r.estado AS status, r.notas_admin AS admin_notes, r.creado_en AS created_at,
                      p.nombre AS product_name,
                      CONCAT(u.nombre, ' ', u.apellidoP) AS customer_name
               FROM resenas_productos r
               JOIN products p ON p.id = r.producto_id
               JOIN users u ON u.id = r.usuario_id`;
    const params = [];
    if (status) { sql += ' WHERE r.status = ?'; params.push(status); }
    sql += ' ORDER BY r.creado_en DESC LIMIT 200';
    const [reviews] = await db.execute(sql, params);
    res.json(reviews);
  } catch (error) {
    console.error('Error consultando reseñas para moderación:', error.message);
    res.status(500).json({ error: 'No se pudieron cargar las reseñas.' });
  }
});

router.patch('/:id', async (req, res) => {
  const id = Number(req.params.id);
  const status = req.body?.status;
  const notes = String(req.body?.admin_notes || '').trim();
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Reseña inválida.' });
  if (!['publicada', 'rechazada'].includes(status)) return res.status(400).json({ error: 'Estado inválido.' });
  if (notes.length > 500) return res.status(400).json({ error: 'Las notas no pueden exceder 500 caracteres.' });

  try {
    const db = await getDB();
    const [result] = await db.execute(
      `UPDATE resenas_productos SET estado = ?, notas_admin = ? WHERE id = ?`,
      [status, notes || null, id]
    );
    if (!result.affectedRows) return res.status(404).json({ error: 'Reseña no encontrada.' });
    res.json({ message: 'Reseña actualizada.' });
  } catch (error) {
    console.error('Error moderando reseña:', error.message);
    res.status(500).json({ error: 'No se pudo actualizar la reseña.' });
  }
});

module.exports = router;
